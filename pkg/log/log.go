package log

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"

	dnsUtilsContext "github.com/Motmedel/dns_utils/pkg/context"
	"github.com/Motmedel/dns_utils/pkg/dns_utils"
	dnsUtilsTypes "github.com/Motmedel/dns_utils/pkg/types"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	motmedelIter "github.com/Motmedel/utils_go/pkg/iter"
	motmedelJson "github.com/Motmedel/utils_go/pkg/json"
	motmedelLog "github.com/Motmedel/utils_go/pkg/log"
	"github.com/Motmedel/utils_go/pkg/net/types/domain_parts"
	"github.com/Motmedel/utils_go/pkg/net/types/flow_tuple"
	"github.com/Motmedel/utils_go/pkg/schema"
	schemaUtils "github.com/Motmedel/utils_go/pkg/schema/utils"
	"github.com/miekg/dns"
)

func EnrichWithDnsMessage(base *schema.Base, message *dns.Msg) {
	if base == nil {
		return
	}

	if message == nil {
		return
	}

	var question *dns.Question
	if questions := message.Question; len(questions) > 0 {
		question = &questions[0]
	}

	ecsDns := base.Dns
	if ecsDns == nil {
		ecsDns = &schema.Dns{}
		base.Dns = ecsDns
	}

	ecsDns.HeaderFlags = dns_utils.GetFlagsFromMessage(message)
	ecsDns.Id = strconv.Itoa(int(message.Id))
	ecsDns.OpCode = dns.OpcodeToString[message.Opcode]

	if question != nil {
		var parts domain_parts.Parts

		parsedParts := domain_parts.New(strings.TrimSuffix(question.Name, "."))
		if parsedParts != nil {
			parts = *parsedParts
		}

		ecsDns.Question = &schema.DnsQuestion{
			Parts: parts,
			Class: dns.ClassToString[question.Qclass],
			Name:  strings.TrimSuffix(question.Name, "."),
			Type:  dns.TypeToString[question.Qtype],
		}
	}

	var resolvedIps []string
	for _, answer := range message.Answer {
		if answer == nil {
			continue
		}

		answerHeader := answer.Header()
		if answerHeader == nil {
			continue
		}

		answerType := dns.TypeToString[answerHeader.Rrtype]
		answerData := dns_utils.GetAnswerString(answer)

		if answerType == "A" || answerType == "AAAA" {
			resolvedIps = append(resolvedIps, answerData)
		}

		ecsDns.Answers = append(
			ecsDns.Answers,
			&schema.DnsAnswer{
				Class: dns.ClassToString[answerHeader.Class],
				Data:  answerData,
				Name:  strings.TrimSuffix(answerHeader.Name, "."),
				Ttl:   int(answerHeader.Ttl),
				Type:  answerType,
			},
		)
	}

	ecsDns.ResolvedIp = motmedelIter.Set(resolvedIps)

	if message.Response {
		ecsDns.ResponseCode = dns.RcodeToString[message.Rcode]
		ecsDns.Type = "answer"
	} else {
		ecsDns.Type = "question"
	}
}

func ParseDnsMessage(message *dns.Msg) *schema.Base {
	if message == nil {
		return nil
	}

	base := &schema.Base{Network: &schema.Network{Protocol: "dns"}}
	EnrichWithDnsMessage(base, message)

	return base
}

func MakeDnsMessage(base *schema.Base) string {
	if base == nil {
		return ""
	}

	clientAddress := "-"
	for _, target := range []*schema.Target{base.Client, base.Source} {
		if target == nil {
			continue
		}
		if target.Ip != "" {
			clientAddress = formatHostPort(target.Ip, target.Port)
			break
		}
	}

	serverAddress := "-"
	for _, target := range []*schema.Target{base.Server, base.Destination} {
		if target == nil {
			continue
		}
		if target.Ip != "" {
			serverAddress = formatHostPort(target.Ip, target.Port)
			break
		}
	}

	transport := "-"
	if network := base.Network; network != nil {
		if network.Transport != "" {
			transport = network.Transport
		}
	}

	questionName := "-"
	questionClass := "-"
	questionType := "-"
	responseCode := "-"
	answerData := "-"

	if ecsDns := base.Dns; ecsDns != nil {
		if question := ecsDns.Question; question != nil {
			if question.Name != "" {
				questionName = question.Name
			}
			if question.Class != "" {
				questionClass = question.Class
			}
			if question.Type != "" {
				questionType = question.Type
			}
		}

		if ecsDns.ResponseCode != "" {
			responseCode = ecsDns.ResponseCode
		}

		if len(ecsDns.ResolvedIp) != 0 {
			answerData = strings.Join(ecsDns.ResolvedIp, ",")
		} else if len(ecsDns.Answers) != 0 {
			var parts []string
			for _, answer := range ecsDns.Answers {
				if answer == nil {
					continue
				}
				if answer.Data != "" {
					parts = append(parts, answer.Data)
				}
			}
			if len(parts) != 0 {
				answerData = strings.Join(parts, ",")
			}
		}
	}

	return fmt.Sprintf(
		"%s -> %s %s \"%s %s %s\" %s \"%s\"",
		clientAddress,
		serverAddress,
		transport,
		questionName,
		questionClass,
		questionType,
		responseCode,
		answerData,
	)
}

func formatHostPort(ip string, port int) string {
	if ip == "" {
		return "-"
	}
	if port == 0 {
		return ip
	}
	return net.JoinHostPort(ip, strconv.Itoa(port))
}

func ParseDnsContext(dnsContext *dnsUtilsTypes.DnsContext) *schema.Base {
	if dnsContext == nil {
		return nil
	}

	var message *dns.Msg
	if answersMessage := dnsContext.AnswerMessage; answersMessage != nil {
		message = answersMessage
	} else if questionMessage := dnsContext.QuestionMessage; questionMessage != nil {
		message = questionMessage
	}

	if message == nil {
		return nil
	}

	transport := strings.ToLower(dnsContext.Transport)
	var ianaNumber int
	switch transport {
	case "tcp":
		ianaNumber = 6
	case "udp", "":
		transport = "udp"
		ianaNumber = 17
	}

	var ecsServer *schema.Target
	var serverIp net.IP
	var serverPort uint16
	if address := dnsContext.ServerAddress; address != "" {
		ecsServer = &schema.Target{}
		if host, port, err := net.SplitHostPort(address); err == nil {
			ecsServer.Address = host
			if addressIp := net.ParseIP(host); addressIp != nil {
				serverIp = addressIp
				ecsServer.Ip = addressIp.String()
			} else {
				ecsServer.Domain = address
			}

			if port != "" {
				if portNum, err := strconv.Atoi(port); err == nil {
					ecsServer.Port = portNum
					serverPort = uint16(portNum)
				}
			}
		}
	}

	var ecsClient *schema.Target
	var clientIp net.IP
	var clientPort uint16
	if address := dnsContext.ClientAddress; address != "" {
		ecsClient = &schema.Target{}
		if host, port, err := net.SplitHostPort(address); err == nil {
			ecsClient.Address = host
			if addressIp := net.ParseIP(host); addressIp != nil {
				clientIp = addressIp
				ecsClient.Ip = addressIp.String()
			} else {
				ecsClient.Domain = address
			}

			if port != "" {
				if portNum, err := strconv.Atoi(port); err == nil {
					ecsClient.Port = portNum
					clientPort = uint16(portNum)
				}
			}
		}
	}

	var communityIdSlice []string

	if flowTuple := flow_tuple.New(clientIp, serverIp, clientPort, serverPort, uint8(ianaNumber)); flowTuple != nil {
		if communityId := flowTuple.Hash(); communityId != "" {
			communityIdSlice = []string{communityId}
		}
	}

	base := &schema.Base{
		Network: &schema.Network{
			CommunityId: communityIdSlice,
			Protocol:    "dns",
			Transport:   transport,
			IanaNumber:  strconv.Itoa(ianaNumber),
		},
		Client: ecsClient,
		Server: ecsServer,
	}
	EnrichWithDnsMessage(base, message)
	schemaUtils.EnrichWithTlsContext(base, dnsContext.TlsContext)

	base.Message = MakeDnsMessage(base)

	return base
}

func ExtractDnsContext(ctx context.Context, record *slog.Record) error {
	if dnsContext, ok := ctx.Value(dnsUtilsContext.DnsContextKey).(*dnsUtilsTypes.DnsContext); ok && dnsContext != nil {
		if base := ParseDnsContext(dnsContext); base != nil {
			if base.Message != "" {
				record.Message = base.Message
				// Prevent the message from being emitted again as a top-level attribute.
				base.Message = ""
			}

			baseMap, err := motmedelJson.ObjectToMap(base)
			if err != nil {
				return motmedelErrors.NewWithTrace(fmt.Errorf("object to map: %w", err), base)
			}

			record.Add(motmedelLog.AttrsFromMap(baseMap)...)
		}
	}

	return nil
}

var DnsContextExtractor = motmedelLog.ContextExtractorFunction(ExtractDnsContext)
