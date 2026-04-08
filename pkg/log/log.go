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

	return base
}

func ExtractDnsContext(ctx context.Context, record *slog.Record) error {
	if dnsContext, ok := ctx.Value(dnsUtilsContext.DnsContextKey).(*dnsUtilsTypes.DnsContext); ok && dnsContext != nil {
		if base := ParseDnsContext(dnsContext); base != nil {
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
