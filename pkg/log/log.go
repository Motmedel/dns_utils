package log

import (
	"context"
	"encoding/json"
	"fmt"
	dnsUtilsContext "github.com/Motmedel/dns_utils/pkg/context"
	"github.com/Motmedel/dns_utils/pkg/dns_utils"
	dnsUtilsTypes "github.com/Motmedel/dns_utils/pkg/types"
	"github.com/Motmedel/ecs_go/ecs"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	motmedelIter "github.com/Motmedel/utils_go/pkg/iter"
	motmedelLog "github.com/Motmedel/utils_go/pkg/log"
	motmedelNet "github.com/Motmedel/utils_go/pkg/net"
	"github.com/Motmedel/utils_go/pkg/net/domain_breakdown"
	"github.com/miekg/dns"
	"log/slog"
	"net"
	"strconv"
	"strings"
)

func EnrichWithDnsMessage(base *ecs.Base, message *dns.Msg) {
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
		ecsDns = &ecs.Dns{}
		base.Dns = ecsDns
	}

	ecsDns.HeaderFlags = dns_utils.GetFlagsFromMessage(message)
	ecsDns.Id = strconv.Itoa(int(message.Id))
	ecsDns.OpCode = dns.OpcodeToString[message.Opcode]

	if question != nil {
		var domainBreakdown motmedelNet.DomainBreakdown

		parsedDomainBreakdown := domain_breakdown.GetDomainBreakdown(strings.TrimSuffix(question.Name, "."))
		if parsedDomainBreakdown != nil {
			domainBreakdown = *parsedDomainBreakdown
		}

		ecsDns.Question = &ecs.DnsQuestion{
			DomainBreakdown: domainBreakdown,
			Class:           dns.ClassToString[question.Qclass],
			Name:            strings.TrimSuffix(question.Name, "."),
			Type:            dns.TypeToString[question.Qtype],
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
			&ecs.DnsAnswer{
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

func ParseDnsMessage(message *dns.Msg) *ecs.Base {
	if message == nil {
		return nil
	}

	base := &ecs.Base{Network: &ecs.Network{Protocol: "dns"}}
	EnrichWithDnsMessage(base, message)

	return base
}

func ParseDnsContext(dnsContext *dnsUtilsTypes.DnsContext) *ecs.Base {
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

	var ecsServer *ecs.Target
	if address := dnsContext.ServerAddress; address != "" {
		ecsServer = &ecs.Target{}
		if host, port, err := net.SplitHostPort(address); err == nil {
			ecsServer.Address = host
			if addressIp := net.ParseIP(host); addressIp != nil {
				ecsServer.Ip = addressIp.String()
			} else {
				ecsServer.Domain = address
			}

			if port != "" {
				if portNum, err := strconv.Atoi(port); err == nil {
					ecsServer.Port = portNum
				}
			}
		}
	}

	var ecsClient *ecs.Target
	if address := dnsContext.ClientAddress; address != "" {
		ecsClient = &ecs.Target{}
		if host, port, err := net.SplitHostPort(address); err == nil {
			ecsClient.Address = host
			if addressIp := net.ParseIP(host); addressIp != nil {
				ecsClient.Ip = addressIp.String()
			} else {
				ecsClient.Domain = address
			}

			if port != "" {
				if portNum, err := strconv.Atoi(port); err == nil {
					ecsClient.Port = portNum
				}
			}
		}
	}

	var communityIdSlice []string
	if communityId := ecs.CommunityIdFromTargets(ecsClient, ecsServer, ianaNumber); communityId != "" {
		communityIdSlice = []string{communityId}
	}

	base := &ecs.Base{
		Network: &ecs.Network{
			CommunityId: communityIdSlice,
			Protocol:    "dns",
			Transport:   transport,
			IanaNumber:  strconv.Itoa(ianaNumber),
		},
		Client: ecsClient,
		Server: ecsServer,
	}
	EnrichWithDnsMessage(base, message)
	ecs.EnrichWithTlsContext(base, dnsContext.TlsContext)

	return base
}

func ExtractDnsContext(ctx context.Context, record *slog.Record) error {
	if dnsContext, ok := ctx.Value(dnsUtilsContext.DnsContextKey).(*dnsUtilsTypes.DnsContext); ok && dnsContext != nil {
		base := ParseDnsContext(dnsContext)
		if base != nil {
			baseBytes, err := json.Marshal(base)
			if err != nil {
				return motmedelErrors.NewWithTrace(fmt.Errorf("json marshal (ecs base): %w", err), base)
			}

			var baseMap map[string]any
			if err = json.Unmarshal(baseBytes, &baseMap); err != nil {
				return motmedelErrors.NewWithTrace(fmt.Errorf("json unmarshal (ecs base map): %w", err), baseMap)
			}

			record.Add(motmedelLog.AttrsFromMap(baseMap)...)
		}
	}

	return nil
}

var DnsContextExtractor = motmedelLog.ContextExtractorFunction(ExtractDnsContext)
