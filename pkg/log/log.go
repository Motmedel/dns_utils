package log

import (
	"context"
	"encoding/json"
	"fmt"
	dnsUtilsContext "github.com/Motmedel/dns_utils/pkg/context"
	dnsUtilsTypes "github.com/Motmedel/dns_utils/pkg/types"
	"github.com/Motmedel/ecs_go/ecs"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	motmedelLog "github.com/Motmedel/utils_go/pkg/log"
	"github.com/Motmedel/utils_go/pkg/net"
	"github.com/Motmedel/utils_go/pkg/net/domain_breakdown"
	"github.com/miekg/dns"
	"log/slog"
)

func ParseDnsMessage(message *dns.Msg) *ecs.Base {
	if message == nil {
		return nil
	}

	var question *dns.Question
	if questions := message.Question; len(questions) > 0 {
		question = &questions[0]
	}

	answers := message.Answer

	if question == nil && len(answers) == 0 {
		return nil
	}

	var ecsDns ecs.Dns
	base := &ecs.Base{Dns: &ecsDns, Network: &ecs.Network{Protocol: "dns"}}

	if question != nil {
		var domainBreakdown net.DomainBreakdown
		if parsedDomainBreakdown := domain_breakdown.GetDomainBreakdown(question.Name); parsedDomainBreakdown != nil {
			domainBreakdown = *parsedDomainBreakdown
		}

		ecsDns.Question = &ecs.DnsQuestion{
			DomainBreakdown: domainBreakdown,
			Class:           "",
			Name:            "",
			Type:            "",
		}
	}

	//for _, answer := range answers {
	//	ecsDns.Answers = append(
	//		ecsDns.Answers,
	//		&ecs.DnsAnswer{},
	//	)
	//}

	return base
}

//func ParseDnsExchange(question *dns.Question, answers []dns.RR) *ecs.Base {
//	if question == nil && len(answers) == 0 {
//		return nil
//	}
//
//	base := &ecs.Base{
//		Network: &ecs.Network{
//			Protocol: "dns",
//
//		},
//	}
//
//}

func ParseDnsContext(dnsContext *dnsUtilsTypes.DnsContext) *ecs.Base {
	if dnsContext == nil {
		return nil
	}

	//var question *dns.Question
	//if questionMessage := dnsContext.QuestionMessage; questionMessage != nil {
	//	// Not sure if it makes sense to have multiple questions?
	//	if questions := questionMessage.Question; len(questions) > 0 {
	//		question = &questions[0]
	//	}
	//}
	//
	//var answers []dns.RR
	//if answersMessage := dnsContext.AnswerMessage; answersMessage != nil {
	//	answers = answersMessage.Answer
	//}

	//return ParseDnsExchange(question, answers)

	return nil
}

func ExtractDnsContext(ctx context.Context, record *slog.Record) error {
	if dnsContext, ok := ctx.Value(dnsUtilsContext.DnsContextKey).(*dnsUtilsTypes.DnsContext); ok && dnsContext != nil {
		base := ParseDnsContext(dnsContext)

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

	return nil
}

var DnsContextExtractor = motmedelLog.ContextExtractorFunction(ExtractDnsContext)
