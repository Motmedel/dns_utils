package dns_utils

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	dnsUtilsContext "github.com/Motmedel/dns_utils/pkg/context"
	dnsUtilsErrors "github.com/Motmedel/dns_utils/pkg/errors"
	dnsUtilsTypes "github.com/Motmedel/dns_utils/pkg/types"
	motmedelContext "github.com/Motmedel/utils_go/pkg/context"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"github.com/Motmedel/utils_go/pkg/errors/types/empty_error"
	"github.com/Motmedel/utils_go/pkg/errors/types/nil_error"
	motmedelTlsTypes "github.com/Motmedel/utils_go/pkg/tls/types"
	"github.com/miekg/dns"
)

const resolvePath = "/etc/resolv.conf"

func GetFlagsFromMessage(message *dns.Msg) []string {
	if message == nil {
		return nil
	}

	var flags []string

	if message.Authoritative {
		flags = append(flags, "AA")
	}
	if message.AuthenticatedData {
		flags = append(flags, "AD")
	}
	if message.CheckingDisabled {
		flags = append(flags, "CD")
	}

	for _, extra := range message.Extra {
		if opt, ok := extra.(*dns.OPT); ok && opt != nil {
			if opt.Do() {
				flags = append(flags, "DO")
			}
			break
		}
	}

	if message.RecursionAvailable {
		flags = append(flags, "RA")
	}
	if message.RecursionDesired {
		flags = append(flags, "RD")
	}
	if message.Truncated {
		flags = append(flags, "TC")
	}

	return flags
}

func GetDnsServers(ctx context.Context) ([]string, error) {
	file, err := os.Open(resolvePath)
	if err != nil {
		return nil, motmedelErrors.NewWithTrace(fmt.Errorf("os open: %w", err), resolvePath)
	}
	defer func() {
		if err := file.Close(); err != nil {
			slog.WarnContext(
				motmedelContext.WithError(
					ctx,
					motmedelErrors.NewWithTrace(fmt.Errorf("file close: %w", err), file),
				),
				"An error occurred when closing the file.",
			)
		}
	}()

	var dnsServers []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "nameserver") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				dnsServers = append(dnsServers, fields[1])
			}
		}
	}

	return dnsServers, nil
}

// ApplyRemainingTtl rewrites every RR TTL to the remaining seconds.
//
// OPT, TSIG and SIG records are skipped: their RR header "TTL" field is
// overloaded (e.g. OPT encodes extended-rcode/version/DO/Z per RFC 6891),
// so blindly rewriting it would corrupt the EDNS extended flags — most
// visibly stripping the DO bit and leaving garbage in the MBZ field,
// which breaks DNSSEC validation downstream.
func ApplyRemainingTtl(message *dns.Msg, seconds uint32) {
	if message == nil {
		return
	}

	update := func(records []dns.RR) {
		for _, record := range records {
			if record == nil {
				continue
			}

			switch record.(type) {
			case *dns.OPT, *dns.TSIG, *dns.SIG:
				continue
			}

			if header := record.Header(); header != nil {
				header.Ttl = seconds
			}
		}
	}

	update(message.Answer)
	update(message.Ns)
	update(message.Extra)
}

func EffectiveMessageTtl(message *dns.Msg) time.Duration {
	if message == nil {
		return 0
	}

	minValue := ^uint32(0)
	sweep := func(records []dns.RR) {
		for _, record := range records {
			if record == nil {
				continue
			}

			switch record.(type) {
			case *dns.OPT, *dns.TSIG, *dns.SIG:
				continue
			default:
				if header := record.Header(); header != nil {
					ttl := header.Ttl
					if ttl < minValue {
						minValue = ttl
					}
				}
			}
		}
	}

	sweep(message.Answer)
	sweep(message.Ns)
	sweep(message.Extra)

	// NXDOMAIN / NODATA – use SOA.MINIMUM if smaller
	if message.Rcode == dns.RcodeNameError || len(message.Answer) == 0 {
		for _, record := range message.Ns {
			if soa, ok := record.(*dns.SOA); ok && soa.Minttl < minValue {
				minValue = soa.Minttl
			}
		}
	}

	return time.Duration(minValue) * time.Second
}

func populateDnsContext(
	dnsContext *dnsUtilsTypes.DnsContext,
	connection *dns.Conn,
	message *dns.Msg,
	responseMessage *dns.Msg,
) error {
	if dnsContext == nil {
		return nil
	}

	// TODO: Maybe I can obtain an earlier time?
	t := time.Now()

	var clientAddress string
	var serverAddress string
	var transport string
	if connection != nil {
		if localAddr := connection.LocalAddr(); localAddr != nil {
			clientAddress = localAddr.String()
		}

		if remoteAddr := connection.RemoteAddr(); remoteAddr != nil {
			serverAddress = remoteAddr.String()
			transport = remoteAddr.Network()
		}

		if tlsConn, ok := connection.Conn.(*tls.Conn); ok && tlsConn != nil {
			connectionState := tlsConn.ConnectionState()
			dnsContext.TlsContext = &motmedelTlsTypes.TlsContext{
				ConnectionState: &connectionState,
				ClientInitiated: true,
			}
		}
	}

	dnsContext.Time = &t
	dnsContext.ClientAddress = clientAddress
	dnsContext.ServerAddress = serverAddress
	dnsContext.Transport = transport
	dnsContext.QuestionMessage = message
	dnsContext.AnswerMessage = responseMessage

	return nil
}

func ExchangeWithConn(ctx context.Context, message *dns.Msg, client *dns.Client, connection *dns.Conn) (*dns.Msg, error) {
	if message == nil {
		return nil, nil
	}

	dnsContext, ok := ctx.Value(dnsUtilsContext.DnsContextKey).(*dnsUtilsTypes.DnsContext)
	if !ok || dnsContext == nil {
		dnsContext = &dnsUtilsTypes.DnsContext{}
	}
	dnsContext.QuestionMessage = message
	ctxWithDnsContext := dnsUtilsContext.WithDnsContextValue(context.Background(), dnsContext)

	if client == nil {
		return nil, motmedelErrors.NewWithTraceCtx(ctxWithDnsContext, nil_error.New("dns client"))
	}

	if connection == nil {
		return nil, motmedelErrors.NewWithTraceCtx(ctxWithDnsContext, nil_error.New("connection"))
	}

	// Exchange

	responseMessage, _, err := client.ExchangeWithConn(message, connection)

	// Populate the DNS context.

	if err := populateDnsContext(dnsContext, connection, message, responseMessage); err != nil {
		return nil, motmedelErrors.NewWithTraceCtx(
			ctxWithDnsContext,
			fmt.Errorf("populate dns context: %w", err),
		)
	}

	// Return

	if err != nil {
		return responseMessage, motmedelErrors.NewWithTraceCtx(
			ctxWithDnsContext,
			fmt.Errorf("dns client exchange: %w", err),
		)
	}
	if responseMessage == nil {
		return nil, motmedelErrors.NewWithTraceCtx(
			ctxWithDnsContext,
			nil_error.New("response message"),
		)
	}

	if responseMessage.Rcode != dns.RcodeSuccess {
		return responseMessage, motmedelErrors.NewWithTraceCtx(
			ctxWithDnsContext,
			&dnsUtilsErrors.RcodeError{Rcode: responseMessage.Rcode},
		)
	}

	return responseMessage, nil
}

func Exchange(ctx context.Context, message *dns.Msg, client *dns.Client, serverAddress string) (*dns.Msg, error) {
	if message == nil {
		return nil, nil
	}

	dnsContext, ok := ctx.Value(dnsUtilsContext.DnsContextKey).(*dnsUtilsTypes.DnsContext)
	if !ok || dnsContext == nil {
		dnsContext = &dnsUtilsTypes.DnsContext{}
	}
	dnsContext.QuestionMessage = message
	if dnsContext.ServerAddress == "" {
		dnsContext.ServerAddress = serverAddress
	}
	ctxWithDnsContext := dnsUtilsContext.WithDnsContextValue(context.Background(), dnsContext)

	if client == nil {
		return nil, motmedelErrors.NewWithTraceCtx(ctxWithDnsContext, nil_error.New("dns client"))
	}

	if serverAddress == "" {
		return nil, motmedelErrors.NewWithTraceCtx(ctxWithDnsContext, empty_error.New("dns server"))
	}

	connection, err := client.Dial(serverAddress)
	if err != nil {
		return nil, motmedelErrors.NewWithTraceCtx(ctxWithDnsContext, fmt.Errorf("client dial: %w", err))
	}
	if connection == nil {
		return nil, motmedelErrors.NewWithTraceCtx(ctxWithDnsContext, nil_error.New("connection"))
	}
	defer func() {
		if err := connection.Close(); err != nil {
			slog.WarnContext(
				motmedelContext.WithError(ctx, err),
				"An error occurred when closing the connection.",
			)
		}
	}()

	// Pass the shared DnsContext to ExchangeWithConn so it populates the same instance.
	ctxForExchange := dnsUtilsContext.WithDnsContextValue(ctx, dnsContext)

	responseMessage, err := ExchangeWithConn(ctxForExchange, message, client, connection)
	if err != nil {
		return nil, motmedelErrors.NewWithTraceCtx(
			ctxWithDnsContext,
			fmt.Errorf("exchange with conn: %w", err),
		)
	}
	if responseMessage == nil {
		return nil, motmedelErrors.NewWithTraceCtx(ctxWithDnsContext, nil_error.New("response message"))
	}

	return responseMessage, nil
}

func GetDnsAnswersWithMessage(ctx context.Context, message *dns.Msg, client *dns.Client, serverAddress string) ([]dns.RR, error) {
	if message == nil {
		return nil, nil
	}

	dnsContext, ok := ctx.Value(dnsUtilsContext.DnsContextKey).(*dnsUtilsTypes.DnsContext)
	if !ok || dnsContext == nil {
		dnsContext = &dnsUtilsTypes.DnsContext{}
	}
	dnsContext.QuestionMessage = message
	if dnsContext.ServerAddress == "" {
		dnsContext.ServerAddress = serverAddress
	}
	ctxWithDnsContext := dnsUtilsContext.WithDnsContextValue(context.Background(), dnsContext)

	if client == nil {
		return nil, motmedelErrors.NewWithTraceCtx(ctxWithDnsContext, nil_error.New("dns client"))
	}

	if serverAddress == "" {
		return nil, motmedelErrors.NewWithTraceCtx(ctxWithDnsContext, empty_error.New("dns server"))
	}

	ctxForExchange := dnsUtilsContext.WithDnsContextValue(ctx, dnsContext)

	responseMessage, err := Exchange(ctxForExchange, message, client, serverAddress)
	if err != nil {
		return nil, motmedelErrors.NewWithTraceCtx(ctxWithDnsContext, fmt.Errorf("exchange: %w", err))
	}
	if responseMessage == nil {
		return nil, motmedelErrors.NewWithTraceCtx(ctxWithDnsContext, nil_error.New("response message"))
	}

	if responseMessage.Truncated {
		tcpDnsClient := *client
		tcpDnsClient.Net = "tcp"

		responseMessage, err = Exchange(ctxForExchange, message, &tcpDnsClient, serverAddress)
		if err != nil {
			return nil, motmedelErrors.NewWithTraceCtx(ctxWithDnsContext, fmt.Errorf("exchange: %w", err))
		}
	}

	if responseMessage == nil {
		return nil, motmedelErrors.NewWithTraceCtx(ctxWithDnsContext, nil_error.New("response message"))
	}

	return responseMessage.Answer, nil
}

func GetDnsAnswers(
	ctx context.Context,
	domain string,
	recordType uint16,
	client *dns.Client,
	serverAddress string,
) ([]dns.RR, error) {
	if domain == "" {
		return nil, nil
	}

	dnsContext, ok := ctx.Value(dnsUtilsContext.DnsContextKey).(*dnsUtilsTypes.DnsContext)
	if !ok || dnsContext == nil {
		dnsContext = &dnsUtilsTypes.DnsContext{}
	}
	if dnsContext.ServerAddress == "" {
		dnsContext.ServerAddress = serverAddress
	}
	ctxWithDnsContext := dnsUtilsContext.WithDnsContextValue(context.Background(), dnsContext)

	if recordType == 0 {
		return nil, motmedelErrors.NewWithTraceCtx(ctxWithDnsContext, dnsUtilsErrors.ErrUnsetRecordType)
	}

	if client == nil {
		return nil, motmedelErrors.NewWithTraceCtx(ctxWithDnsContext, nil_error.New("dns client"))
	}

	if serverAddress == "" {
		return nil, motmedelErrors.NewWithTraceCtx(ctxWithDnsContext, empty_error.New("dns server"))
	}

	message := &dns.Msg{}
	message.SetQuestion(dns.Fqdn(domain), recordType)

	if client.Net == "" || client.Net == "udp" {
		if bufferSize := client.UDPSize; bufferSize > 0 {
			message.SetEdns0(bufferSize, false)
		}
	}

	dnsContext.QuestionMessage = message
	ctxForDownstream := dnsUtilsContext.WithDnsContextValue(ctx, dnsContext)

	answers, err := GetDnsAnswersWithMessage(ctxForDownstream, message, client, serverAddress)
	if err != nil {
		return nil, motmedelErrors.NewWithTraceCtx(
			ctxWithDnsContext,
			fmt.Errorf("get dns answers with message: %w", err),
		)
	}
	return answers, nil
}

func GetAnswerString(answer dns.RR) string {
	switch typedAnswer := answer.(type) {
	case *dns.A:
		if a := typedAnswer.A; a != nil {
			return a.String()
		}
	case *dns.AAAA:
		if aaaa := typedAnswer.AAAA; aaaa != nil {
			return aaaa.String()
		}
	case *dns.MX:
		return typedAnswer.Mx
	case *dns.NS:
		return typedAnswer.Ns
	case *dns.TXT:
		return strings.Join(typedAnswer.Txt, "")
	case *dns.CNAME:
		return typedAnswer.Target
	case *dns.HTTPS:
		return strings.TrimPrefix(typedAnswer.String(), typedAnswer.Hdr.String())
	}

	// TODO: There could be more types...

	return ""
}

func GetDnsAnswerStrings(
	ctx context.Context,
	domain string,
	recordType uint16,
	dnsClient *dns.Client,
	dnsServerAddress string,
) ([]string, error) {
	if domain == "" {
		return nil, nil
	}

	dnsContext, ok := ctx.Value(dnsUtilsContext.DnsContextKey).(*dnsUtilsTypes.DnsContext)
	if !ok || dnsContext == nil {
		dnsContext = &dnsUtilsTypes.DnsContext{}
	}
	if dnsContext.ServerAddress == "" {
		dnsContext.ServerAddress = dnsServerAddress
	}
	ctxWithDnsContext := dnsUtilsContext.WithDnsContextValue(context.Background(), dnsContext)

	if recordType == 0 {
		return nil, motmedelErrors.NewWithTraceCtx(ctxWithDnsContext, dnsUtilsErrors.ErrUnsetRecordType)
	}

	if dnsClient == nil {
		return nil, motmedelErrors.NewWithTraceCtx(ctxWithDnsContext, nil_error.New("dns client"))
	}

	if dnsServerAddress == "" {
		return nil, motmedelErrors.NewWithTraceCtx(ctxWithDnsContext, empty_error.New("dns server"))
	}

	ctxForDownstream := dnsUtilsContext.WithDnsContextValue(ctx, dnsContext)

	answers, err := GetDnsAnswers(ctxForDownstream, domain, recordType, dnsClient, dnsServerAddress)
	if err != nil {
		return nil, motmedelErrors.NewWithTraceCtx(
			ctxWithDnsContext,
			fmt.Errorf("get dns answers: %w", err),
		)
	}

	var answerStrings []string

	for _, answer := range answers {
		if answerString := GetAnswerString(answer); answerString != "" {
			answerStrings = append(answerStrings, answerString)
		}
	}

	return answerStrings, nil
}

func GetPrefixedTxtRecordStrings(
	ctx context.Context,
	domain string,
	prefix string,
	dnsClient *dns.Client,
	dnsServerAddress string,
) ([]string, error) {
	if domain == "" {
		return nil, nil
	}

	dnsContext, ok := ctx.Value(dnsUtilsContext.DnsContextKey).(*dnsUtilsTypes.DnsContext)
	if !ok || dnsContext == nil {
		dnsContext = &dnsUtilsTypes.DnsContext{}
	}
	if dnsContext.ServerAddress == "" {
		dnsContext.ServerAddress = dnsServerAddress
	}
	ctxWithDnsContext := dnsUtilsContext.WithDnsContextValue(context.Background(), dnsContext)

	if dnsClient == nil {
		return nil, motmedelErrors.NewWithTraceCtx(ctxWithDnsContext, nil_error.New("dns client"))
	}

	if dnsServerAddress == "" {
		return nil, motmedelErrors.NewWithTraceCtx(ctxWithDnsContext, empty_error.New("dns server"))
	}

	ctxForDownstream := dnsUtilsContext.WithDnsContextValue(ctx, dnsContext)

	answerStrings, err := GetDnsAnswerStrings(ctxForDownstream, domain, dns.TypeTXT, dnsClient, dnsServerAddress)
	if err != nil {
		return nil, motmedelErrors.NewWithTraceCtx(
			ctxWithDnsContext,
			fmt.Errorf("get dns answer strings: %w", err),
		)
	}

	var prefixedAnswerStrings []string

	for _, answerString := range answerStrings {
		if strings.HasPrefix(answerString, prefix) {
			prefixedAnswerStrings = append(prefixedAnswerStrings, answerString)
		}
	}

	return prefixedAnswerStrings, nil
}

func DomainExists(ctx context.Context, domain string, client *dns.Client, serverAddress string) (bool, error) {
	if domain == "" {
		return false, nil
	}

	dnsContext, ok := ctx.Value(dnsUtilsContext.DnsContextKey).(*dnsUtilsTypes.DnsContext)
	if !ok || dnsContext == nil {
		dnsContext = &dnsUtilsTypes.DnsContext{}
	}
	if dnsContext.ServerAddress == "" {
		dnsContext.ServerAddress = serverAddress
	}
	ctxWithDnsContext := dnsUtilsContext.WithDnsContextValue(context.Background(), dnsContext)

	if client == nil {
		return false, motmedelErrors.NewWithTraceCtx(ctxWithDnsContext, nil_error.New("dns client"))
	}

	if serverAddress == "" {
		return false, motmedelErrors.NewWithTraceCtx(ctxWithDnsContext, empty_error.New("dns server"))
	}

	ctxForDownstream := dnsUtilsContext.WithDnsContextValue(ctx, dnsContext)

	// NOTE: The question type should not matter?
	_, err := GetDnsAnswers(ctxForDownstream, domain, dns.TypeSOA, client, serverAddress)
	if err != nil {
		var rcodeError *dnsUtilsErrors.RcodeError
		if errors.As(err, &rcodeError) {
			if rcodeError.Rcode == dns.RcodeNameError {
				return false, nil
			}
		}
		return false, motmedelErrors.NewWithTraceCtx(ctxWithDnsContext, fmt.Errorf("get dns answers: %w", err))
	}

	return true, nil
}

func SupportsDnssec(ctx context.Context, domain string, client *dns.Client, serverAddress string) (bool, error) {
	if domain == "" {
		return false, nil
	}

	dnsContext, ok := ctx.Value(dnsUtilsContext.DnsContextKey).(*dnsUtilsTypes.DnsContext)
	if !ok || dnsContext == nil {
		dnsContext = &dnsUtilsTypes.DnsContext{}
	}
	if dnsContext.ServerAddress == "" {
		dnsContext.ServerAddress = serverAddress
	}
	ctxWithDnsContext := dnsUtilsContext.WithDnsContextValue(context.Background(), dnsContext)

	if client == nil {
		return false, motmedelErrors.NewWithTraceCtx(ctxWithDnsContext, nil_error.New("dns client"))
	}

	if serverAddress == "" {
		return false, motmedelErrors.NewWithTraceCtx(ctxWithDnsContext, empty_error.New("dns server"))
	}

	message := new(dns.Msg)
	message.SetQuestion(dns.Fqdn(domain), dns.TypeDNSKEY)

	opt := &dns.OPT{
		Hdr:    dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT, Class: 4096},
		Option: []dns.EDNS0{&dns.EDNS0_COOKIE{}},
	}
	opt.SetDo()

	message.Extra = append(message.Extra, opt)

	dnsContext.QuestionMessage = message
	ctxForDownstream := dnsUtilsContext.WithDnsContextValue(ctx, dnsContext)

	answers, err := GetDnsAnswersWithMessage(ctxForDownstream, message, client, serverAddress)
	if err != nil {
		return false, motmedelErrors.NewWithTraceCtx(
			ctxWithDnsContext,
			fmt.Errorf("get dns answers with message: %w", err),
		)
	}

	dnssecSupported := false
	for _, answer := range answers {
		if _, ok := answer.(*dns.DNSKEY); ok {
			dnssecSupported = true
			break
		}
	}

	return dnssecSupported, nil
}
