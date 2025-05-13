package dns_utils

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	dnsUtilsContext "github.com/Motmedel/dns_utils/pkg/context"
	dnsUtilsErrors "github.com/Motmedel/dns_utils/pkg/errors"
	dnsUtilsTypes "github.com/Motmedel/dns_utils/pkg/types"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	motmedelTlsTypes "github.com/Motmedel/utils_go/pkg/tls/types"
	"github.com/miekg/dns"
	"os"
	"strings"
	"time"
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

func GetDnsServers() ([]string, error) {
	file, err := os.Open(resolvePath)
	if err != nil {
		return nil, motmedelErrors.NewWithTrace(fmt.Errorf("os open: %w", err), resolvePath)
	}
	defer file.Close()

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
func ApplyRemainingTtl(message *dns.Msg, seconds uint32) {
	if message == nil {
		return
	}

	update := func(records []dns.RR) {
		for _, record := range records {
			if record == nil {
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

func Exchange(ctx context.Context, message *dns.Msg, client *dns.Client, serverAddress string) (*dns.Msg, error) {
	if message == nil {
		return nil, nil
	}

	if client == nil {
		return nil, motmedelErrors.NewWithTrace(dnsUtilsErrors.ErrNilDnsClient)
	}

	if serverAddress == "" {
		return nil, motmedelErrors.NewWithTrace(dnsUtilsErrors.ErrEmptyDnsServer)
	}

	connection, err := client.Dial(serverAddress)
	if err != nil {
		return nil, motmedelErrors.NewWithTrace(fmt.Errorf("client dial: %w", err))
	}
	defer connection.Close()

	var clientAddress string
	if localAddr := connection.LocalAddr(); localAddr != nil {
		clientAddress = localAddr.String()
	}

	responseMessage, _, err := client.ExchangeWithConn(message, connection)

	if dnsContext, ok := ctx.Value(dnsUtilsContext.DnsContextKey).(*dnsUtilsTypes.DnsContext); ok && dnsContext != nil {
		// TODO: Maybe I can obtain an earlier time?
		t := time.Now()
		dnsContext.Time = &t
		dnsContext.ClientAddress = clientAddress
		dnsContext.ServerAddress = serverAddress
		dnsContext.Transport = strings.TrimSuffix(strings.ToLower(client.Net), "-tls")
		dnsContext.QuestionMessage = message
		dnsContext.AnswerMessage = responseMessage

		if tlsConn, ok := connection.Conn.(*tls.Conn); ok && tlsConn != nil {
			connectionState := tlsConn.ConnectionState()
			dnsContext.TlsContext = &motmedelTlsTypes.TlsContext{
				ConnectionState: &connectionState,
				ClientInitiated: true,
			}
		}
	}

	if err != nil {
		return nil, motmedelErrors.NewWithTrace(fmt.Errorf("dns client exchange: %w", err))
	}
	if responseMessage == nil {
		return nil, motmedelErrors.NewWithTrace(fmt.Errorf("%w (response)", dnsUtilsErrors.ErrNilMessage))
	}

	if responseMessage.Rcode != dns.RcodeSuccess {
		return responseMessage, motmedelErrors.NewWithTrace(&dnsUtilsErrors.RcodeError{Rcode: responseMessage.Rcode})
	}

	return responseMessage, nil
}

func GetDnsAnswersWithMessage(ctx context.Context, message *dns.Msg, client *dns.Client, serverAddress string) ([]dns.RR, error) {
	if message == nil {
		return nil, nil
	}

	if client == nil {
		return nil, motmedelErrors.NewWithTrace(dnsUtilsErrors.ErrNilDnsClient)
	}

	if serverAddress == "" {
		return nil, motmedelErrors.NewWithTrace(dnsUtilsErrors.ErrEmptyDnsServer)
	}

	responseMessage, err := Exchange(ctx, message, client, serverAddress)
	if err != nil {
		return nil, fmt.Errorf("exchange: %w", err)
	}
	if responseMessage == nil {
		return nil, motmedelErrors.NewWithTrace(fmt.Errorf("%w (response)", dnsUtilsErrors.ErrNilMessage))
	}

	if responseMessage.Truncated {
		tcpDnsClient := *client
		tcpDnsClient.Net = "tcp"

		responseMessage, err = Exchange(ctx, message, &tcpDnsClient, serverAddress)
		if err != nil {
			return nil, motmedelErrors.New(fmt.Errorf("exchange: %w", err), tcpDnsClient)
		}
	}

	if responseMessage == nil {
		return nil, motmedelErrors.NewWithTrace(fmt.Errorf("%w (response)", dnsUtilsErrors.ErrNilMessage))
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

	if recordType == 0 {
		return nil, motmedelErrors.NewWithTrace(dnsUtilsErrors.ErrUnsetRecordType)
	}

	if client == nil {
		return nil, motmedelErrors.NewWithTrace(dnsUtilsErrors.ErrNilDnsClient)
	}

	if serverAddress == "" {
		return nil, motmedelErrors.NewWithTrace(dnsUtilsErrors.ErrEmptyDnsServer)
	}

	message := &dns.Msg{}
	message.SetQuestion(dns.Fqdn(domain), recordType)

	if client.Net == "" || client.Net == "udp" {
		if bufferSize := client.UDPSize; bufferSize > 0 {
			message.SetEdns0(bufferSize, false)
		}
	}

	return GetDnsAnswersWithMessage(ctx, message, client, serverAddress)
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

	if recordType == 0 {
		return nil, motmedelErrors.NewWithTrace(dnsUtilsErrors.ErrUnsetRecordType)
	}

	if dnsClient == nil {
		return nil, motmedelErrors.NewWithTrace(dnsUtilsErrors.ErrNilDnsClient)
	}

	if dnsServerAddress == "" {
		return nil, motmedelErrors.NewWithTrace(dnsUtilsErrors.ErrEmptyDnsServer)
	}

	answers, err := GetDnsAnswers(ctx, domain, recordType, dnsClient, dnsServerAddress)
	if err != nil {
		return nil, fmt.Errorf("get dns answers: %w", err)
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

	if dnsClient == nil {
		return nil, motmedelErrors.NewWithTrace(dnsUtilsErrors.ErrNilDnsClient)
	}

	if dnsServerAddress == "" {
		return nil, motmedelErrors.NewWithTrace(dnsUtilsErrors.ErrEmptyDnsServer)
	}

	answerStrings, err := GetDnsAnswerStrings(ctx, domain, dns.TypeTXT, dnsClient, dnsServerAddress)
	if err != nil {
		return nil, fmt.Errorf("get dns answer strings: %w", err)
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

	if client == nil {
		return false, motmedelErrors.NewWithTrace(dnsUtilsErrors.ErrNilDnsClient)
	}

	if serverAddress == "" {
		return false, motmedelErrors.NewWithTrace(dnsUtilsErrors.ErrEmptyDnsServer)
	}

	// NOTE: The question type should not matter?
	_, err := GetDnsAnswers(ctx, domain, dns.TypeSOA, client, serverAddress)
	if err != nil {
		var rcodeError *dnsUtilsErrors.RcodeError
		if errors.As(err, &rcodeError) {
			if rcodeError.Rcode == dns.RcodeNameError {
				return false, nil
			}
		}
		return false, fmt.Errorf("get dns answers: %w", err)
	}

	return true, nil
}

func SupportsDnssec(ctx context.Context, domain string, client *dns.Client, serverAddress string) (bool, error) {
	if domain == "" {
		return false, nil
	}

	if client == nil {
		return false, motmedelErrors.NewWithTrace(dnsUtilsErrors.ErrNilDnsClient)
	}

	if serverAddress == "" {
		return false, motmedelErrors.NewWithTrace(dnsUtilsErrors.ErrEmptyDnsServer)
	}

	message := new(dns.Msg)
	message.SetQuestion(dns.Fqdn(domain), dns.TypeDNSKEY)

	opt := &dns.OPT{
		Hdr:    dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT, Class: 4096},
		Option: []dns.EDNS0{&dns.EDNS0_COOKIE{}},
	}
	opt.SetDo()

	message.Extra = append(message.Extra, opt)

	answers, err := GetDnsAnswersWithMessage(ctx, message, client, serverAddress)
	if err != nil {
		return false, motmedelErrors.New(fmt.Errorf("get dns answers with message: %w", err), message)
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
