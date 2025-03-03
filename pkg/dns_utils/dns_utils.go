package dns_utils

import (
	"bufio"
	"context"
	"fmt"
	dnsUtilsContext "github.com/Motmedel/dns_utils/pkg/context"
	dnsUtilsErrors "github.com/Motmedel/dns_utils/pkg/errors"
	dnsUtilsTypes "github.com/Motmedel/dns_utils/pkg/types"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"github.com/miekg/dns"
	"os"
	"strings"
	"sync"
)

const resolvePath = "/etc/resolv.conf"

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

	in, _, err := client.Exchange(message, serverAddress)
	dnsContext, ok := ctx.Value(*dnsUtilsContext.DnsContextKey).(*dnsUtilsTypes.DnsContext)
	if ok && dnsContext != nil {
		dnsContext.QuestionMessage = message
		dnsContext.AnswerMessage = in
	}
	if err != nil {
		return nil, motmedelErrors.NewWithTrace(
			fmt.Errorf("dns client exchange: %w", err),
			message,
			serverAddress,
		)
	}
	if in == nil {
		return nil, motmedelErrors.NewWithTrace(dnsUtilsErrors.ErrNilExchangeMessage)
	}

	if in.Rcode != dns.RcodeSuccess {
		if in.Rcode == dns.RcodeNameError {
			return nil, nil
		}

		return nil, motmedelErrors.NewWithTrace(&dnsUtilsErrors.RcodeError{Rcode: in.Rcode})
	}

	if in.MsgHdr.Truncated {
		tcpDnsClient := *client
		tcpDnsClient.Net = "tcp"
		in, _, err = tcpDnsClient.Exchange(message, serverAddress)
		if dnsContext != nil {
			dnsContext.QuestionMessage = message
			dnsContext.AnswerMessage = in
		}
		if err != nil {
			return nil, motmedelErrors.NewWithTrace(
				fmt.Errorf("dns client exchange (tcp): %w", err),
				message,
				serverAddress,
			)
		}
		if in == nil {
			return nil, motmedelErrors.NewWithTrace(dnsUtilsErrors.ErrNilExchangeMessage)
		}

		if in.Rcode != dns.RcodeSuccess {
			if in.Rcode == dns.RcodeNameError {
				return nil, nil
			}

			return nil, motmedelErrors.NewWithTrace(&dnsUtilsErrors.RcodeError{Rcode: in.Rcode})
		}
	}

	return in.Answer, nil
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

	return GetDnsAnswersWithMessage(ctx, message, client, serverAddress)
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
		return nil, motmedelErrors.New(
			fmt.Errorf("get dns answers: %w", err),
			domain,
			recordType,
			dnsClient,
			dnsServerAddress,
		)
	}

	var answerStrings []string

	for _, answer := range answers {
		switch typedAnswer := answer.(type) {
		case *dns.A:
			if a := typedAnswer.A; a != nil {
				answerStrings = append(answerStrings, a.String())
			}
		case *dns.AAAA:
			if aaaa := typedAnswer.AAAA; aaaa != nil {
				answerStrings = append(answerStrings, aaaa.String())
			}
		case *dns.MX:
			answerStrings = append(answerStrings, typedAnswer.Mx)
		case *dns.NS:
			answerStrings = append(answerStrings, typedAnswer.Ns)
		case *dns.TXT:
			answerStrings = append(answerStrings, strings.Join(typedAnswer.Txt, ""))
		case *dns.CNAME:
			answerStrings = append(answerStrings, typedAnswer.Target)
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

	if prefix == "" {
		return nil, motmedelErrors.NewWithTrace(dnsUtilsErrors.ErrEmptyPrefix)
	}

	if dnsClient == nil {
		return nil, motmedelErrors.NewWithTrace(dnsUtilsErrors.ErrNilDnsClient)
	}

	if dnsServerAddress == "" {
		return nil, motmedelErrors.NewWithTrace(dnsUtilsErrors.ErrEmptyDnsServer)
	}

	answerStrings, err := GetDnsAnswerStrings(ctx, domain, dns.TypeTXT, dnsClient, dnsServerAddress)
	if err != nil {
		return nil, motmedelErrors.New(
			fmt.Errorf("get dns answer strings: %w", err),
			domain, dnsClient, dnsServerAddress,
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

func GetActiveRecords(
	domain string,
	client *dns.Client,
	serverAddress string,
) (*dnsUtilsTypes.ActiveResult, error) {
	if domain == "" {
		return nil, nil
	}

	if client == nil {
		return nil, motmedelErrors.NewWithTrace(dnsUtilsErrors.ErrNilDnsClient)
	}

	if serverAddress == "" {
		return nil, motmedelErrors.NewWithTrace(dnsUtilsErrors.ErrEmptyDnsServer)
	}

	var cnames []string
	var addressRecords []string
	var addressRecordsMutex sync.Mutex
	var numGoroutines int
	errorChannel := make(chan error)

	var once sync.Once

	// TODO: Use `errgroup` instead?

	numGoroutines += 1
	go func() {
		errorChannel <- func() error {
			aAnswers, err := GetDnsAnswers(context.Background(), domain, dns.TypeA, client, serverAddress)
			if err != nil {
				return motmedelErrors.New(
					fmt.Errorf("get dns answers (a): %w", err),
					domain, client, serverAddress,
				)
			}

			var aCnames []string
			for _, answer := range aAnswers {
				switch typedAnswer := answer.(type) {
				case *dns.A:
					addressRecordsMutex.Lock()
					addressRecords = append(addressRecords, typedAnswer.A.String())
					addressRecordsMutex.Unlock()
				case *dns.CNAME:
					aCnames = append(aCnames, typedAnswer.Target)
				}
			}

			once.Do(func() {
				cnames = aCnames
			})

			return nil
		}()
	}()

	numGoroutines += 1
	go func() {
		errorChannel <- func() error {
			aaaaAnswers, err := GetDnsAnswers(context.Background(), domain, dns.TypeAAAA, client, serverAddress)
			if err != nil {
				return motmedelErrors.New(
					fmt.Errorf("get dns answers (aaaa): %w", err),
					domain, client, serverAddress,
				)
			}

			var aaaaCnames []string
			for _, answer := range aaaaAnswers {
				switch typedAnswer := answer.(type) {
				case *dns.AAAA:
					addressRecordsMutex.Lock()
					addressRecords = append(addressRecords, typedAnswer.AAAA.String())
					addressRecordsMutex.Unlock()
				case *dns.CNAME:
					aaaaCnames = append(aaaaCnames, typedAnswer.Target)
				}
			}

			once.Do(func() {
				cnames = aaaaCnames
			})

			return nil
		}()
	}()

	var mxHosts []string

	numGoroutines += 1
	go func() {
		errorChannel <- func() error {
			var err error
			mxAnswers, err := GetDnsAnswers(context.Background(), domain, dns.TypeMX, client, serverAddress)
			if err != nil {
				return motmedelErrors.New(
					fmt.Errorf("get dns answers (mx): %w", err),
					domain, client, serverAddress,
				)
			}

			for _, answer := range mxAnswers {
				switch typedAnswer := answer.(type) {
				case *dns.MX:
					mxHosts = append(mxHosts, typedAnswer.Mx)
				}
			}

			return nil
		}()
	}()

	for i := 0; i < numGoroutines; i++ {
		if err := <-errorChannel; err != nil {
			return nil, err
		}
	}

	return &dnsUtilsTypes.ActiveResult{Domain: domain, Cnames: cnames, Addresses: addressRecords, MxHosts: mxHosts}, nil
}
