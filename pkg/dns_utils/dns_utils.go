package dns_utils

import (
	"bufio"
	"fmt"
	dnsUtilsErrors "github.com/Motmedel/dns_utils/pkg/errors"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"github.com/miekg/dns"
	"os"
	"strings"
	"sync"
)

const resolvePath = "/etc/resolv.conf"

func GetDnsAnswersWithMessage(message *dns.Msg, client *dns.Client, serverAddress string) ([]dns.RR, error) {
	if message == nil {
		return nil, nil
	}

	if client == nil {
		return nil, motmedelErrors.MakeErrorWithStackTrace(dnsUtilsErrors.ErrNilDnsClient)
	}

	if serverAddress == "" {
		return nil, motmedelErrors.MakeErrorWithStackTrace(dnsUtilsErrors.ErrEmptyDnsServer)
	}

	in, _, err := client.Exchange(message, serverAddress)
	if err != nil {
		return nil, motmedelErrors.MakeErrorWithStackTrace(
			fmt.Errorf("dns client exchange: %w", err),
			message,
			serverAddress,
		)
	}
	if in == nil {
		return nil, motmedelErrors.MakeErrorWithStackTrace(dnsUtilsErrors.ErrNilExchangeMessage)
	}

	if in.Rcode != dns.RcodeSuccess {
		if in.Rcode == dns.RcodeNameError {
			return nil, nil
		}

		return nil, motmedelErrors.MakeErrorWithStackTrace(&dnsUtilsErrors.RcodeError{Rcode: in.Rcode})
	}

	if in.MsgHdr.Truncated {
		tcpDnsClient := *client
		tcpDnsClient.Net = "tcp"
		in, _, err = tcpDnsClient.Exchange(message, serverAddress)
		if err != nil {
			return nil, motmedelErrors.MakeErrorWithStackTrace(
				fmt.Errorf("dns client exchange (tcp): %w", err),
				message,
				serverAddress,
			)
		}
		if in == nil {
			return nil, motmedelErrors.MakeErrorWithStackTrace(dnsUtilsErrors.ErrNilExchangeMessage)
		}

		if in.Rcode != dns.RcodeSuccess {
			if in.Rcode == dns.RcodeNameError {
				return nil, nil
			}

			return nil, motmedelErrors.MakeErrorWithStackTrace(&dnsUtilsErrors.RcodeError{Rcode: in.Rcode})
		}
	}

	return in.Answer, nil
}

func GetDnsAnswers(domain string, recordType uint16, client *dns.Client, serverAddress string) ([]dns.RR, error) {
	if domain == "" {
		return nil, nil
	}

	if recordType == 0 {
		return nil, motmedelErrors.MakeErrorWithStackTrace(dnsUtilsErrors.ErrUnsetRecordType)
	}

	if client == nil {
		return nil, motmedelErrors.MakeErrorWithStackTrace(dnsUtilsErrors.ErrNilDnsClient)
	}

	if serverAddress == "" {
		return nil, motmedelErrors.MakeErrorWithStackTrace(dnsUtilsErrors.ErrEmptyDnsServer)
	}

	message := &dns.Msg{}
	message.SetQuestion(dns.Fqdn(domain), recordType)

	return GetDnsAnswersWithMessage(message, client, serverAddress)
}

func GetDnsAnswerStrings(
	domain string,
	recordType uint16,
	dnsClient *dns.Client,
	dnsServerAddress string,
) ([]string, error) {
	if domain == "" {
		return nil, nil
	}

	if recordType == 0 {
		return nil, motmedelErrors.MakeErrorWithStackTrace(dnsUtilsErrors.ErrUnsetRecordType)
	}

	if dnsClient == nil {
		return nil, motmedelErrors.MakeErrorWithStackTrace(dnsUtilsErrors.ErrNilDnsClient)
	}

	if dnsServerAddress == "" {
		return nil, motmedelErrors.MakeErrorWithStackTrace(dnsUtilsErrors.ErrEmptyDnsServer)
	}

	answers, err := GetDnsAnswers(domain, recordType, dnsClient, dnsServerAddress)
	if err != nil {
		return nil, motmedelErrors.MakeError(
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

func GetDnsServers() ([]string, error) {
	file, err := os.Open(resolvePath)
	if err != nil {
		return nil, motmedelErrors.MakeErrorWithStackTrace(fmt.Errorf("os open: %w", err), resolvePath)
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

func GetPrefixedTxtRecordStrings(
	domain string,
	prefix string,
	dnsClient *dns.Client,
	dnsServerAddress string,
) ([]string, error) {
	if domain == "" {
		return nil, nil
	}

	if prefix == "" {
		return nil, motmedelErrors.MakeErrorWithStackTrace(dnsUtilsErrors.ErrEmptyPrefix)
	}

	if dnsClient == nil {
		return nil, motmedelErrors.MakeErrorWithStackTrace(dnsUtilsErrors.ErrNilDnsClient)
	}

	if dnsServerAddress == "" {
		return nil, motmedelErrors.MakeErrorWithStackTrace(dnsUtilsErrors.ErrEmptyDnsServer)
	}

	answerStrings, err := GetDnsAnswerStrings(domain, dns.TypeTXT, dnsClient, dnsServerAddress)
	if err != nil {
		return nil, motmedelErrors.MakeError(
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

type ActiveResult struct {
	Domain    string
	Cnames    []string
	Addresses []string
	MxHosts   []string
}

func GetActiveRecords(domain string, client *dns.Client, serverAddress string) (*ActiveResult, error) {
	if domain == "" {
		return nil, nil
	}

	if client == nil {
		return nil, motmedelErrors.MakeErrorWithStackTrace(dnsUtilsErrors.ErrNilDnsClient)
	}

	if serverAddress == "" {
		return nil, motmedelErrors.MakeErrorWithStackTrace(dnsUtilsErrors.ErrEmptyDnsServer)
	}

	var cnames []string
	var addressRecords []string
	var addressRecordsMutex sync.Mutex
	var numGoroutines int
	errorChannel := make(chan error)

	var once sync.Once

	numGoroutines += 1
	go func() {
		errorChannel <- func() error {
			aAnswers, err := GetDnsAnswers(domain, dns.TypeA, client, serverAddress)
			if err != nil {
				return motmedelErrors.MakeError(
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
			aaaaAnswers, err := GetDnsAnswers(domain, dns.TypeAAAA, client, serverAddress)
			if err != nil {
				return motmedelErrors.MakeError(
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
			mxAnswers, err := GetDnsAnswers(domain, dns.TypeMX, client, serverAddress)
			if err != nil {
				return motmedelErrors.MakeError(
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

	return &ActiveResult{Domain: domain, Cnames: cnames, Addresses: addressRecords, MxHosts: mxHosts}, nil
}
