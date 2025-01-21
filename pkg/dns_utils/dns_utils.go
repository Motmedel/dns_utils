package dns_utils

import (
	"bufio"
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
		return nil, dnsUtilsErrors.ErrNilDnsClient
	}

	if serverAddress == "" {
		return nil, dnsUtilsErrors.ErrEmptyDnsServer
	}

	in, _, err := client.Exchange(message, serverAddress)
	if err != nil {
		return nil, &motmedelErrors.CauseError{
			Message: "An error occurred when performing the DNS exchange.",
			Cause:   err,
		}
	}
	if in == nil {
		return nil, dnsUtilsErrors.ErrNilExchangeMessage
	}

	if in.Rcode != dns.RcodeSuccess {
		if in.Rcode == dns.RcodeNameError {
			return nil, nil
		}

		return nil, &dnsUtilsErrors.RcodeError{Rcode: in.Rcode}
	}

	if in.MsgHdr.Truncated {
		tcpDnsClient := *client
		tcpDnsClient.Net = "tcp"
		in, _, err = tcpDnsClient.Exchange(message, serverAddress)
		if err != nil {
			return nil, &motmedelErrors.CauseError{
				Message: "An error occurred when performing the DNS exchange with a TCP client.",
				Cause:   err,
			}
		}
		if in == nil {
			return nil, dnsUtilsErrors.ErrNilExchangeMessage
		}

		if in.Rcode != dns.RcodeSuccess {
			if in.Rcode == dns.RcodeNameError {
				return nil, nil
			}

			return nil, &dnsUtilsErrors.RcodeError{Rcode: in.Rcode}
		}
	}

	return in.Answer, nil
}

func GetDnsAnswers(domain string, recordType uint16, client *dns.Client, serverAddress string) ([]dns.RR, error) {
	if domain == "" {
		return nil, nil
	}

	if recordType == 0 {
		return nil, dnsUtilsErrors.ErrUnsetRecordType
	}

	if client == nil {
		return nil, dnsUtilsErrors.ErrNilDnsClient
	}

	if serverAddress == "" {
		return nil, dnsUtilsErrors.ErrEmptyDnsServer
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
		return nil, dnsUtilsErrors.ErrUnsetRecordType
	}

	if dnsClient == nil {
		return nil, dnsUtilsErrors.ErrNilDnsClient
	}

	if dnsServerAddress == "" {
		return nil, dnsUtilsErrors.ErrEmptyDnsServer
	}

	answers, err := GetDnsAnswers(domain, recordType, dnsClient, dnsServerAddress)
	if err != nil {
		return nil, &motmedelErrors.CauseError{
			Message: "An error occurred when getting DNS answers.",
			Cause:   err,
		}
	}

	var answerStrings []string

	for _, answer := range answers {
		switch typedAnswer := answer.(type) {
		case *dns.A:
			if a := typedAnswer.A; len(a) != 0 {
				answerStrings = append(answerStrings, a.String())
			}
		case *dns.AAAA:
			if aaaa := typedAnswer.AAAA; len(aaaa) != 0 {
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
		return nil, &motmedelErrors.InputError{
			Message: "An error occurred when opening the resolve file.",
			Cause:   err,
			Input:   resolvePath,
		}
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
		return nil, dnsUtilsErrors.ErrEmptyPrefix
	}

	if dnsClient == nil {
		return nil, dnsUtilsErrors.ErrNilDnsClient
	}

	if dnsServerAddress == "" {
		return nil, dnsUtilsErrors.ErrEmptyDnsServer
	}

	answerStrings, err := GetDnsAnswerStrings(domain, dns.TypeTXT, dnsClient, dnsServerAddress)
	if err != nil {
		return nil, &motmedelErrors.InputError{
			Message: "An error occurred when getting TXT DNS answer strings.",
			Cause:   err,
			Input:   domain,
		}
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
		return nil, dnsUtilsErrors.ErrNilDnsClient
	}

	if serverAddress == "" {
		return nil, dnsUtilsErrors.ErrEmptyDnsServer
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
				return &motmedelErrors.InputError{
					Message: "An error occurred when querying for A records.",
					Cause:   err,
					Input:   domain,
				}
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
				return &motmedelErrors.InputError{
					Message: "An error occurred when querying for AAAA records.",
					Cause:   err,
					Input:   domain,
				}
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
				return &motmedelErrors.InputError{
					Message: "An error occurred when querying for MX records.",
					Cause:   err,
					Input:   domain,
				}
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
