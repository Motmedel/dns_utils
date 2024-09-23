package dns_utils

import (
	"bufio"
	dnsUtilsErrors "github.com/Motmedel/dns_utils/pkg/errors"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"github.com/miekg/dns"
	"os"
	"strings"
)

const resolvePath = "/etc/resolv.conf"

func GetDNSAnswers(domain string, recordType uint16, dnsClient *dns.Client, dnsServerAddress string) ([]dns.RR, error) {
	if domain == "" {
		return nil, nil
	}

	if recordType == 0 {
		return nil, dnsUtilsErrors.ErrUnsetRecordType
	}

	if dnsClient == nil {
		return nil, dnsUtilsErrors.ErrNilDnsClient
	}

	dnsMessage := &dns.Msg{}
	dnsMessage.SetQuestion(dns.Fqdn(domain), recordType)
	dnsMessage.SetEdns0(4096, true)

	in, _, err := dnsClient.Exchange(dnsMessage, dnsServerAddress)
	if err != nil {
		return nil, &motmedelErrors.CauseError{
			Message: "An error occurred when performing the DNS exchange",
			Cause:   err,
		}
	}

	if in.Rcode != dns.RcodeSuccess {
		if in.Rcode == dns.RcodeNameError {
			return nil, nil
		}

		return nil, &dnsUtilsErrors.RcodeError{Rcode: in.Rcode}
	}

	return in.Answer, nil
}

func GetDNSAnswerStrings(
	domain string,
	recordType uint16,
	dnsClient *dns.Client,
	dnsServerAddress string,
	recurseCname bool,
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

	answers, err := GetDNSAnswers(domain, recordType, dnsClient, dnsServerAddress)
	if err != nil {
		return nil, &motmedelErrors.CauseError{
			Message: "An error occurred when getting DNS answers.",
			Cause:   err,
		}
	}

	var answerStrings []string

	for _, answer := range answers {
		if answer.Header().Rrtype == dns.TypeCNAME && recurseCname {
			if t, ok := answer.(*dns.CNAME); ok {
				recursiveLookupCname, err := GetDNSAnswerStrings(
					t.Target,
					recordType,
					dnsClient,
					dnsServerAddress,
					recurseCname,
				)
				if err != nil {
					return nil, &motmedelErrors.InputError{
						Message: "An error occurred when getting DNS answers strings.",
						Cause:   err,
						Input:   t.Target,
					}
				}
				answerStrings = append(answerStrings, recursiveLookupCname...)
				continue
			}
			answer.Header().Rrtype = recordType
		}

		switch dnsRec := answer.(type) {
		case *dns.A:
			answerStrings = append(answerStrings, dnsRec.A.String())
		case *dns.AAAA:
			answerStrings = append(answerStrings, dnsRec.AAAA.String())
		case *dns.MX:
			answerStrings = append(answerStrings, dnsRec.Mx)
		case *dns.NS:
			answerStrings = append(answerStrings, dnsRec.Ns)
		case *dns.TXT:
			answerStrings = append(answerStrings, strings.Join(dnsRec.Txt, ""))
		case *dns.CNAME:
			answerStrings = append(answerStrings, dnsRec.Target)
		}
	}

	return answerStrings, nil
}

func GetDNSServers() ([]string, error) {
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

func GetPrefixedTXTRecordString(
	domain string,
	prefix string,
	dnsClient *dns.Client,
	dnsServerAddress string,
) (string, error) {
	if domain == "" {
		return "", nil
	}

	if prefix == "" {
		return "", dnsUtilsErrors.ErrEmptyPrefix
	}

	if dnsClient == nil {
		return "", dnsUtilsErrors.ErrNilDnsClient
	}

	if dnsServerAddress == "" {
		return "", dnsUtilsErrors.ErrEmptyDnsServer
	}

	answerStrings, err := GetDNSAnswerStrings(domain, dns.TypeTXT, dnsClient, dnsServerAddress, true)
	if err != nil {
		return "", &motmedelErrors.InputError{
			Message: "An error occurred when getting TXT DNS answer strings..",
			Cause:   err,
			Input:   domain,
		}
	}

	for _, answerString := range answerStrings {
		if strings.HasPrefix(answerString, prefix) {
			return answerString, nil
		}
	}

	return "", nil
}
