package dns_utils

import (
	"bufio"
	"fmt"
	"github.com/miekg/dns"
	"os"
	"strings"
)

func GetDNSAnswers(domain string, recordType uint16, dnsClient *dns.Client, dnsServerAddress string) ([]dns.RR, error) {
	dnsMessage := &dns.Msg{}
	dnsMessage.SetQuestion(dns.Fqdn(domain), recordType)

	in, _, err := dnsClient.Exchange(dnsMessage, dnsServerAddress)
	if err != nil {
		return nil, err
	}

	if in.Rcode != dns.RcodeSuccess {
		if in.Rcode == dns.RcodeNameError {
			return nil, nil
		}

		return nil, fmt.Errorf("DNS query failed with rcode %v", in.Rcode)
	}

	if in.MsgHdr.Truncated {
		dnsMessage.SetEdns0(4096, true)

		in, _, err = dnsClient.Exchange(dnsMessage, dnsServerAddress)
		if err != nil {
			return nil, err
		}
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
	answers, err := GetDNSAnswers(domain, recordType, dnsClient, dnsServerAddress)
	if err != nil {
		return nil, err
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
					return nil, fmt.Errorf(
						"failed to recursively lookup txt record for %v: %w",
						t.Target,
						err,
					)
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
	file, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return nil, err
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
	answerStrings, err := GetDNSAnswerStrings(domain, dns.TypeTXT, dnsClient, dnsServerAddress, true)
	if err != nil {
		return "", err
	}

	for _, answerString := range answerStrings {
		if strings.HasPrefix(answerString, prefix) {
			return answerString, nil
		}
	}

	return "", nil
}
