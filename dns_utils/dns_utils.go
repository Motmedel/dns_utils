package dns_utils

import (
	"bufio"
	"fmt"
	"github.com/miekg/dns"
	"os"
	"strings"
)

func getDNSAnswers(domain string, recordType uint16, dnsClient *dns.Client, dnsServerAddress string) ([]dns.RR, error) {
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

func getDNSRecords(
	domain string,
	recordType uint16,
	dnsClient *dns.Client,
	dnsServerAddress string,
	recurseCname bool,
) (records []string, err error) {
	answers, err := getDNSAnswers(domain, recordType, dnsClient, dnsServerAddress)
	if err != nil {
		return nil, err
	}

	for _, answer := range answers {
		if answer.Header().Rrtype == dns.TypeCNAME && recurseCname {
			if t, ok := answer.(*dns.CNAME); ok {
				recursiveLookupCname, err := getDNSRecords(
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
				records = append(records, recursiveLookupCname...)
				continue
			}
			answer.Header().Rrtype = recordType
		}

		switch dnsRec := answer.(type) {
		case *dns.A:
			records = append(records, dnsRec.A.String())
		case *dns.AAAA:
			records = append(records, dnsRec.AAAA.String())
		case *dns.MX:
			records = append(records, dnsRec.Mx)
		case *dns.NS:
			records = append(records, dnsRec.Ns)
		case *dns.TXT:
			records = append(records, strings.Join(dnsRec.Txt, ""))
		case *dns.CNAME:
			records = append(records, dnsRec.Target)
		}
	}

	return records, nil
}

func getDnsServers() ([]string, error) {
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
