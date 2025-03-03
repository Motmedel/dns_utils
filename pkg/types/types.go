package types

import (
	"context"
	"github.com/Motmedel/dns_utils/pkg/dns_utils"
	"github.com/miekg/dns"
)

type Client struct {
	*dns.Client
	Address string
}

func (client *Client) GetDnsAnswersWithMessage(ctx context.Context, message *dns.Msg) ([]dns.RR, error) {
	return dns_utils.GetDnsAnswersWithMessage(ctx, message, client.Client, client.Address)
}

func (client *Client) GetDnsAnswers(ctx context.Context, domain string, recordType uint16) ([]dns.RR, error) {
	return dns_utils.GetDnsAnswers(ctx, domain, recordType, client.Client, client.Address)
}

func (client *Client) GetDnsAnswerStrings(ctx context.Context, domain string, recordType uint16) ([]string, error) {
	return dns_utils.GetDnsAnswerStrings(ctx, domain, recordType, client.Client, client.Address)
}

func (client *Client) GetPrefixedTxtRecordStrings(ctx context.Context, domain string, prefix string) ([]string, error) {
	return dns_utils.GetPrefixedTxtRecordStrings(ctx, domain, prefix, client.Client, client.Address)
}

func (client *Client) GetActiveRecords(domain string) (*ActiveResult, error) {
	return dns_utils.GetActiveRecords(domain, client.Client, client.Address)
}

type ActiveResult struct {
	Domain    string
	Cnames    []string
	Addresses []string
	MxHosts   []string
}

type DnsContext struct {
	QuestionMessage *dns.Msg
	AnswerMessage   *dns.Msg
}

func NewClient(serverAddress string) *Client {
	return &Client{
		Client:  new(dns.Client),
		Address: serverAddress,
	}
}
