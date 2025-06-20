package client

import (
	"context"
	"fmt"
	"github.com/Motmedel/dns_utils/pkg/dns_utils"
	dnsUtilsErrors "github.com/Motmedel/dns_utils/pkg/errors"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"github.com/miekg/dns"
)

type Client struct {
	*dns.Client
	Address string
}

func (client *Client) Exchange(ctx context.Context, message *dns.Msg) (*dns.Msg, error) {
	return dns_utils.Exchange(ctx, message, client.Client, client.Address)
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

func (client *Client) DomainExists(ctx context.Context, domain string) (bool, error) {
	return dns_utils.DomainExists(ctx, domain, client.Client, client.Address)
}

func (client *Client) SupportsDnssec(ctx context.Context, domain string) (bool, error) {
	return dns_utils.SupportsDnssec(ctx, domain, client.Client, client.Address)
}

func NewWithAddress(address string) (*Client, error) {
	if address == "" {
		return nil, motmedelErrors.NewWithTrace(dnsUtilsErrors.ErrEmptyDnsServer)
	}

	var client dns.Client
	client.UDPSize = 4096

	return &Client{Client: &client, Address: address}, nil
}

func New(ctx context.Context) (*Client, error) {
	dnsServerAddresses, err := dns_utils.GetDnsServers(ctx)
	if err != nil {
		return nil, fmt.Errorf("get dns servers: %w", err)
	}

	if len(dnsServerAddresses) == 0 {
		return nil, motmedelErrors.NewWithTrace(dnsUtilsErrors.ErrEmptyDnsServer)
	}

	return NewWithAddress(dnsServerAddresses[0] + ":53")
}
