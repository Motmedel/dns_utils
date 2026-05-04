package client

import (
	"context"
	"fmt"
	"net"

	"github.com/Motmedel/dns_utils/pkg/dns_utils"
	"github.com/Motmedel/dns_utils/pkg/types/client/config"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"github.com/Motmedel/utils_go/pkg/errors/types/empty_error"
	"github.com/miekg/dns"
)

var DefaultClient = New()

type Client struct {
	*config.Config
}

func (c *Client) resolve() (*dns.Client, string) {
	if c == nil || c.Config == nil {
		return nil, ""
	}
	return c.DnsClient, c.Address
}

func (c *Client) Exchange(ctx context.Context, message *dns.Msg) (*dns.Msg, error) {
	dnsClient, address := c.resolve()
	return dns_utils.Exchange(ctx, message, dnsClient, address)
}

func (c *Client) GetDnsAnswersWithMessage(ctx context.Context, message *dns.Msg) ([]dns.RR, error) {
	dnsClient, address := c.resolve()
	return dns_utils.GetDnsAnswersWithMessage(ctx, message, dnsClient, address)
}

func (c *Client) GetDnsAnswers(ctx context.Context, domain string, recordType uint16) ([]dns.RR, error) {
	dnsClient, address := c.resolve()
	return dns_utils.GetDnsAnswers(ctx, domain, recordType, dnsClient, address)
}

func (c *Client) GetDnsAnswerStrings(ctx context.Context, domain string, recordType uint16) ([]string, error) {
	dnsClient, address := c.resolve()
	return dns_utils.GetDnsAnswerStrings(ctx, domain, recordType, dnsClient, address)
}

func (c *Client) GetPrefixedTxtRecordStrings(ctx context.Context, domain string, prefix string) ([]string, error) {
	dnsClient, address := c.resolve()
	return dns_utils.GetPrefixedTxtRecordStrings(ctx, domain, prefix, dnsClient, address)
}

func (c *Client) DomainExists(ctx context.Context, domain string) (bool, error) {
	dnsClient, address := c.resolve()
	return dns_utils.DomainExists(ctx, domain, dnsClient, address)
}

func (c *Client) SupportsDnssec(ctx context.Context, domain string) (bool, error) {
	dnsClient, address := c.resolve()
	return dns_utils.SupportsDnssec(ctx, domain, dnsClient, address)
}

func New(options ...config.Option) *Client {
	return &Client{Config: config.New(options...)}
}

func NewFromResolvConf(ctx context.Context, options ...config.Option) (*Client, error) {
	dnsServerAddresses, err := dns_utils.GetDnsServers(ctx)
	if err != nil {
		return nil, fmt.Errorf("get dns servers: %w", err)
	}

	if len(dnsServerAddresses) == 0 {
		return nil, motmedelErrors.NewWithTrace(empty_error.New("dns server"))
	}

	address := net.JoinHostPort(dnsServerAddresses[0], "53")
	options = append([]config.Option{config.WithAddress(address)}, options...)
	return New(options...), nil
}
