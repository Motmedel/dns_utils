package config

import (
	"github.com/miekg/dns"
)

type Option func(*Config)

const (
	DefaultAddress = "8.8.8.8:53"
	DefaultUDPSize = 4096
)

type Config struct {
	Address   string
	DnsClient *dns.Client
}

func New(options ...Option) *Config {
	config := &Config{
		Address:   DefaultAddress,
		DnsClient: &dns.Client{UDPSize: DefaultUDPSize},
	}

	for _, option := range options {
		if option != nil {
			option(config)
		}
	}

	return config
}

func WithAddress(address string) Option {
	return func(configuration *Config) {
		configuration.Address = address
	}
}

func WithDnsClient(dnsClient *dns.Client) Option {
	return func(configuration *Config) {
		configuration.DnsClient = dnsClient
	}
}
