package config

import (
	"testing"

	"github.com/miekg/dns"
)

func TestNew(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name            string
		options         []Option
		expectedAddress string
		expectClient    bool
	}{
		{
			name:            "no options leaves the defaults",
			options:         nil,
			expectedAddress: DefaultAddress,
			expectClient:    true,
		},
		{
			name:            "the address can be set",
			options:         []Option{WithAddress("192.0.2.1:53")},
			expectedAddress: "192.0.2.1:53",
			expectClient:    true,
		},
		{
			// A nil option must be skipped rather than panic the constructor.
			name:            "a nil option is ignored",
			options:         []Option{nil, WithAddress("192.0.2.2:53"), nil},
			expectedAddress: "192.0.2.2:53",
			expectClient:    true,
		},
		{
			name:            "the last option wins",
			options:         []Option{WithAddress("first:53"), WithAddress("second:53")},
			expectedAddress: "second:53",
			expectClient:    true,
		},
		{
			name:            "the client can be replaced",
			options:         []Option{WithDnsClient(&dns.Client{Net: "tcp-tls"})},
			expectedAddress: DefaultAddress,
			expectClient:    true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			config := New(testCase.options...)

			if config == nil {
				t.Fatal("expected a configuration")
			}

			if config.Address != testCase.expectedAddress {
				t.Errorf("expected address %q, got %q", testCase.expectedAddress, config.Address)
			}

			if testCase.expectClient && config.DnsClient == nil {
				t.Error("expected a dns client")
			}
		})
	}
}

func TestNewDefaultClientCarriesTheDefaultUdpSize(t *testing.T) {
	t.Parallel()

	config := New()

	if config.DnsClient.UDPSize != DefaultUDPSize {
		t.Errorf("expected UDP size %d, got %d", DefaultUDPSize, config.DnsClient.UDPSize)
	}
}

func TestWithDnsClientReplacesTheDefault(t *testing.T) {
	t.Parallel()

	client := &dns.Client{Net: "tcp-tls"}

	config := New(WithDnsClient(client))

	if config.DnsClient != client {
		t.Error("expected the supplied client to be used")
	}
}
