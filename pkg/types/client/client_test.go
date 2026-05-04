package client

import (
	"testing"

	"github.com/Motmedel/dns_utils/pkg/types/client/config"
)

func TestNew_Defaults(t *testing.T) {
	c := New()
	if c == nil {
		t.Fatal("client = nil, want non-nil")
	}
	if c.Config == nil {
		t.Fatal("Config = nil, want non-nil")
	}
	if c.Address != config.DefaultAddress {
		t.Errorf("Address = %q, want %q", c.Address, config.DefaultAddress)
	}
	if c.DnsClient == nil {
		t.Fatal("DnsClient = nil, want non-nil")
	}
	if c.DnsClient.UDPSize != config.DefaultUDPSize {
		t.Errorf("UDPSize = %d, want %d", c.DnsClient.UDPSize, config.DefaultUDPSize)
	}
}

func TestNew_WithAddress(t *testing.T) {
	const addr = "1.1.1.1:53"
	c := New(config.WithAddress(addr))
	if c == nil {
		t.Fatal("client = nil, want non-nil")
	}
	if c.Address != addr {
		t.Errorf("Address = %q, want %q", c.Address, addr)
	}
}

func TestDefaultClient(t *testing.T) {
	if DefaultClient == nil {
		t.Fatal("DefaultClient is nil")
	}
	if DefaultClient.Address != config.DefaultAddress {
		t.Errorf("DefaultClient.Address = %q, want %q", DefaultClient.Address, config.DefaultAddress)
	}
	if DefaultClient.DnsClient == nil {
		t.Fatal("DefaultClient.DnsClient is nil")
	}
}
