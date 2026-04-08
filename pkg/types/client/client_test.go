package client

import (
	"errors"
	"testing"

	"github.com/Motmedel/utils_go/pkg/errors/types/empty_error"
)

func TestNewWithAddress_Empty(t *testing.T) {
	c, err := NewWithAddress("")
	if c != nil {
		t.Errorf("client = %v, want nil", c)
	}

	var ee *empty_error.Error
	if !errors.As(err, &ee) {
		t.Fatalf("err type = %T (%v), want *empty_error.Error", err, err)
	}
	if ee.Field != "dns server" {
		t.Errorf("Field = %q, want %q", ee.Field, "dns server")
	}
}

func TestNewWithAddress_Valid(t *testing.T) {
	const addr = "8.8.8.8:53"
	c, err := NewWithAddress(addr)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if c == nil {
		t.Fatal("client = nil, want non-nil")
	}
	if c.Address != addr {
		t.Errorf("Address = %q, want %q", c.Address, addr)
	}
	if c.Client == nil {
		t.Fatal("inner Client = nil, want non-nil")
	}
	if c.UDPSize != 4096 {
		t.Errorf("UDPSize = %d, want 4096", c.UDPSize)
	}
}

func TestDefaultClient(t *testing.T) {
	if DefaultClient == nil {
		t.Fatal("DefaultClient is nil")
	}
	if DefaultClient.Address != DefaultServerAddress {
		t.Errorf("DefaultClient.Address = %q, want %q", DefaultClient.Address, DefaultServerAddress)
	}
	if DefaultClient.Client == nil {
		t.Fatal("DefaultClient.Client is nil")
	}
}
