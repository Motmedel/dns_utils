package quic

import (
	"context"
	"errors"
	"testing"

	dnsUtilsContext "github.com/Motmedel/dns_utils/pkg/context"
	dnsUtilsTypes "github.com/Motmedel/dns_utils/pkg/types"
	"github.com/Motmedel/utils_go/pkg/errors/types/empty_error"
	"github.com/miekg/dns"
)

func TestExchange_NilMessage(t *testing.T) {
	got, err := Exchange(context.Background(), nil, "1.2.3.4:853", nil, nil)
	if err != nil {
		t.Errorf("err = %v, want nil", err)
	}
	if got != nil {
		t.Errorf("got = %v, want nil", got)
	}
}

func TestExchange_EmptyServer(t *testing.T) {
	ctx := context.WithValue(context.Background(), dnsUtilsContext.DnsContextKey, &dnsUtilsTypes.DnsContext{})
	_, err := Exchange(ctx, &dns.Msg{}, "", nil, nil)
	if err == nil {
		t.Fatal("err = nil, want error")
	}

	var ee *empty_error.Error
	if !errors.As(err, &ee) {
		t.Fatalf("err type = %T (%v), want *empty_error.Error", err, err)
	}
	if ee.Field != "dns server" {
		t.Errorf("Field = %q, want %q", ee.Field, "dns server")
	}
}
