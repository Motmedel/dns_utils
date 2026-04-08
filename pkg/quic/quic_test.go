package quic

import (
	"context"
	"errors"
	"testing"

	dnsUtilsContext "github.com/Motmedel/dns_utils/pkg/context"
	dnsUtilsTypes "github.com/Motmedel/dns_utils/pkg/types"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"github.com/Motmedel/utils_go/pkg/errors/types/empty_error"
	"github.com/miekg/dns"
)

func extractDnsContext(t *testing.T, err error) *dnsUtilsTypes.DnsContext {
	t.Helper()

	var extErr *motmedelErrors.ExtendedError
	if !errors.As(err, &extErr) {
		t.Fatalf("expected *motmedelErrors.ExtendedError, got %T (%v)", err, err)
	}
	ctxPtr := extErr.GetContext()
	if ctxPtr == nil {
		t.Fatal("ExtendedError.Context is nil")
	}
	dnsCtx, ok := (*ctxPtr).Value(dnsUtilsContext.DnsContextKey).(*dnsUtilsTypes.DnsContext)
	if !ok || dnsCtx == nil {
		t.Fatal("DnsContext not found in error context")
	}
	return dnsCtx
}

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
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn("example.com"), dns.TypeA)

	_, err := Exchange(context.Background(), msg, "", nil, nil)
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

func TestExchange_EmptyServer_WithoutPreexistingDnsContext(t *testing.T) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn("example.com"), dns.TypeA)

	// No dnsContext in ctx — this used to panic because of an unchecked type
	// assertion.
	_, err := Exchange(context.Background(), msg, "", nil, nil)
	if err == nil {
		t.Fatal("err = nil, want error")
	}
}

func TestExchange_Error_AttachesDnsContextWithQuestion(t *testing.T) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn("example.com"), dns.TypeA)

	_, err := Exchange(context.Background(), msg, "", nil, nil)
	dnsCtx := extractDnsContext(t, err)

	if dnsCtx.QuestionMessage != msg {
		t.Errorf("DnsContext.QuestionMessage = %v, want %v", dnsCtx.QuestionMessage, msg)
	}
}

func TestExchange_Error_ReusesExistingDnsContext(t *testing.T) {
	existing := &dnsUtilsTypes.DnsContext{}
	ctx := dnsUtilsContext.WithDnsContextValue(context.Background(), existing)

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn("example.com"), dns.TypeA)

	_, err := Exchange(ctx, msg, "", nil, nil)
	dnsCtx := extractDnsContext(t, err)

	if dnsCtx != existing {
		t.Errorf("DnsContext is not the caller-supplied instance")
	}
	if existing.QuestionMessage != msg {
		t.Errorf("caller DnsContext.QuestionMessage not populated")
	}
}
