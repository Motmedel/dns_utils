package dns_utils

import (
	"context"
	"errors"
	"net"
	"reflect"
	"testing"
	"time"

	dnsUtilsContext "github.com/Motmedel/dns_utils/pkg/context"
	dnsUtilsErrors "github.com/Motmedel/dns_utils/pkg/errors"
	dnsUtilsTypes "github.com/Motmedel/dns_utils/pkg/types"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"github.com/Motmedel/utils_go/pkg/errors/types/empty_error"
	"github.com/Motmedel/utils_go/pkg/errors/types/nil_error"
	"github.com/miekg/dns"
)

func TestGetFlagsFromMessage_Nil(t *testing.T) {
	if got := GetFlagsFromMessage(nil); got != nil {
		t.Errorf("GetFlagsFromMessage(nil) = %v, want nil", got)
	}
}

func TestGetFlagsFromMessage_AllSet(t *testing.T) {
	msg := &dns.Msg{}
	msg.Authoritative = true
	msg.AuthenticatedData = true
	msg.CheckingDisabled = true
	msg.RecursionAvailable = true
	msg.RecursionDesired = true
	msg.Truncated = true

	opt := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
	opt.SetDo()
	msg.Extra = append(msg.Extra, opt)

	got := GetFlagsFromMessage(msg)
	want := []string{"AA", "AD", "CD", "DO", "RA", "RD", "TC"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("GetFlagsFromMessage() = %v, want %v", got, want)
	}
}

func TestGetFlagsFromMessage_NoFlags(t *testing.T) {
	msg := &dns.Msg{}
	if got := GetFlagsFromMessage(msg); got != nil {
		t.Errorf("GetFlagsFromMessage(empty) = %v, want nil", got)
	}
}

func TestGetFlagsFromMessage_OptWithoutDO(t *testing.T) {
	msg := &dns.Msg{}
	msg.RecursionDesired = true
	opt := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
	msg.Extra = append(msg.Extra, opt)

	got := GetFlagsFromMessage(msg)
	want := []string{"RD"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("GetFlagsFromMessage() = %v, want %v", got, want)
	}
}

func makeA(ttl uint32, ip string) *dns.A {
	return &dns.A{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
		A:   net.ParseIP(ip),
	}
}

func TestApplyRemainingTtl_Nil(t *testing.T) {
	// Should not panic
	ApplyRemainingTtl(nil, 42)
}

func TestApplyRemainingTtl_RewritesAllSections(t *testing.T) {
	msg := &dns.Msg{
		Answer: []dns.RR{makeA(100, "1.2.3.4"), nil, makeA(200, "5.6.7.8")},
		Ns:     []dns.RR{makeA(300, "9.9.9.9")},
		Extra:  []dns.RR{makeA(400, "8.8.8.8")},
	}
	ApplyRemainingTtl(msg, 7)

	for _, rr := range msg.Answer {
		if rr == nil {
			continue
		}
		if rr.Header().Ttl != 7 {
			t.Errorf("Answer TTL = %d, want 7", rr.Header().Ttl)
		}
	}
	if msg.Ns[0].Header().Ttl != 7 {
		t.Errorf("Ns TTL = %d, want 7", msg.Ns[0].Header().Ttl)
	}
	if msg.Extra[0].Header().Ttl != 7 {
		t.Errorf("Extra TTL = %d, want 7", msg.Extra[0].Header().Ttl)
	}
}

func TestApplyRemainingTtl_PreservesOptEdnsFlags(t *testing.T) {
	// The OPT pseudo-record's "Ttl" field encodes
	// (extended-rcode, version, DO, Z) per RFC 6891. Rewriting it would
	// strip the DO bit and corrupt the MBZ field, breaking DNSSEC
	// validation downstream.
	opt := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT, Class: 4096}}
	opt.SetDo()
	originalTtl := opt.Hdr.Ttl

	msg := &dns.Msg{
		Answer: []dns.RR{makeA(100, "1.2.3.4")},
		Extra:  []dns.RR{opt},
	}
	ApplyRemainingTtl(msg, 7)

	if msg.Answer[0].Header().Ttl != 7 {
		t.Errorf("Answer TTL = %d, want 7", msg.Answer[0].Header().Ttl)
	}
	if opt.Hdr.Ttl != originalTtl {
		t.Errorf("OPT TTL = 0x%x, want 0x%x (unchanged)", opt.Hdr.Ttl, originalTtl)
	}
	if !opt.Do() {
		t.Errorf("OPT DO bit was cleared")
	}
}

func TestEffectiveMessageTtl_Nil(t *testing.T) {
	if got := EffectiveMessageTtl(nil); got != 0 {
		t.Errorf("EffectiveMessageTtl(nil) = %v, want 0", got)
	}
}

func TestEffectiveMessageTtl_MinAcrossSections(t *testing.T) {
	msg := &dns.Msg{
		Answer: []dns.RR{makeA(300, "1.1.1.1"), makeA(60, "2.2.2.2")},
		Ns:     []dns.RR{makeA(120, "3.3.3.3")},
		Extra:  []dns.RR{makeA(900, "4.4.4.4")},
	}
	got := EffectiveMessageTtl(msg)
	if got != 60*time.Second {
		t.Errorf("EffectiveMessageTtl = %v, want %v", got, 60*time.Second)
	}
}

func TestEffectiveMessageTtl_IgnoresOpt(t *testing.T) {
	opt := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT, Ttl: 0}}
	msg := &dns.Msg{
		Answer: []dns.RR{makeA(150, "1.1.1.1")},
		Extra:  []dns.RR{opt},
	}
	got := EffectiveMessageTtl(msg)
	if got != 150*time.Second {
		t.Errorf("EffectiveMessageTtl = %v, want %v", got, 150*time.Second)
	}
}

func TestEffectiveMessageTtl_NXDOMAINUsesSoaMinttl(t *testing.T) {
	soa := &dns.SOA{
		Hdr:    dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
		Minttl: 30,
	}
	msg := &dns.Msg{
		MsgHdr: dns.MsgHdr{Rcode: dns.RcodeNameError},
		Ns:     []dns.RR{soa},
	}
	got := EffectiveMessageTtl(msg)
	if got != 30*time.Second {
		t.Errorf("EffectiveMessageTtl = %v, want %v", got, 30*time.Second)
	}
}

func TestGetAnswerString(t *testing.T) {
	tests := []struct {
		name string
		rr   dns.RR
		want string
	}{
		{
			name: "A",
			rr:   &dns.A{A: net.ParseIP("1.2.3.4")},
			want: "1.2.3.4",
		},
		{
			name: "AAAA",
			rr:   &dns.AAAA{AAAA: net.ParseIP("::1")},
			want: "::1",
		},
		{
			name: "MX",
			rr:   &dns.MX{Mx: "mail.example.com."},
			want: "mail.example.com.",
		},
		{
			name: "NS",
			rr:   &dns.NS{Ns: "ns1.example.com."},
			want: "ns1.example.com.",
		},
		{
			name: "TXT",
			rr:   &dns.TXT{Txt: []string{"hello", "world"}},
			want: "helloworld",
		},
		{
			name: "CNAME",
			rr:   &dns.CNAME{Target: "alias.example.com."},
			want: "alias.example.com.",
		},
		{
			name: "Unknown",
			rr:   &dns.SOA{},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetAnswerString(tt.rr); got != tt.want {
				t.Errorf("GetAnswerString = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGetAnswerString_NilA(t *testing.T) {
	if got := GetAnswerString(&dns.A{}); got != "" {
		t.Errorf("GetAnswerString(&dns.A{}) = %q, want empty", got)
	}
	if got := GetAnswerString(&dns.AAAA{}); got != "" {
		t.Errorf("GetAnswerString(&dns.AAAA{}) = %q, want empty", got)
	}
}

// Validation error helpers

func assertNilField(t *testing.T, err error, field string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected nil_error, got nil")
	}
	var ne *nil_error.Error
	if !errors.As(err, &ne) {
		t.Fatalf("expected *nil_error.Error, got %T (%v)", err, err)
	}
	if ne.Field != field {
		t.Errorf("nil_error.Field = %q, want %q", ne.Field, field)
	}
}

func assertEmptyField(t *testing.T, err error, field string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected empty_error, got nil")
	}
	var ee *empty_error.Error
	if !errors.As(err, &ee) {
		t.Fatalf("expected *empty_error.Error, got %T (%v)", err, err)
	}
	if ee.Field != field {
		t.Errorf("empty_error.Field = %q, want %q", ee.Field, field)
	}
}

// extractDnsContext walks the error chain for an *ExtendedError with a
// *DnsContext stored in its attached context.
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
	got, err := Exchange(context.Background(), nil, &dns.Client{}, "1.2.3.4:53")
	if err != nil {
		t.Errorf("err = %v, want nil", err)
	}
	if got != nil {
		t.Errorf("got = %v, want nil", got)
	}
}

func TestExchange_NilClient(t *testing.T) {
	_, err := Exchange(context.Background(), &dns.Msg{}, nil, "1.2.3.4:53")
	assertNilField(t, err, "dns client")
}

func TestExchange_EmptyServer(t *testing.T) {
	_, err := Exchange(context.Background(), &dns.Msg{}, &dns.Client{}, "")
	assertEmptyField(t, err, "dns server")
}

func TestExchangeWithConn_NilMessage(t *testing.T) {
	got, err := ExchangeWithConn(context.Background(), nil, &dns.Client{}, &dns.Conn{})
	if err != nil {
		t.Errorf("err = %v, want nil", err)
	}
	if got != nil {
		t.Errorf("got = %v, want nil", got)
	}
}

func TestExchangeWithConn_NilClient(t *testing.T) {
	_, err := ExchangeWithConn(context.Background(), &dns.Msg{}, nil, &dns.Conn{})
	assertNilField(t, err, "dns client")
}

func TestExchangeWithConn_NilConnection(t *testing.T) {
	_, err := ExchangeWithConn(context.Background(), &dns.Msg{}, &dns.Client{}, nil)
	assertNilField(t, err, "connection")
}

func TestGetDnsAnswersWithMessage_NilMessage(t *testing.T) {
	got, err := GetDnsAnswersWithMessage(context.Background(), nil, &dns.Client{}, "1.2.3.4:53")
	if err != nil {
		t.Errorf("err = %v, want nil", err)
	}
	if got != nil {
		t.Errorf("got = %v, want nil", got)
	}
}

func TestGetDnsAnswersWithMessage_NilClient(t *testing.T) {
	_, err := GetDnsAnswersWithMessage(context.Background(), &dns.Msg{}, nil, "1.2.3.4:53")
	assertNilField(t, err, "dns client")
}

func TestGetDnsAnswersWithMessage_EmptyServer(t *testing.T) {
	_, err := GetDnsAnswersWithMessage(context.Background(), &dns.Msg{}, &dns.Client{}, "")
	assertEmptyField(t, err, "dns server")
}

func TestGetDnsAnswers_EmptyDomain(t *testing.T) {
	got, err := GetDnsAnswers(context.Background(), "", dns.TypeA, &dns.Client{}, "1.2.3.4:53")
	if err != nil {
		t.Errorf("err = %v, want nil", err)
	}
	if got != nil {
		t.Errorf("got = %v, want nil", got)
	}
}

func TestGetDnsAnswers_UnsetRecordType(t *testing.T) {
	_, err := GetDnsAnswers(context.Background(), "example.com", 0, &dns.Client{}, "1.2.3.4:53")
	if !errors.Is(err, dnsUtilsErrors.ErrUnsetRecordType) {
		t.Errorf("err = %v, want ErrUnsetRecordType", err)
	}
}

func TestGetDnsAnswers_NilClient(t *testing.T) {
	_, err := GetDnsAnswers(context.Background(), "example.com", dns.TypeA, nil, "1.2.3.4:53")
	assertNilField(t, err, "dns client")
}

func TestGetDnsAnswers_EmptyServer(t *testing.T) {
	_, err := GetDnsAnswers(context.Background(), "example.com", dns.TypeA, &dns.Client{}, "")
	assertEmptyField(t, err, "dns server")
}

func TestGetDnsAnswerStrings_EmptyDomain(t *testing.T) {
	got, err := GetDnsAnswerStrings(context.Background(), "", dns.TypeA, &dns.Client{}, "1.2.3.4:53")
	if err != nil {
		t.Errorf("err = %v, want nil", err)
	}
	if got != nil {
		t.Errorf("got = %v, want nil", got)
	}
}

func TestGetDnsAnswerStrings_UnsetRecordType(t *testing.T) {
	_, err := GetDnsAnswerStrings(context.Background(), "example.com", 0, &dns.Client{}, "1.2.3.4:53")
	if !errors.Is(err, dnsUtilsErrors.ErrUnsetRecordType) {
		t.Errorf("err = %v, want ErrUnsetRecordType", err)
	}
}

func TestGetDnsAnswerStrings_NilClient(t *testing.T) {
	_, err := GetDnsAnswerStrings(context.Background(), "example.com", dns.TypeA, nil, "1.2.3.4:53")
	assertNilField(t, err, "dns client")
}

func TestGetDnsAnswerStrings_EmptyServer(t *testing.T) {
	_, err := GetDnsAnswerStrings(context.Background(), "example.com", dns.TypeA, &dns.Client{}, "")
	assertEmptyField(t, err, "dns server")
}

func TestGetPrefixedTxtRecordStrings_EmptyDomain(t *testing.T) {
	got, err := GetPrefixedTxtRecordStrings(context.Background(), "", "v=", &dns.Client{}, "1.2.3.4:53")
	if err != nil {
		t.Errorf("err = %v, want nil", err)
	}
	if got != nil {
		t.Errorf("got = %v, want nil", got)
	}
}

func TestGetPrefixedTxtRecordStrings_NilClient(t *testing.T) {
	_, err := GetPrefixedTxtRecordStrings(context.Background(), "example.com", "v=", nil, "1.2.3.4:53")
	assertNilField(t, err, "dns client")
}

func TestGetPrefixedTxtRecordStrings_EmptyServer(t *testing.T) {
	_, err := GetPrefixedTxtRecordStrings(context.Background(), "example.com", "v=", &dns.Client{}, "")
	assertEmptyField(t, err, "dns server")
}

func TestDomainExists_EmptyDomain(t *testing.T) {
	ok, err := DomainExists(context.Background(), "", &dns.Client{}, "1.2.3.4:53")
	if err != nil {
		t.Errorf("err = %v, want nil", err)
	}
	if ok {
		t.Errorf("ok = true, want false")
	}
}

func TestDomainExists_NilClient(t *testing.T) {
	_, err := DomainExists(context.Background(), "example.com", nil, "1.2.3.4:53")
	assertNilField(t, err, "dns client")
}

func TestDomainExists_EmptyServer(t *testing.T) {
	_, err := DomainExists(context.Background(), "example.com", &dns.Client{}, "")
	assertEmptyField(t, err, "dns server")
}

func TestSupportsDnssec_EmptyDomain(t *testing.T) {
	ok, err := SupportsDnssec(context.Background(), "", &dns.Client{}, "1.2.3.4:53")
	if err != nil {
		t.Errorf("err = %v, want nil", err)
	}
	if ok {
		t.Errorf("ok = true, want false")
	}
}

func TestSupportsDnssec_NilClient(t *testing.T) {
	_, err := SupportsDnssec(context.Background(), "example.com", nil, "1.2.3.4:53")
	assertNilField(t, err, "dns client")
}

func TestSupportsDnssec_EmptyServer(t *testing.T) {
	_, err := SupportsDnssec(context.Background(), "example.com", &dns.Client{}, "")
	assertEmptyField(t, err, "dns server")
}

// The tests below verify the "error with context" pattern: errors returned from
// the exported functions should carry a DnsContext that has been populated with
// whatever information was available at failure time.

func TestExchange_Error_AttachesDnsContextWithQuestion(t *testing.T) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn("example.com"), dns.TypeA)

	_, err := Exchange(context.Background(), msg, nil, "1.2.3.4:53")
	dnsCtx := extractDnsContext(t, err)

	if dnsCtx.QuestionMessage != msg {
		t.Errorf("DnsContext.QuestionMessage = %v, want %v", dnsCtx.QuestionMessage, msg)
	}
	if dnsCtx.ServerAddress != "1.2.3.4:53" {
		t.Errorf("DnsContext.ServerAddress = %q, want %q", dnsCtx.ServerAddress, "1.2.3.4:53")
	}
}

func TestExchange_Error_ReusesExistingDnsContext(t *testing.T) {
	existing := &dnsUtilsTypes.DnsContext{}
	ctx := dnsUtilsContext.WithDnsContextValue(context.Background(), existing)

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn("example.com"), dns.TypeA)

	_, err := Exchange(ctx, msg, &dns.Client{}, "")
	dnsCtx := extractDnsContext(t, err)

	if dnsCtx != existing {
		t.Errorf("DnsContext is not the caller-supplied instance")
	}
	if existing.QuestionMessage != msg {
		t.Errorf("caller DnsContext.QuestionMessage not populated")
	}
}

func TestExchangeWithConn_Error_AttachesDnsContext(t *testing.T) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn("example.com"), dns.TypeA)

	_, err := ExchangeWithConn(context.Background(), msg, nil, &dns.Conn{})
	dnsCtx := extractDnsContext(t, err)

	if dnsCtx.QuestionMessage != msg {
		t.Errorf("DnsContext.QuestionMessage not set on error")
	}
}

func TestGetDnsAnswersWithMessage_Error_AttachesDnsContext(t *testing.T) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn("example.com"), dns.TypeA)

	_, err := GetDnsAnswersWithMessage(context.Background(), msg, nil, "1.2.3.4:53")
	dnsCtx := extractDnsContext(t, err)

	if dnsCtx.QuestionMessage != msg {
		t.Errorf("DnsContext.QuestionMessage not set on error")
	}
	if dnsCtx.ServerAddress != "1.2.3.4:53" {
		t.Errorf("DnsContext.ServerAddress = %q, want %q", dnsCtx.ServerAddress, "1.2.3.4:53")
	}
}

func TestGetDnsAnswers_Error_AttachesDnsContext(t *testing.T) {
	_, err := GetDnsAnswers(context.Background(), "example.com", dns.TypeA, nil, "1.2.3.4:53")
	dnsCtx := extractDnsContext(t, err)

	if dnsCtx.ServerAddress != "1.2.3.4:53" {
		t.Errorf("DnsContext.ServerAddress = %q, want %q", dnsCtx.ServerAddress, "1.2.3.4:53")
	}
}

func TestGetDnsAnswers_UnsetRecordType_AttachesDnsContext(t *testing.T) {
	_, err := GetDnsAnswers(context.Background(), "example.com", 0, &dns.Client{}, "1.2.3.4:53")
	if !errors.Is(err, dnsUtilsErrors.ErrUnsetRecordType) {
		t.Fatalf("err = %v, want ErrUnsetRecordType", err)
	}
	dnsCtx := extractDnsContext(t, err)
	if dnsCtx.ServerAddress != "1.2.3.4:53" {
		t.Errorf("DnsContext.ServerAddress = %q, want %q", dnsCtx.ServerAddress, "1.2.3.4:53")
	}
}

func TestGetDnsAnswerStrings_Error_AttachesDnsContext(t *testing.T) {
	_, err := GetDnsAnswerStrings(context.Background(), "example.com", dns.TypeA, nil, "1.2.3.4:53")
	dnsCtx := extractDnsContext(t, err)

	if dnsCtx.ServerAddress != "1.2.3.4:53" {
		t.Errorf("DnsContext.ServerAddress = %q, want %q", dnsCtx.ServerAddress, "1.2.3.4:53")
	}
}

func TestGetPrefixedTxtRecordStrings_Error_AttachesDnsContext(t *testing.T) {
	_, err := GetPrefixedTxtRecordStrings(context.Background(), "example.com", "v=", nil, "1.2.3.4:53")
	dnsCtx := extractDnsContext(t, err)

	if dnsCtx.ServerAddress != "1.2.3.4:53" {
		t.Errorf("DnsContext.ServerAddress = %q, want %q", dnsCtx.ServerAddress, "1.2.3.4:53")
	}
}

func TestDomainExists_Error_AttachesDnsContext(t *testing.T) {
	_, err := DomainExists(context.Background(), "example.com", nil, "1.2.3.4:53")
	dnsCtx := extractDnsContext(t, err)

	if dnsCtx.ServerAddress != "1.2.3.4:53" {
		t.Errorf("DnsContext.ServerAddress = %q, want %q", dnsCtx.ServerAddress, "1.2.3.4:53")
	}
}

func TestSupportsDnssec_Error_AttachesDnsContext(t *testing.T) {
	_, err := SupportsDnssec(context.Background(), "example.com", nil, "1.2.3.4:53")
	dnsCtx := extractDnsContext(t, err)

	if dnsCtx.ServerAddress != "1.2.3.4:53" {
		t.Errorf("DnsContext.ServerAddress = %q, want %q", dnsCtx.ServerAddress, "1.2.3.4:53")
	}
}
