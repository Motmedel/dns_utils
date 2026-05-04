package client

import (
	"context"
	"errors"
	"testing"

	dnsUtilsErrors "github.com/Motmedel/dns_utils/pkg/errors"
	"github.com/miekg/dns"
)

// dmarcTxtHandler returns a handler that answers TXT queries by name. The
// records map's keys are FQDN names (e.g. "_dmarc.example.com.").
func dmarcTxtHandler(records map[string][][]string) dns.HandlerFunc {
	return func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if r.Question[0].Qtype == dns.TypeTXT {
			name := r.Question[0].Name
			for _, rec := range records[name] {
				rr := &dns.TXT{
					Hdr: dns.RR_Header{
						Name:   name,
						Rrtype: dns.TypeTXT,
						Class:  dns.ClassINET,
						Ttl:    60,
					},
					Txt: rec,
				}
				m.Answer = append(m.Answer, rr)
			}
		}
		_ = w.WriteMsg(m)
	}
}

func TestGetDmarcRecordStringWithSubdomain_EmptySubdomain(t *testing.T) {
	t.Parallel()
	got, err := DefaultClient.GetDmarcRecordStringWithSubdomain(context.Background(), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "" {
		t.Fatalf("expected empty string, got %q", got)
	}
}

func TestGetDmarcRecordStringWithSubdomain_NilClient(t *testing.T) {
	t.Parallel()
	var c *Client
	_, err := c.GetDmarcRecordStringWithSubdomain(context.Background(), "_dmarc.example.com")
	if err == nil {
		t.Fatal("expected error for nil client")
	}
}

func TestGetDmarcRecordStringWithSubdomain_HappyPath(t *testing.T) {
	t.Parallel()

	client, teardown := startTestDnsServer(t, dmarcTxtHandler(map[string][][]string{
		"_dmarc.example.com.": {{"v=DMARC1; p=reject"}},
	}))
	defer teardown()

	got, err := client.GetDmarcRecordStringWithSubdomain(context.Background(), "_dmarc.example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "v=DMARC1; p=reject" {
		t.Errorf("got %q", got)
	}
}

func TestGetDmarcRecordStringWithSubdomain_MultipleRecords(t *testing.T) {
	t.Parallel()

	client, teardown := startTestDnsServer(t, dmarcTxtHandler(map[string][][]string{
		"_dmarc.example.com.": {{"v=DMARC1; p=reject"}, {"v=DMARC1; p=none"}},
	}))
	defer teardown()

	_, err := client.GetDmarcRecordStringWithSubdomain(context.Background(), "_dmarc.example.com")
	var multi *dnsUtilsErrors.MultipleRecordsError
	if !errors.As(err, &multi) {
		t.Fatalf("expected MultipleRecordsError, got %v", err)
	}
}

func TestGetDmarcRecordStringWithSubdomain_NxDomainIsNotAnError(t *testing.T) {
	t.Parallel()

	client, teardown := startTestDnsServer(t, nxdomainHandler())
	defer teardown()

	got, err := client.GetDmarcRecordStringWithSubdomain(context.Background(), "_dmarc.example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "" {
		t.Errorf("expected empty string for NXDOMAIN, got %q", got)
	}
}

func TestGetDmarcRecordStringWithSubdomain_OtherRcodePropagated(t *testing.T) {
	t.Parallel()

	client, teardown := startTestDnsServer(t, servfailHandler())
	defer teardown()

	_, err := client.GetDmarcRecordStringWithSubdomain(context.Background(), "_dmarc.example.com")
	if err == nil {
		t.Fatal("expected propagated error")
	}
	var rcode *dnsUtilsErrors.RcodeError
	if !errors.As(err, &rcode) {
		t.Errorf("expected rcode err in chain, got %v", err)
	}
}

func TestGetDmarcRecord_NilClient(t *testing.T) {
	t.Parallel()
	var c *Client
	_, err := c.GetDmarcRecord(context.Background(), "example.com")
	if err == nil {
		t.Fatal("expected error for nil client")
	}
}

func TestGetDmarcRecord_EmptyDomain(t *testing.T) {
	t.Parallel()
	rec, err := DefaultClient.GetDmarcRecord(context.Background(), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rec != nil {
		t.Fatalf("expected nil record, got %v", rec)
	}
}

func TestGetDmarcRecord_CanceledContext(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := DefaultClient.GetDmarcRecord(ctx, "example.com")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestGetDmarcRecordWithSubdomain_NilClient(t *testing.T) {
	t.Parallel()
	var c *Client
	_, err := c.GetDmarcRecordWithSubdomain(context.Background(), "_dmarc.example.com")
	if err == nil {
		t.Fatal("expected error for nil client")
	}
}

func TestGetDmarcRecordWithSubdomain_EmptySubdomain(t *testing.T) {
	t.Parallel()
	rec, err := DefaultClient.GetDmarcRecordWithSubdomain(context.Background(), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rec != nil {
		t.Fatalf("expected nil record, got %v", rec)
	}
}

func TestGetDmarcRecordWithSubdomain_CanceledContext(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := DefaultClient.GetDmarcRecordWithSubdomain(ctx, "_dmarc.example.com")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestGetDmarcRecordWithSubdomain_HappyPath(t *testing.T) {
	t.Parallel()

	client, teardown := startTestDnsServer(t, dmarcTxtHandler(map[string][][]string{
		"_dmarc.example.com.": {{"v=DMARC1; p=reject"}},
	}))
	defer teardown()

	got, err := client.GetDmarcRecordWithSubdomain(context.Background(), "_dmarc.example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil || got.P != "reject" || got.Raw != "v=DMARC1; p=reject" {
		t.Errorf("unexpected record: %#v", got)
	}
}

func TestGetDmarcRecordWithSubdomain_ParseErrorReturnsRawAndError(t *testing.T) {
	t.Parallel()

	client, teardown := startTestDnsServer(t, dmarcTxtHandler(map[string][][]string{
		"_dmarc.example.com.": {{"v=DMARC1; bogus=value"}},
	}))
	defer teardown()

	got, err := client.GetDmarcRecordWithSubdomain(context.Background(), "_dmarc.example.com")
	if err == nil {
		t.Fatal("expected parse error")
	}
	if got == nil || got.Raw != "v=DMARC1; bogus=value" {
		t.Errorf("expected raw to be preserved, got %#v", got)
	}
}

func TestGetDmarcRecordWithSubdomain_NoRecordReturnsNilNil(t *testing.T) {
	t.Parallel()

	client, teardown := startTestDnsServer(t, nxdomainHandler())
	defer teardown()

	got, err := client.GetDmarcRecordWithSubdomain(context.Background(), "_dmarc.example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil record, got %#v", got)
	}
}

func TestGetDmarcRecord_LowercasesDomainAndPopulatesRecord(t *testing.T) {
	t.Parallel()

	client, teardown := startTestDnsServer(t, dmarcTxtHandler(map[string][][]string{
		"_dmarc.example.com.": {{"v=DMARC1; p=reject"}},
	}))
	defer teardown()

	got, err := client.GetDmarcRecord(context.Background(), "Example.COM")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("expected record")
	}
	if got.Domain != "example.com" {
		t.Errorf("Domain not lowercased: %q", got.Domain)
	}
}

func TestGetDmarcRecord_PreservesDomainOnParseError(t *testing.T) {
	t.Parallel()

	client, teardown := startTestDnsServer(t, dmarcTxtHandler(map[string][][]string{
		"_dmarc.example.com.": {{"v=DMARC1; bogus=value"}},
	}))
	defer teardown()

	got, err := client.GetDmarcRecord(context.Background(), "Example.com")
	if err == nil {
		t.Fatal("expected error")
	}
	if got == nil || got.Domain != "example.com" {
		t.Errorf("expected lowercased domain on errored record, got %#v", got)
	}
}
