package client

import (
	"context"
	"errors"
	"testing"

	dnsUtilsErrors "github.com/Motmedel/dns_utils/pkg/errors"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
	"github.com/miekg/dns"
)

// spfTxtHandler answers TXT queries by FQDN name.
func spfTxtHandler(records map[string][]string) dns.HandlerFunc {
	return func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		for _, q := range r.Question {
			entries, ok := records[q.Name]
			if !ok {
				m.Rcode = dns.RcodeNameError
				continue
			}
			if q.Qtype != dns.TypeTXT {
				continue
			}
			for _, entry := range entries {
				m.Answer = append(m.Answer, &dns.TXT{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
					Txt: []string{entry},
				})
			}
		}
		_ = w.WriteMsg(m)
	}
}

func TestGetSpfRecordString_CancelledContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	got, err := DefaultClient.GetSpfRecordString(ctx, "example.com")
	if got != "" {
		t.Fatalf("got %q want empty", got)
	}
	if err != context.Canceled {
		t.Fatalf("err: got %v want context.Canceled", err)
	}
}

func TestGetSpfRecordString_NilClient(t *testing.T) {
	t.Parallel()

	var c *Client
	got, err := c.GetSpfRecordString(context.Background(), "example.com")
	if got != "" {
		t.Fatalf("got %q want empty", got)
	}
	if err == nil {
		t.Fatal("expected error for nil client")
	}
}

func TestGetSpfRecordString_EmptyDomain(t *testing.T) {
	t.Parallel()

	got, err := DefaultClient.GetSpfRecordString(context.Background(), "")
	if got != "" {
		t.Fatalf("got %q want empty", got)
	}
	if err != nil {
		t.Fatalf("err: got %v want nil", err)
	}
}

func TestGetSpfRecord_CancelledContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	record, err := DefaultClient.GetSpfRecord(ctx, "example.com")
	if record != nil {
		t.Fatalf("record: got %v want nil", record)
	}
	if err != context.Canceled {
		t.Fatalf("err: got %v want context.Canceled", err)
	}
}

func TestGetSpfRecord_NilClient(t *testing.T) {
	t.Parallel()

	var c *Client
	record, err := c.GetSpfRecord(context.Background(), "example.com")
	if record != nil {
		t.Fatalf("record: got %v want nil", record)
	}
	if err == nil {
		t.Fatal("expected error for nil client")
	}
}

func TestGetSpfRecord_EmptyDomain(t *testing.T) {
	t.Parallel()

	record, err := DefaultClient.GetSpfRecord(context.Background(), "")
	if record != nil {
		t.Fatalf("record: got %v want nil", record)
	}
	if err != nil {
		t.Fatalf("err: got %v want nil", err)
	}
}

func TestGetSpfRecordString_SingleRecord(t *testing.T) {
	t.Parallel()

	client, teardown := startTestDnsServer(t, spfTxtHandler(map[string][]string{
		"example.com.": {"v=spf1 -all"},
	}))
	defer teardown()

	got, err := client.GetSpfRecordString(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != "v=spf1 -all" {
		t.Fatalf("got %q", got)
	}
}

func TestGetSpfRecordString_NXDomainReturnsEmpty(t *testing.T) {
	t.Parallel()

	client, teardown := startTestDnsServer(t, spfTxtHandler(map[string][]string{}))
	defer teardown()

	got, err := client.GetSpfRecordString(context.Background(), "missing.example")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != "" {
		t.Fatalf("got %q want empty", got)
	}
}

func TestGetSpfRecordString_MultipleRecordsError(t *testing.T) {
	t.Parallel()

	client, teardown := startTestDnsServer(t, spfTxtHandler(map[string][]string{
		"example.com.": {"v=spf1 -all", "v=spf1 ~all"},
	}))
	defer teardown()

	got, err := client.GetSpfRecordString(context.Background(), "example.com")
	if got != "" {
		t.Fatalf("got %q want empty on multiple-records error", got)
	}
	if !errors.Is(err, dnsUtilsErrors.ErrMultipleRecords) {
		t.Fatalf("err: got %v want ErrMultipleRecords", err)
	}
}

func TestGetSpfRecord_ParsedSuccessfully(t *testing.T) {
	t.Parallel()

	client, teardown := startTestDnsServer(t, spfTxtHandler(map[string][]string{
		"example.com.": {"v=spf1 -all"},
	}))
	defer teardown()

	record, err := client.GetSpfRecord(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if record == nil || record.Domain != "example.com" {
		t.Fatalf("record: got %+v", record)
	}
	if record.Raw != "v=spf1 -all" {
		t.Fatalf("raw: got %q", record.Raw)
	}
	if len(record.Terms) != 1 {
		t.Fatalf("terms length: got %d want 1", len(record.Terms))
	}
}

func TestGetSpfRecord_ParseFailureReturnsRawAndError(t *testing.T) {
	t.Parallel()

	client, teardown := startTestDnsServer(t, spfTxtHandler(map[string][]string{
		"example.com.": {"v=spf1 garbage~~"},
	}))
	defer teardown()

	record, err := client.GetSpfRecord(context.Background(), "example.com")
	if err == nil {
		t.Fatal("expected parse error")
	}
	if !motmedelErrors.IsAny(err, motmedelErrors.ErrSyntaxError, motmedelErrors.ErrSemanticError) {
		t.Fatalf("err: got %v want syntax or semantic", err)
	}
	if record == nil {
		t.Fatal("record should be non-nil with raw set")
	}
	if record.Raw != "v=spf1 garbage~~" {
		t.Fatalf("raw: got %q", record.Raw)
	}
}

func TestGetSpfRecord_NoSpfReturnsNil(t *testing.T) {
	t.Parallel()

	client, teardown := startTestDnsServer(t, spfTxtHandler(map[string][]string{}))
	defer teardown()

	record, err := client.GetSpfRecord(context.Background(), "missing.example")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if record != nil {
		t.Fatalf("record: got %+v want nil", record)
	}
}
