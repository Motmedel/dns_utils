package client

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	dnsUtilsErrors "github.com/Motmedel/dns_utils/pkg/errors"
	"github.com/Motmedel/dns_utils/pkg/types/client/config"
	"github.com/Motmedel/utils_go/pkg/errors/types/nil_error"
	"github.com/miekg/dns"
)

func TestCommonDkimSelectors(t *testing.T) {
	t.Parallel()

	var selectors []string
	for selector, err := range CommonDkimSelectors() {
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		selectors = append(selectors, selector)
	}

	if len(selectors) == 0 {
		t.Fatal("expected non-empty selector list")
	}

	wantContains := []string{"selector1", "google", "default"}
	for _, want := range wantContains {
		found := false
		for _, s := range selectors {
			if s == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected selector %q to be present", want)
		}
	}

	for _, s := range selectors {
		if s == "" {
			t.Error("did not expect empty selector entries")
		}
	}
}

func TestCommonDkimSelectorsEarlyStop(t *testing.T) {
	t.Parallel()

	count := 0
	for _, err := range CommonDkimSelectors() {
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		count++
		if count == 3 {
			break
		}
	}

	if count != 3 {
		t.Fatalf("expected to stop at 3 iterations, got %d", count)
	}
}

func expectNilDnsClientError(t *testing.T, err error) {
	t.Helper()
	ne, ok := errors.AsType[*nil_error.Error](err)
	if !ok {
		t.Fatalf("err type = %T (%v), want *nil_error.Error", err, err)
	}
	if ne.Field != "dns client" {
		t.Errorf("Field = %q, want %q", ne.Field, "dns client")
	}
}

// startTestDnsServer starts a local UDP DNS server that dispatches queries to
// the supplied handler. It returns a client pointing at the server and a
// teardown function. The server address is bound to a random local port.
func startTestDnsServer(t *testing.T, handler dns.HandlerFunc) (*Client, func()) {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen packet: %v", err)
	}

	server := &dns.Server{
		PacketConn: pc,
		Handler:    handler,
	}

	started := make(chan struct{})
	server.NotifyStartedFunc = func() { close(started) }

	errCh := make(chan error, 1)
	go func() { errCh <- server.ActivateAndServe() }()

	select {
	case <-started:
	case err := <-errCh:
		t.Fatalf("server start: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("dns server did not start in time")
	}

	client := New(
		config.WithDnsClient(&dns.Client{UDPSize: 4096, Timeout: 2 * time.Second}),
		config.WithAddress(pc.LocalAddr().String()),
	)

	teardown := func() {
		_ = server.Shutdown()
		<-errCh
	}

	return client, teardown
}

// txtHandler builds a handler that returns the supplied TXT records (one RR
// per outer slice element) for any TXT query.
func txtHandler(records [][]string) dns.HandlerFunc {
	return func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if r.Question[0].Qtype == dns.TypeTXT {
			for _, rec := range records {
				rr := &dns.TXT{
					Hdr: dns.RR_Header{
						Name:   r.Question[0].Name,
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

func nxdomainHandler() dns.HandlerFunc {
	return func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeNameError
		_ = w.WriteMsg(m)
	}
}

func servfailHandler() dns.HandlerFunc {
	return func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeServerFailure
		_ = w.WriteMsg(m)
	}
}

const validDkimRecordString = "v=DKIM1; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDDmzRmJRQxLEuyYiyMg4suA2SyMwR5MGHpP9diNT1hRiwUd/mZp1ro7kIDTKS8ttkI6z6eTRW9e9dDOxzSxNuXmume60Cjbu08gOyhPG3GfWdg7QkdN6kR4V75MFlw624VY35DaXBvnlTJTgRg/EW72O1DiYVThkyCgpSYS8nmEQIDAQAB"

func TestGetDkimRecordStringWithDomainName(t *testing.T) {
	t.Parallel()

	t.Run("nil dns client", func(t *testing.T) {
		t.Parallel()
		var c *Client
		got, err := c.GetDkimRecordStringWithDomainName(context.Background(), "example.com")
		if got != "" {
			t.Errorf("got = %q, want empty", got)
		}
		expectNilDnsClientError(t, err)
	})

	t.Run("cancelled context", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		got, err := DefaultClient.GetDkimRecordStringWithDomainName(ctx, "example.com")
		if got != "" {
			t.Errorf("got = %q, want empty", got)
		}
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
	})

	t.Run("empty domain", func(t *testing.T) {
		t.Parallel()
		got, err := DefaultClient.GetDkimRecordStringWithDomainName(context.Background(), "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "" {
			t.Errorf("got = %q, want empty", got)
		}
	})

	t.Run("single record", func(t *testing.T) {
		t.Parallel()
		client, teardown := startTestDnsServer(t, txtHandler([][]string{{validDkimRecordString}}))
		defer teardown()

		got, err := client.GetDkimRecordStringWithDomainName(context.Background(), "example.com")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != validDkimRecordString {
			t.Errorf("got = %q, want %q", got, validDkimRecordString)
		}
	})

	t.Run("split TXT chunks join", func(t *testing.T) {
		t.Parallel()
		client, teardown := startTestDnsServer(t, txtHandler([][]string{{"v=DKIM1; ", "p=AAA"}}))
		defer teardown()

		got, err := client.GetDkimRecordStringWithDomainName(context.Background(), "example.com")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := "v=DKIM1; p=AAA"
		if got != want {
			t.Errorf("got = %q, want %q", got, want)
		}
	})

	t.Run("nxdomain returns empty", func(t *testing.T) {
		t.Parallel()
		client, teardown := startTestDnsServer(t, nxdomainHandler())
		defer teardown()

		got, err := client.GetDkimRecordStringWithDomainName(context.Background(), "missing.example.com")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "" {
			t.Errorf("got = %q, want empty", got)
		}
	})

	t.Run("servfail surfaces error", func(t *testing.T) {
		t.Parallel()
		client, teardown := startTestDnsServer(t, servfailHandler())
		defer teardown()

		got, err := client.GetDkimRecordStringWithDomainName(context.Background(), "broken.example.com")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if got != "" {
			t.Errorf("got = %q, want empty", got)
		}
		rcode, ok := errors.AsType[*dnsUtilsErrors.RcodeError](err)
		if !ok {
			t.Fatalf("err type = %T (%v), want *dnsUtilsErrors.RcodeError", err, err)
		}
		if rcode.Rcode != dns.RcodeServerFailure {
			t.Errorf("rcode = %d, want %d", rcode.Rcode, dns.RcodeServerFailure)
		}
	})

	t.Run("multiple records error", func(t *testing.T) {
		t.Parallel()
		client, teardown := startTestDnsServer(t, txtHandler([][]string{
			{"v=DKIM1; p=AAA"},
			{"v=DKIM1; p=BBB"},
		}))
		defer teardown()

		got, err := client.GetDkimRecordStringWithDomainName(context.Background(), "example.com")
		if got != "" {
			t.Errorf("got = %q, want empty", got)
		}
		multi, ok := errors.AsType[*dnsUtilsErrors.MultipleRecordsError](err)
		if !ok {
			t.Fatalf("err type = %T (%v), want *dnsUtilsErrors.MultipleRecordsError", err, err)
		}
		if len(multi.Records) != 2 {
			t.Errorf("Records count = %d, want 2", len(multi.Records))
		}
	})

	t.Run("empty TXT entries skipped", func(t *testing.T) {
		t.Parallel()
		client, teardown := startTestDnsServer(t, txtHandler([][]string{{""}}))
		defer teardown()

		got, err := client.GetDkimRecordStringWithDomainName(context.Background(), "example.com")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "" {
			t.Errorf("got = %q, want empty", got)
		}
	})
}

func TestGetDkimRecordString(t *testing.T) {
	t.Parallel()

	t.Run("nil dns client", func(t *testing.T) {
		t.Parallel()
		var c *Client
		got, err := c.GetDkimRecordString(context.Background(), "example.com", "selector1")
		if got != "" {
			t.Errorf("got = %q, want empty", got)
		}
		expectNilDnsClientError(t, err)
	})

	t.Run("cancelled context", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		got, err := DefaultClient.GetDkimRecordString(ctx, "example.com", "selector1")
		if got != "" {
			t.Errorf("got = %q, want empty", got)
		}
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
	})

	t.Run("empty domain", func(t *testing.T) {
		t.Parallel()
		got, err := DefaultClient.GetDkimRecordString(context.Background(), "", "selector1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "" {
			t.Errorf("got = %q, want empty", got)
		}
	})

	t.Run("composes selector and domain", func(t *testing.T) {
		t.Parallel()
		var seen string
		client, teardown := startTestDnsServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
			seen = r.Question[0].Name
			txtHandler([][]string{{validDkimRecordString}})(w, r)
		})
		defer teardown()

		got, err := client.GetDkimRecordString(context.Background(), "example.com", "selector1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != validDkimRecordString {
			t.Errorf("got = %q, want %q", got, validDkimRecordString)
		}
		const wantQuery = "selector1._domainkey.example.com."
		if seen != wantQuery {
			t.Errorf("query = %q, want %q", seen, wantQuery)
		}
	})

	t.Run("wraps inner error", func(t *testing.T) {
		t.Parallel()
		client, teardown := startTestDnsServer(t, servfailHandler())
		defer teardown()

		_, err := client.GetDkimRecordString(context.Background(), "example.com", "selector1")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "get record string with domain name") {
			t.Errorf("err = %v, expected to mention inner func", err)
		}
	})
}

func TestGetDkimRecord(t *testing.T) {
	t.Parallel()

	t.Run("nil dns client", func(t *testing.T) {
		t.Parallel()
		var c *Client
		got, err := c.GetDkimRecord(context.Background(), "example.com", "selector1")
		if got != nil {
			t.Errorf("got = %v, want nil", got)
		}
		expectNilDnsClientError(t, err)
	})

	t.Run("cancelled context", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		got, err := DefaultClient.GetDkimRecord(ctx, "example.com", "selector1")
		if got != nil {
			t.Errorf("got = %v, want nil", got)
		}
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
	})

	t.Run("empty domain", func(t *testing.T) {
		t.Parallel()
		got, err := DefaultClient.GetDkimRecord(context.Background(), "", "selector1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != nil {
			t.Errorf("got = %v, want nil", got)
		}
	})

	t.Run("nxdomain returns nil record", func(t *testing.T) {
		t.Parallel()
		client, teardown := startTestDnsServer(t, nxdomainHandler())
		defer teardown()

		got, err := client.GetDkimRecord(context.Background(), "missing.example.com", "selector1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != nil {
			t.Errorf("got = %v, want nil", got)
		}
	})

	t.Run("valid record parsed and decorated", func(t *testing.T) {
		t.Parallel()
		client, teardown := startTestDnsServer(t, txtHandler([][]string{{validDkimRecordString}}))
		defer teardown()

		got, err := client.GetDkimRecord(context.Background(), "example.com", "selector1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got == nil {
			t.Fatal("got nil record, want non-nil")
		}
		if got.Domain != "example.com" {
			t.Errorf("Domain = %q, want %q", got.Domain, "example.com")
		}
		if got.Selector != "selector1" {
			t.Errorf("Selector = %q, want %q", got.Selector, "selector1")
		}
		if got.PublicKeyData == "" {
			t.Error("expected non-empty PublicKeyData")
		}
		if got.Raw != validDkimRecordString {
			t.Errorf("Raw mismatch: got %q, want %q", got.Raw, validDkimRecordString)
		}
	})

	t.Run("dns error wrapped", func(t *testing.T) {
		t.Parallel()
		client, teardown := startTestDnsServer(t, servfailHandler())
		defer teardown()

		got, err := client.GetDkimRecord(context.Background(), "example.com", "selector1")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if got != nil {
			t.Errorf("got = %v, want nil", got)
		}
		if !strings.Contains(err.Error(), "get record string") {
			t.Errorf("err = %v, expected to mention get record string", err)
		}
	})

	t.Run("malformed record returns raw record and error", func(t *testing.T) {
		t.Parallel()
		const garbage = "this is not a dkim record"
		client, teardown := startTestDnsServer(t, txtHandler([][]string{{garbage}}))
		defer teardown()

		got, err := client.GetDkimRecord(context.Background(), "example.com", "selector1")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if got == nil {
			t.Fatal("expected raw record on parse failure, got nil")
		}
		if got.Raw != garbage {
			t.Errorf("Raw = %q, want %q", got.Raw, garbage)
		}
		if got.Domain != "example.com" {
			t.Errorf("Domain = %q, want %q", got.Domain, "example.com")
		}
	})
}
