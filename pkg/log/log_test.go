package log

import (
	"context"
	"log/slog"
	"net"
	"reflect"
	"testing"

	dnsUtilsContext "github.com/Motmedel/dns_utils/pkg/context"
	dnsUtilsTypes "github.com/Motmedel/dns_utils/pkg/types"
	"github.com/Motmedel/utils_go/pkg/net/types/flow_tuple"
	"github.com/Motmedel/utils_go/pkg/schema"
	"github.com/miekg/dns"
)

func makeA(name string, ttl uint32, ip string) *dns.A {
	return &dns.A{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
		A:   net.ParseIP(ip),
	}
}

func makeAAAA(name string, ttl uint32, ip string) *dns.AAAA {
	return &dns.AAAA{
		Hdr:  dns.RR_Header{Name: name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl},
		AAAA: net.ParseIP(ip),
	}
}

func TestEnrichWithDnsMessage_NilBase(t *testing.T) {
	// Should not panic.
	EnrichWithDnsMessage(nil, &dns.Msg{})
}

func TestEnrichWithDnsMessage_NilMessage(t *testing.T) {
	base := &schema.Base{}
	EnrichWithDnsMessage(base, nil)
	if base.Dns != nil {
		t.Errorf("base.Dns = %v, want nil", base.Dns)
	}
}

func TestEnrichWithDnsMessage_QuestionOnly(t *testing.T) {
	msg := &dns.Msg{}
	msg.RecursionDesired = true
	msg.SetQuestion("www.example.com.", dns.TypeA)
	msg.Id = 42

	base := &schema.Base{}
	EnrichWithDnsMessage(base, msg)

	if base.Dns == nil {
		t.Fatalf("base.Dns = nil, want non-nil")
	}

	if got, want := base.Dns.Id, "42"; got != want {
		t.Errorf("Id = %q, want %q", got, want)
	}
	if got, want := base.Dns.OpCode, "QUERY"; got != want {
		t.Errorf("OpCode = %q, want %q", got, want)
	}
	if got, want := base.Dns.Type, "question"; got != want {
		t.Errorf("Type = %q, want %q", got, want)
	}
	if got, want := base.Dns.HeaderFlags, []string{"RD"}; !reflect.DeepEqual(got, want) {
		t.Errorf("HeaderFlags = %v, want %v", got, want)
	}
	if base.Dns.Question == nil {
		t.Fatalf("Question = nil, want non-nil")
	}
	if got, want := base.Dns.Question.Name, "www.example.com"; got != want {
		t.Errorf("Question.Name = %q, want %q", got, want)
	}
	if got, want := base.Dns.Question.Type, "A"; got != want {
		t.Errorf("Question.Type = %q, want %q", got, want)
	}
	if got, want := base.Dns.Question.Class, "IN"; got != want {
		t.Errorf("Question.Class = %q, want %q", got, want)
	}
	if got, want := base.Dns.Question.RegisteredDomain, "example.com"; got != want {
		t.Errorf("Question.RegisteredDomain = %q, want %q", got, want)
	}
	if got, want := base.Dns.Question.Subdomain, "www"; got != want {
		t.Errorf("Question.Subdomain = %q, want %q", got, want)
	}
	if got, want := base.Dns.Question.TopLevelDomain, "com"; got != want {
		t.Errorf("Question.TopLevelDomain = %q, want %q", got, want)
	}
	if base.Dns.ResponseCode != "" {
		t.Errorf("ResponseCode = %q, want empty", base.Dns.ResponseCode)
	}
}

func TestEnrichWithDnsMessage_AnswerWithResolvedIps(t *testing.T) {
	msg := &dns.Msg{}
	msg.Id = 7
	msg.Response = true
	msg.RecursionAvailable = true
	msg.SetQuestion("example.com.", dns.TypeA)
	msg.Answer = []dns.RR{
		makeA("example.com.", 60, "1.2.3.4"),
		makeA("example.com.", 60, "1.2.3.4"), // duplicate to test set deduplication
		makeA("example.com.", 60, "5.6.7.8"),
		makeAAAA("example.com.", 60, "::1"),
		nil, // must be skipped
	}

	base := &schema.Base{}
	EnrichWithDnsMessage(base, msg)

	if base.Dns == nil {
		t.Fatalf("base.Dns = nil, want non-nil")
	}

	if got, want := base.Dns.Type, "answer"; got != want {
		t.Errorf("Type = %q, want %q", got, want)
	}
	if got, want := base.Dns.ResponseCode, "NOERROR"; got != want {
		t.Errorf("ResponseCode = %q, want %q", got, want)
	}
	if got, want := len(base.Dns.Answers), 4; got != want {
		t.Fatalf("len(Answers) = %d, want %d", got, want)
	}

	wantIps := map[string]bool{"1.2.3.4": true, "5.6.7.8": true, "::1": true}
	if got := len(base.Dns.ResolvedIp); got != len(wantIps) {
		t.Fatalf("len(ResolvedIp) = %d, want %d (%v)", got, len(wantIps), base.Dns.ResolvedIp)
	}
	for _, ip := range base.Dns.ResolvedIp {
		if !wantIps[ip] {
			t.Errorf("unexpected ResolvedIp %q", ip)
		}
	}

	first := base.Dns.Answers[0]
	if first.Name != "example.com" {
		t.Errorf("Answer[0].Name = %q, want %q", first.Name, "example.com")
	}
	if first.Type != "A" {
		t.Errorf("Answer[0].Type = %q, want %q", first.Type, "A")
	}
	if first.Data != "1.2.3.4" {
		t.Errorf("Answer[0].Data = %q, want %q", first.Data, "1.2.3.4")
	}
	if first.Ttl != 60 {
		t.Errorf("Answer[0].Ttl = %d, want 60", first.Ttl)
	}
}

func TestEnrichWithDnsMessage_PreservesExistingDns(t *testing.T) {
	existing := &schema.Dns{Id: "existing"}
	base := &schema.Base{Dns: existing}

	msg := &dns.Msg{}
	msg.SetQuestion("example.com.", dns.TypeA)
	msg.Id = 99

	EnrichWithDnsMessage(base, msg)

	if base.Dns != existing {
		t.Errorf("base.Dns was replaced, want same pointer")
	}
	if base.Dns.Id != "99" {
		t.Errorf("Id = %q, want %q", base.Dns.Id, "99")
	}
}

func TestParseDnsMessage_Nil(t *testing.T) {
	if got := ParseDnsMessage(nil); got != nil {
		t.Errorf("ParseDnsMessage(nil) = %v, want nil", got)
	}
}

func TestParseDnsMessage_SetsDnsProtocol(t *testing.T) {
	msg := &dns.Msg{}
	msg.SetQuestion("example.com.", dns.TypeA)

	base := ParseDnsMessage(msg)
	if base == nil {
		t.Fatalf("ParseDnsMessage = nil, want non-nil")
	}
	if base.Network == nil || base.Network.Protocol != "dns" {
		t.Errorf("Network.Protocol = %v, want dns", base.Network)
	}
	if base.Dns == nil || base.Dns.Question == nil {
		t.Errorf("Dns.Question = nil, want non-nil")
	}
}

func TestParseDnsContext_Nil(t *testing.T) {
	if got := ParseDnsContext(nil); got != nil {
		t.Errorf("ParseDnsContext(nil) = %v, want nil", got)
	}
}

func TestParseDnsContext_NoMessages(t *testing.T) {
	if got := ParseDnsContext(&dnsUtilsTypes.DnsContext{Transport: "udp"}); got != nil {
		t.Errorf("ParseDnsContext(no messages) = %v, want nil", got)
	}
}

func TestParseDnsContext_PrefersAnswerMessage(t *testing.T) {
	question := &dns.Msg{}
	question.SetQuestion("example.com.", dns.TypeA)

	answer := &dns.Msg{}
	answer.SetQuestion("example.com.", dns.TypeA)
	answer.Response = true
	answer.Answer = []dns.RR{makeA("example.com.", 30, "1.2.3.4")}

	base := ParseDnsContext(&dnsUtilsTypes.DnsContext{
		QuestionMessage: question,
		AnswerMessage:   answer,
		Transport:       "udp",
	})
	if base == nil {
		t.Fatalf("base = nil, want non-nil")
	}
	if base.Dns == nil || base.Dns.Type != "answer" {
		t.Errorf("Dns.Type = %v, want answer", base.Dns)
	}
}

func TestParseDnsContext_FallsBackToQuestionMessage(t *testing.T) {
	question := &dns.Msg{}
	question.SetQuestion("example.com.", dns.TypeA)

	base := ParseDnsContext(&dnsUtilsTypes.DnsContext{
		QuestionMessage: question,
		Transport:       "udp",
	})
	if base == nil {
		t.Fatalf("base = nil, want non-nil")
	}
	if base.Dns == nil || base.Dns.Type != "question" {
		t.Errorf("Dns.Type = %v, want question", base.Dns)
	}
}

func TestParseDnsContext_TransportDefaults(t *testing.T) {
	msg := &dns.Msg{}
	msg.SetQuestion("example.com.", dns.TypeA)

	tests := []struct {
		name       string
		transport  string
		wantTrans  string
		wantIana   string
	}{
		{"empty defaults to udp", "", "udp", "17"},
		{"udp", "udp", "udp", "17"},
		{"tcp", "tcp", "tcp", "6"},
		{"uppercase is lowered", "TCP", "tcp", "6"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base := ParseDnsContext(&dnsUtilsTypes.DnsContext{
				QuestionMessage: msg,
				Transport:       tt.transport,
			})
			if base == nil || base.Network == nil {
				t.Fatalf("base.Network = nil, want non-nil")
			}
			if base.Network.Transport != tt.wantTrans {
				t.Errorf("Transport = %q, want %q", base.Network.Transport, tt.wantTrans)
			}
			if base.Network.IanaNumber != tt.wantIana {
				t.Errorf("IanaNumber = %q, want %q", base.Network.IanaNumber, tt.wantIana)
			}
		})
	}
}

func TestParseDnsContext_ParsesAddresses(t *testing.T) {
	msg := &dns.Msg{}
	msg.SetQuestion("example.com.", dns.TypeA)

	base := ParseDnsContext(&dnsUtilsTypes.DnsContext{
		QuestionMessage: msg,
		ClientAddress:   "10.0.0.5:51234",
		ServerAddress:   "8.8.8.8:53",
		Transport:       "udp",
	})
	if base == nil {
		t.Fatalf("base = nil, want non-nil")
	}

	if base.Client == nil {
		t.Fatalf("Client = nil, want non-nil")
	}
	if base.Client.Address != "10.0.0.5" {
		t.Errorf("Client.Address = %q, want %q", base.Client.Address, "10.0.0.5")
	}
	if base.Client.Ip != "10.0.0.5" {
		t.Errorf("Client.Ip = %q, want %q", base.Client.Ip, "10.0.0.5")
	}
	if base.Client.Port != 51234 {
		t.Errorf("Client.Port = %d, want 51234", base.Client.Port)
	}
	if base.Client.Domain != "" {
		t.Errorf("Client.Domain = %q, want empty", base.Client.Domain)
	}

	if base.Server == nil {
		t.Fatalf("Server = nil, want non-nil")
	}
	if base.Server.Address != "8.8.8.8" {
		t.Errorf("Server.Address = %q, want %q", base.Server.Address, "8.8.8.8")
	}
	if base.Server.Ip != "8.8.8.8" {
		t.Errorf("Server.Ip = %q, want %q", base.Server.Ip, "8.8.8.8")
	}
	if base.Server.Port != 53 {
		t.Errorf("Server.Port = %d, want 53", base.Server.Port)
	}

	want := flow_tuple.New(
		net.ParseIP("10.0.0.5"),
		net.ParseIP("8.8.8.8"),
		51234,
		53,
		17,
	).Hash()
	if got := base.Network.CommunityId; len(got) != 1 || got[0] != want {
		t.Errorf("CommunityId = %v, want [%s]", got, want)
	}
}

func TestParseDnsContext_HostnameAddress(t *testing.T) {
	msg := &dns.Msg{}
	msg.SetQuestion("example.com.", dns.TypeA)

	base := ParseDnsContext(&dnsUtilsTypes.DnsContext{
		QuestionMessage: msg,
		ServerAddress:   "dns.example.com:53",
		Transport:       "udp",
	})
	if base == nil || base.Server == nil {
		t.Fatalf("Server = nil, want non-nil")
	}
	if base.Server.Ip != "" {
		t.Errorf("Server.Ip = %q, want empty (hostname, not IP)", base.Server.Ip)
	}
	if base.Server.Domain != "dns.example.com:53" {
		t.Errorf("Server.Domain = %q, want %q", base.Server.Domain, "dns.example.com:53")
	}
	if base.Server.Port != 53 {
		t.Errorf("Server.Port = %d, want 53", base.Server.Port)
	}
}

func TestParseDnsContext_NoAddresses(t *testing.T) {
	msg := &dns.Msg{}
	msg.SetQuestion("example.com.", dns.TypeA)

	base := ParseDnsContext(&dnsUtilsTypes.DnsContext{
		QuestionMessage: msg,
		Transport:       "udp",
	})
	if base == nil {
		t.Fatalf("base = nil, want non-nil")
	}
	if base.Client != nil {
		t.Errorf("Client = %v, want nil", base.Client)
	}
	if base.Server != nil {
		t.Errorf("Server = %v, want nil", base.Server)
	}
}

func TestExtractDnsContext_NoContext(t *testing.T) {
	rec := slog.Record{}
	if err := ExtractDnsContext(context.Background(), &rec); err != nil {
		t.Errorf("err = %v, want nil", err)
	}
	if rec.NumAttrs() != 0 {
		t.Errorf("NumAttrs = %d, want 0", rec.NumAttrs())
	}
}

func TestExtractDnsContext_EmitsAttrs(t *testing.T) {
	msg := &dns.Msg{}
	msg.Id = 1
	msg.SetQuestion("example.com.", dns.TypeA)

	ctx := dnsUtilsContext.WithDnsContextValue(
		context.Background(),
		&dnsUtilsTypes.DnsContext{QuestionMessage: msg, Transport: "udp"},
	)

	rec := slog.Record{}
	if err := ExtractDnsContext(ctx, &rec); err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if rec.NumAttrs() == 0 {
		t.Errorf("NumAttrs = 0, want > 0")
	}

	var seenDns, seenNetwork bool
	rec.Attrs(func(a slog.Attr) bool {
		switch a.Key {
		case "dns":
			seenDns = true
		case "network":
			seenNetwork = true
		}
		return true
	})
	if !seenDns {
		t.Errorf("missing dns attr")
	}
	if !seenNetwork {
		t.Errorf("missing network attr")
	}
}

func TestExtractDnsContext_WrongContextValue(t *testing.T) {
	// Context key present but with a nil *DnsContext → no attrs, no error.
	ctx := context.WithValue(context.Background(), dnsUtilsContext.DnsContextKey, (*dnsUtilsTypes.DnsContext)(nil))
	rec := slog.Record{}
	if err := ExtractDnsContext(ctx, &rec); err != nil {
		t.Errorf("err = %v, want nil", err)
	}
	if rec.NumAttrs() != 0 {
		t.Errorf("NumAttrs = %d, want 0", rec.NumAttrs())
	}
}
