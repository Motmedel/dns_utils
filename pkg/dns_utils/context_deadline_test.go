package dns_utils

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// TestExchangeWithConnHonoursContextDeadline pins the behaviour that the
// caller's deadline bounds the exchange. Before the context-aware call was
// used, only the client's own timeout applied, so this took miekg's two second
// default however short the caller's deadline was.
func TestExchangeWithConnHonoursContextDeadline(t *testing.T) {
	t.Parallel()

	// A listener that accepts and then says nothing, so the exchange can only
	// end on a deadline.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { _ = connection.Close() })
		}
	}()

	netConnection, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = netConnection.Close() })

	message := new(dns.Msg)
	message.SetQuestion(dns.Fqdn("example.com"), dns.TypeA)

	const deadline = 150 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()

	start := time.Now()
	_, err = ExchangeWithConn(ctx, message, &dns.Client{}, &dns.Conn{Conn: netConnection})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected the exchange to fail against a silent server")
	}

	// miekg's default is two seconds; the caller asked for a good deal less.
	if elapsed > time.Second {
		t.Errorf("exchange took %v, so the caller's %v deadline was not honoured", elapsed, deadline)
	}
}
