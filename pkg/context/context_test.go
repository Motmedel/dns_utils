package context

import (
	"context"
	"testing"

	dnsUtilsTypes "github.com/Motmedel/dns_utils/pkg/types"
)

func TestWithDnsContextValue(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name       string
		dnsContext *dnsUtilsTypes.DnsContext
	}{
		{name: "a context is retrievable", dnsContext: &dnsUtilsTypes.DnsContext{}},
		{name: "a nil context is stored as it was given", dnsContext: nil},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			ctx := WithDnsContextValue(context.Background(), testCase.dnsContext)

			stored, ok := ctx.Value(DnsContextKey).(*dnsUtilsTypes.DnsContext)
			if !ok {
				t.Fatal("expected a dns context under the key")
			}

			if stored != testCase.dnsContext {
				t.Errorf("expected the same pointer back, got %p want %p", stored, testCase.dnsContext)
			}
		})
	}
}

func TestWithDnsContext(t *testing.T) {
	t.Parallel()

	ctx := WithDnsContext(context.Background())

	stored, ok := ctx.Value(DnsContextKey).(*dnsUtilsTypes.DnsContext)
	if !ok || stored == nil {
		t.Fatal("expected a fresh dns context under the key")
	}
}

func TestTheKeyIsPrivateToThisPackage(t *testing.T) {
	t.Parallel()

	// A struct key cannot collide with a string key some other package puts in
	// the same context, which is the reason for the unexported type.
	ctx := context.WithValue(context.Background(), "DnsContextKey", &dnsUtilsTypes.DnsContext{}) //nolint:staticcheck // deliberately a string key

	if ctx.Value(DnsContextKey) != nil {
		t.Error("a string key must not satisfy the package's own key")
	}
}

func TestValuesNest(t *testing.T) {
	t.Parallel()

	first := &dnsUtilsTypes.DnsContext{}
	second := &dnsUtilsTypes.DnsContext{}

	ctx := WithDnsContextValue(WithDnsContextValue(context.Background(), first), second)

	if stored, _ := ctx.Value(DnsContextKey).(*dnsUtilsTypes.DnsContext); stored != second {
		t.Error("expected the innermost value to win")
	}
}
