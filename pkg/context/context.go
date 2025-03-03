package context

import (
	"context"
	dnsUtilsTypes "github.com/Motmedel/dns_utils/pkg/types"
)

type dnsContextKeyType struct{}

var DnsContextKey = &dnsContextKeyType{}

func WithDnsContextValue(parent context.Context, dnsContext *dnsUtilsTypes.DnsContext) context.Context {
	return context.WithValue(parent, DnsContextKey, dnsContext)
}

func WithDnsContext(parent context.Context) context.Context {
	return WithDnsContextValue(parent, &dnsUtilsTypes.DnsContext{})
}
