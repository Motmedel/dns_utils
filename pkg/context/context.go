package context

import (
	"context"
	dnsUtilsTypes "github.com/Motmedel/dns_utils/pkg/types"
)

type dnsContextKeyType struct{}

var DnsContextKey = &dnsContextKeyType{}

func WithDnsContext(parent context.Context) context.Context {
	return context.WithValue(parent, DnsContextKey, &dnsUtilsTypes.DnsContext{})
}
