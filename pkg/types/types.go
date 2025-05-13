package types

import (
	motmedelTlsTypes "github.com/Motmedel/utils_go/pkg/tls/types"
	"github.com/miekg/dns"
	"time"
)

type ActiveResult struct {
	Domain    string
	Cnames    []string
	Addresses []string
	MxHosts   []string
}

type DnsContext struct {
	QuestionMessage *dns.Msg
	AnswerMessage   *dns.Msg
	ClientAddress   string
	ServerAddress   string
	Transport       string
	Time            *time.Time
	TlsContext      *motmedelTlsTypes.TlsContext
}
