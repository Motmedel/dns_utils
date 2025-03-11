package types

import (
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
	ServerAddress   string
	Transport       string
	Time            *time.Time
}
