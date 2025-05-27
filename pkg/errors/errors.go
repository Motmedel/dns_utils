package errors

import (
	"errors"
	"fmt"
	"github.com/miekg/dns"
)

var (
	ErrNilDnsClient      = errors.New("nil dns client")
	ErrUnsetRecordType   = errors.New("unset record type")
	ErrUnsuccessfulRcode = errors.New("unsuccessful rcode")
	ErrEmptyDnsServer    = errors.New("empty dns server")
	ErrNilMessage        = errors.New("nil message")
	ErrMultipleRecords   = errors.New("multiple records")
	ErrNilConnection     = errors.New("nil connection")
)

type RcodeError struct {
	Rcode int
}

func (rcodeError *RcodeError) Is(target error) bool {
	return target == ErrUnsuccessfulRcode
}

func (rcodeError *RcodeError) Error() string {
	rcode := rcodeError.Rcode

	msg := fmt.Sprintf("%s: %d", ErrUnsuccessfulRcode, rcode)
	if rcodeString, ok := dns.RcodeToString[rcode]; ok && rcodeString != "" {
		msg += fmt.Sprintf(" (%s)", rcodeString)
	}

	return msg
}

type MultipleRecordsError struct {
	Records []string
}

func (multipleRecordsError *MultipleRecordsError) Is(target error) bool {
	return target == ErrMultipleRecords
}

func (multipleRecordsError *MultipleRecordsError) Error() string {
	return ErrMultipleRecords.Error()
}

func (multipleRecordsError *MultipleRecordsError) GetInput() any {
	return multipleRecordsError.Records
}
