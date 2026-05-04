package errors

import (
	"errors"
	"fmt"

	"github.com/miekg/dns"
)

var (
	ErrUnsetRecordType   = errors.New("unset record type")
	ErrUnsuccessfulRcode = errors.New("unsuccessful rcode")
	ErrMultipleRecords   = errors.New("multiple records")
)

type RcodeError struct {
	Rcode int
}

func (e *RcodeError) Is(target error) bool {
	return target == ErrUnsuccessfulRcode
}

func (e *RcodeError) Error() string {
	rcode := e.Rcode

	msg := fmt.Sprintf("%s: %d", ErrUnsuccessfulRcode, rcode)
	if rcodeString, ok := dns.RcodeToString[rcode]; ok && rcodeString != "" {
		msg += fmt.Sprintf(" (%s)", rcodeString)
	}

	return msg
}

type MultipleRecordsError struct {
	Records []string
}

func (e *MultipleRecordsError) Is(target error) bool {
	return target == ErrMultipleRecords
}

func (e *MultipleRecordsError) Error() string {
	return ErrMultipleRecords.Error()
}

func (e *MultipleRecordsError) GetInput() any {
	return e.Records
}
