package errors

import (
	"errors"
	"fmt"
)

var (
	ErrNilDnsClient       = errors.New("nil dns client")
	ErrUnsetRecordType    = errors.New("unset record type")
	ErrUnsuccessfulRcode  = errors.New("unsuccessful rcode")
	ErrEmptyDnsServer     = errors.New("empty dns server")
	ErrNilExchangeMessage = errors.New("nil exchange message")
	ErrMultipleRecords    = errors.New("multiple records")
)

type RcodeError struct {
	Rcode int
}

func (rcodeError *RcodeError) Is(target error) bool {
	return target == ErrUnsuccessfulRcode
}

func (rcodeError *RcodeError) Error() string {
	return fmt.Sprintf("%s: %d", ErrUnsuccessfulRcode, rcodeError.Rcode)
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
