package errors

import (
	"errors"
	"fmt"
)

var (
	ErrNilDnsClient      = errors.New("dns client is nil")
	ErrUnsetRecordType   = errors.New("unset record type")
	ErrUnsuccessfulRcode = errors.New("unsuccessful rcode")
	ErrEmptyDnsServer    = errors.New("dns server is empty")
	ErrEmptyPrefix       = errors.New("prefix is empty")
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
