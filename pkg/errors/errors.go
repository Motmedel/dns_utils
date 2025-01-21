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
	ErrEmptyPrefix        = errors.New("empty prefix")
	ErrNilExchangeMessage = errors.New("nil exchange message")
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
