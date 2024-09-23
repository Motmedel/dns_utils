package errors

import (
	"errors"
	motmedelErrors "github.com/Motmedel/utils_go/pkg/errors"
)

var (
	ErrNilDnsClient      = errors.New("dns client is nil")
	ErrUnsetRecordType   = errors.New("unset record type")
	ErrUnsuccessfulRcode = errors.New("unsuccessful rcode")
	ErrEmptyDnsServer    = errors.New("dns server is empty")
	ErrEmptyPrefix       = errors.New("prefix is empty")
)

type RcodeError struct {
	motmedelErrors.CauseError
	Rcode int
}

func (rcodeError *RcodeError) Is(target error) bool {
	return target == ErrUnsuccessfulRcode
}
