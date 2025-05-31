package errors

import "errors"

var (
	ErrMessageLengthOverflow = errors.New("message length overflow")
)
