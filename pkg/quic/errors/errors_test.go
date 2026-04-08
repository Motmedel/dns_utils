package errors

import "testing"

func TestErrMessageLengthOverflow_Message(t *testing.T) {
	if got, want := ErrMessageLengthOverflow.Error(), "message length overflow"; got != want {
		t.Errorf("ErrMessageLengthOverflow.Error() = %q, want %q", got, want)
	}
}
