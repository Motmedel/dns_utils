package errors

import (
	"errors"
	"testing"

	"github.com/miekg/dns"
)

func TestRcodeError_Error_KnownRcode(t *testing.T) {
	err := &RcodeError{Rcode: dns.RcodeNameError}
	got := err.Error()
	want := "unsuccessful rcode: 3 (NXDOMAIN)"
	if got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

func TestRcodeError_Error_UnknownRcode(t *testing.T) {
	err := &RcodeError{Rcode: 9999}
	got := err.Error()
	want := "unsuccessful rcode: 9999"
	if got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

func TestRcodeError_Is(t *testing.T) {
	err := &RcodeError{Rcode: dns.RcodeServerFailure}
	if !errors.Is(err, ErrUnsuccessfulRcode) {
		t.Errorf("errors.Is(err, ErrUnsuccessfulRcode) = false, want true")
	}
	if errors.Is(err, ErrUnsetRecordType) {
		t.Errorf("errors.Is(err, ErrUnsetRecordType) = true, want false")
	}
}

func TestRcodeError_AsTarget(t *testing.T) {
	err := error(&RcodeError{Rcode: dns.RcodeNameError})
	var target *RcodeError
	if !errors.As(err, &target) {
		t.Fatalf("errors.As did not match *RcodeError")
	}
	if target.Rcode != dns.RcodeNameError {
		t.Errorf("Rcode = %d, want %d", target.Rcode, dns.RcodeNameError)
	}
}

func TestMultipleRecordsError_Error(t *testing.T) {
	err := &MultipleRecordsError{Records: []string{"a", "b"}}
	if got, want := err.Error(), "multiple records"; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

func TestMultipleRecordsError_Is(t *testing.T) {
	err := &MultipleRecordsError{Records: []string{"a"}}
	if !errors.Is(err, ErrMultipleRecords) {
		t.Errorf("errors.Is(err, ErrMultipleRecords) = false, want true")
	}
	if errors.Is(err, ErrUnsuccessfulRcode) {
		t.Errorf("errors.Is(err, ErrUnsuccessfulRcode) = true, want false")
	}
}

func TestMultipleRecordsError_GetInput(t *testing.T) {
	records := []string{"x", "y", "z"}
	err := &MultipleRecordsError{Records: records}

	got, ok := err.GetInput().([]string)
	if !ok {
		t.Fatalf("GetInput() did not return []string")
	}
	if len(got) != len(records) {
		t.Fatalf("GetInput() len = %d, want %d", len(got), len(records))
	}
	for i := range records {
		if got[i] != records[i] {
			t.Errorf("GetInput()[%d] = %q, want %q", i, got[i], records[i])
		}
	}
}
