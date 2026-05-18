package scanner

import (
	"errors"
	"testing"
)

func TestIsExpectedSMBWriteDeniedError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "privilege not held hex", err: errors.New("server returned error 0xc0000061"), want: true},
		{name: "privilege not held symbolic", err: errors.New("STATUS_PRIVILEGE_NOT_HELD"), want: true},
		{name: "access denied hex", err: errors.New("0xc0000022"), want: true},
		{name: "unexpected transport", err: errors.New("connection reset by peer"), want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isExpectedSMBWriteDeniedError(tt.err); got != tt.want {
				t.Fatalf("isExpectedSMBWriteDeniedError(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}
