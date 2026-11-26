package scanner

import (
	"context"
	"errors"
	"net"
	"strconv"
	"testing"
	"time"
)

func TestNewSMBConnection_SilentHostTimesOut(t *testing.T) {
	addr := silentListener(t)
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(portStr)

	d, err := NewDialer("", time.Second, 500*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	o := &Options{Dialer: d, SmbPort: port, NullSession: true, Timeout: time.Second}

	start := time.Now()
	conn, err := NewSMBConnection(context.Background(), DNHost{IP: net.ParseIP("127.0.0.1")}, o)
	if err == nil {
		conn.Close()
		t.Fatal("expected an error from a host that never replies")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("NewSMBConnection returned after %v, want under 3s", elapsed)
	}
}

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
