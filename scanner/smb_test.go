package scanner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/jfjallid/go-smb/smb"
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
		{name: "access denied", err: &smb.NTStatusError{Op: "Create", Status: smb.StatusAccessDenied, Err: smb.StatusMap[smb.StatusAccessDenied]}, want: true},
		{name: "wrapped access denied", err: fmt.Errorf("put file: %w", &smb.NTStatusError{Op: "Create", Status: smb.StatusAccessDenied, Err: smb.StatusMap[smb.StatusAccessDenied]}), want: true},
		{name: "privilege not held (unmapped status)", err: &smb.NTStatusError{Op: "Create", Status: statusPrivilegeNotHeld}, want: true},
		{name: "other status", err: &smb.NTStatusError{Op: "Create", Status: smb.StatusBadNetworkName, Err: smb.StatusMap[smb.StatusBadNetworkName]}, want: false},
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
