package scanner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jfjallid/go-smb/smb"
	"github.com/vflame6/sharefinder/logger"
)

func TestClassify(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want Stage
	}{
		{"connection refused", &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}, StageConnect},
		{"timeout", context.DeadlineExceeded, StageConnect},
		{"connect stage", &StageError{Stage: StageConnect, Host: "h", Err: errors.New("EOF")}, StageConnect},
		{"auth stage", &StageError{Stage: StageAuth, Host: "h", Err: smb.StatusMap[smb.StatusLogonFailure]}, StageAuth},
		{"wrapped enumeration stage", fmt.Errorf("listing: %w", &StageError{Stage: StageEnumerate, Host: "h", Err: errors.New("denied")}), StageEnumerate},
	}
	for _, tt := range tests {
		if got := classify(tt.err); got != tt.want {
			t.Errorf("%s: classify = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestSummaryLine(t *testing.T) {
	var st Stats
	st.Targets.Add(254)
	st.Reachable.Add(12)
	st.Authenticated.Add(10)
	st.Failed.Add(2)
	if got, want := st.SummaryLine(), "Summary: 254 targets, 12 reachable, 10 authenticated, 2 failed"; got != want {
		t.Fatalf("SummaryLine() = %q, want %q", got, want)
	}
}

func TestReportHostError(t *testing.T) {
	authErr := &StageError{Stage: StageAuth, Host: "10.0.0.9", Err: smb.StatusMap[smb.StatusLogonFailure]}
	enumErr := &StageError{Stage: StageEnumerate, Host: "10.0.0.9", Err: errors.New("access denied")}
	connErr := &StageError{Stage: StageConnect, Host: "10.0.0.9", Err: errors.New("i/o timeout")}

	out := captureLog(t, func() {
		reportHostError("10.0.0.9", authErr)
		reportHostError("10.0.0.9", enumErr)
		reportHostError("10.0.0.9", connErr)
	})
	for _, want := range []string{"[-] 10.0.0.9: authentication failed: Logon failed", "[-] 10.0.0.9: enumeration failed: access denied"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q: %q", want, out)
		}
	}
	if strings.Contains(out, "connection failed") || strings.Contains(out, "during authentication") {
		t.Errorf("unreachable hosts stay hidden without --debug, and are not authentication errors: %q", out)
	}

	prev := logger.Log.Debug
	logger.Log.Debug = true
	defer func() { logger.Log.Debug = prev }()
	if out := captureLog(t, func() { reportHostError("10.0.0.9", connErr) }); !strings.Contains(out, "10.0.0.9: connection failed: i/o timeout") {
		t.Errorf("--debug shows unreachable hosts: %q", out)
	}
}

func TestRun_UnreachableTargetsAreQuiet(t *testing.T) {
	d, err := NewDialer("", 300*time.Millisecond, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	o := &Options{Dialer: d, Timeout: 300 * time.Millisecond, SmbPort: 445, NullSession: true, Mode: AuthNull, Writer: NewOutputWriter()}
	s := NewScanner(o, nil, time.Now(), 8)
	var targets []DNHost
	for i := 1; i <= 8; i++ {
		targets = append(targets, DNHost{IP: net.ParseIP(fmt.Sprintf("192.0.2.%d", i))}) // TEST-NET-1: never answers
	}
	out := captureLog(t, func() {
		if err := s.Run(context.Background(), TargetsFromList(targets)); err != nil {
			t.Error(err)
		}
	})
	if strings.Contains(out, "192.0.2.") {
		t.Errorf("unreachable hosts must not be reported without --debug: %q", out)
	}
	if got, want := s.Stats.SummaryLine(), "Summary: 8 targets, 0 reachable, 0 authenticated, 0 failed"; got != want {
		t.Fatalf("SummaryLine() = %q, want %q", got, want)
	}
}
