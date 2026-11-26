package scanner

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

func TestProgressLine(t *testing.T) {
	var st Stats
	st.Total.Store(254)
	st.Done.Add(120)
	st.Reachable.Add(12)
	st.Shares.Add(45)
	st.Files.Add(12345)
	if got, want := st.ProgressLine(83*time.Second+400*time.Millisecond), "[*] 1m23s  targets 120/254  reachable 12  shares 45  files 12345"; got != want {
		t.Fatalf("ProgressLine = %q, want %q", got, want)
	}

	// a producer that does not know its total yet
	var unknown Stats
	unknown.Done.Add(3)
	if got, want := unknown.ProgressLine(0), "[*] 0s  targets 3  reachable 0  shares 0  files 0"; got != want {
		t.Fatalf("ProgressLine = %q, want %q", got, want)
	}
}

func TestRun_ProgressIsDrawnAndCleared(t *testing.T) {
	d, err := NewDialer("", 200*time.Millisecond, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	o := &Options{Dialer: d, Timeout: 200 * time.Millisecond, SmbPort: 445, NullSession: true, Mode: AuthNull, Writer: NewOutputWriter(), Progress: true}
	s := NewScanner(o, nil, time.Now(), 2)
	targets := []DNHost{{IP: net.ParseIP("192.0.2.1")}, {IP: net.ParseIP("192.0.2.2")}, {IP: net.ParseIP("192.0.2.1")}}
	out := captureLog(t, func() {
		if err := s.Run(context.Background(), TargetsFromList(targets)); err != nil {
			t.Error(err)
		}
	})
	if !strings.Contains(out, "[*] ") || !strings.HasSuffix(out, "\r\033[K") {
		t.Fatalf("the progress line must be drawn and cleared at the end: %q", out)
	}
	// the duplicate target is skipped, and still counts as done
	if got := s.Stats.Done.Load(); got != 3 {
		t.Fatalf("Done = %d, want 3", got)
	}
}
