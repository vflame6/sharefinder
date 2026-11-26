package scanner

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"
)

// sweepScanner returns a scanner whose sweep probes port with the given pool.
func sweepScanner(t *testing.T, port, threads int, timeout time.Duration) *Scanner {
	t.Helper()
	d, err := NewDialer("", 5*time.Second, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	o := &Options{Dialer: d, SmbPort: port, Writer: NewOutputWriter(),
		Discovery: SweepConfig{Enabled: true, Threads: threads, Timeout: timeout}}
	return NewScanner(o, nil, time.Now(), 2)
}

// runSweep feeds targets to the sweep and collects what it forwards.
func runSweep(ctx context.Context, s *Scanner, targets []DNHost) []DNHost {
	in, out := make(chan DNHost), make(chan DNHost, len(targets))
	go func() {
		defer close(in)
		for _, t := range targets {
			select {
			case in <- t:
			case <-ctx.Done():
				return
			}
		}
	}()
	s.sweep(ctx, in, out)
	close(out)
	var live []DNHost
	for h := range out {
		live = append(live, h)
	}
	return live
}

func testNet(n int) []DNHost {
	var targets []DNHost
	for i := 1; i <= n; i++ {
		// TEST-NET-1 and -3: reserved, nothing answers
		targets = append(targets, DNHost{IP: net.ParseIP(fmt.Sprintf("192.0.2.%d", i%250+1))}, DNHost{IP: net.ParseIP(fmt.Sprintf("203.0.113.%d", i%250+1))})
	}
	return targets[:n]
}

func listen(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func TestSweep_OnlyRespondersPass(t *testing.T) {
	s := sweepScanner(t, listen(t), 4, 500*time.Millisecond)
	live := runSweep(context.Background(), s, []DNHost{{IP: net.ParseIP("192.0.2.1")}, {IP: net.ParseIP("127.0.0.1")}, {IP: net.ParseIP("127.0.0.1")}})
	if len(live) != 1 || live[0].Address() != "127.0.0.1" {
		t.Fatalf("forwarded %v, want only 127.0.0.1", live)
	}
	// the duplicate and the silent host are done; the responder is the SMB stage's
	if targets, done := s.Stats.Targets.Load(), s.Stats.Done.Load(); targets != 2 || done != 2 {
		t.Fatalf("targets %d, done %d; want 2, 2", targets, done)
	}
}

func TestSweep_40FilteredTargetsUnderOneSecond(t *testing.T) {
	s := sweepScanner(t, 445, 500, 500*time.Millisecond)
	start := time.Now()
	if live := runSweep(context.Background(), s, testNet(40)); len(live) != 0 {
		t.Fatalf("nothing answers on TEST-NET, forwarded %v", live)
	}
	if took := time.Since(start); took > 1500*time.Millisecond {
		t.Fatalf("40 silent targets took %v with 500 threads and a 500 ms timeout", took)
	}
}

func TestSweep_CancelStopsPromptly(t *testing.T) {
	s := sweepScanner(t, 445, 10, 5*time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(200*time.Millisecond, cancel)
	start := time.Now()
	runSweep(ctx, s, testNet(1000))
	if took := time.Since(start); took > time.Second {
		t.Fatalf("the sweep took %v to stop after cancel", took)
	}
}
