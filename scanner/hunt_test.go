package scanner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// slowDNS answers after 100 ms: hostN resolves to 10.0.0.N, names starting
// with "gone" do not resolve.
func slowDNS(ctx context.Context, name string) (net.IP, error) {
	select {
	case <-time.After(100 * time.Millisecond):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if strings.HasPrefix(name, "gone") {
		return nil, errors.New("no such host")
	}
	var n int
	fmt.Sscanf(strings.ToLower(name), "host%d", &n)
	return net.IPv4(10, 0, byte(n/250), byte(n%250)), nil
}

func TestResolvePool_Parallel(t *testing.T) {
	var names []DNHost
	for i := 1; i <= 60; i++ {
		names = append(names, DNHost{Hostname: fmt.Sprintf("host%d.corp.local", i)})
	}
	// the same computer twice (two domains in a forest list it), and two
	// computers without a DNS record
	names = append(names, DNHost{Hostname: "HOST1.corp.local"}, DNHost{Hostname: "gone1.corp.local"}, DNHost{Hostname: "gone2.corp.local"}, DNHost{Hostname: "host2.corp.local"})

	in, out := make(chan DNHost), make(chan DNHost, len(names))
	go func() {
		defer close(in)
		for _, n := range names {
			in <- n
		}
	}()
	var failed, duplicates int
	start := time.Now()
	logs := captureLog(t, func() {
		failed, duplicates = resolvePool(context.Background(), slowDNS, in, out, 32)
	})
	took := time.Since(start)
	close(out)

	if took > 500*time.Millisecond {
		t.Fatalf("64 names at 100 ms each over 32 workers took %v", took)
	}
	got := map[string]bool{}
	for h := range out {
		if h.IP == nil {
			t.Fatalf("%s forwarded without an address", h.Hostname)
		}
		got[strings.ToLower(h.Hostname)] = true
	}
	if len(got) != 60 || failed != 2 || duplicates != 2 {
		t.Fatalf("forwarded %d names, %d failed, %d duplicates; want 60, 2, 2", len(got), failed, duplicates)
	}
	if strings.Contains(logs, "gone1") {
		t.Errorf("unresolvable names are debug messages: %q", logs)
	}
}

func TestResolvePool_CancelStops(t *testing.T) {
	in, out := make(chan DNHost), make(chan DNHost)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		for i := 0; ; i++ {
			select {
			case in <- DNHost{Hostname: fmt.Sprintf("host%d", i)}:
			case <-ctx.Done():
				return
			}
		}
	}()
	time.AfterFunc(150*time.Millisecond, cancel)
	done := make(chan struct{})
	go func() {
		resolvePool(ctx, slowDNS, in, out, 4) // nobody reads out
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("resolvePool must return when ctx is done")
	}
}

func TestHuntTargets_CountsDroppedNames(t *testing.T) {
	s := NewScanner(&Options{}, nil, time.Now(), 1)
	names := []DNHost{{Hostname: "host1.corp.local"}, {Hostname: "gone.corp.local"}, {Hostname: "host1.corp.local"}, {Hostname: "host2.corp.local"}}
	out := make(chan DNHost, len(names))
	logs := captureLog(t, func() {
		if err := s.HuntTargets(names, slowDNS)(context.Background(), out); err != nil {
			t.Error(err)
		}
	})
	close(out)
	if n := len(out); n != 2 {
		t.Fatalf("forwarded %d hosts, want 2", n)
	}
	// dropped names are done for the progress line
	if done := s.Stats.Done.Load(); done != 2 {
		t.Fatalf("done = %d, want 2 (one unresolvable, one duplicate)", done)
	}
	if !strings.Contains(logs, "1 domain computer(s) did not resolve") {
		t.Fatalf("unresolvable computers are counted for the user: %q", logs)
	}
}
