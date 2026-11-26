package scanner

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jfjallid/go-smb/smb"
)

// poolProbe records how many listings run at once.
type poolProbe struct {
	mu       sync.Mutex
	now, max int
	opened   atomic.Int64
	closed   atomic.Int64
}

func (p *poolProbe) enter() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.now++
	p.max = max(p.max, p.now)
}

func (p *poolProbe) leave() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.now--
}

// slowConn lists every share in 50 ms.
type slowConn struct{ probe *poolProbe }

func (c *slowConn) WalkShare(ctx context.Context, share string, lim ListLimits, recurse bool,
	emit func(dir smb.SharedFile, depth int, entries []smb.SharedFile), onErr func(string, error)) (walkStats, error) {
	c.probe.enter()
	defer c.probe.leave()
	time.Sleep(50 * time.Millisecond)
	emit(smb.SharedFile{}, 0, []smb.SharedFile{{Name: "a.txt"}})
	return walkStats{Files: 1}, nil
}

func (c *slowConn) Close() { c.probe.closed.Add(1) }

// failingConn fails a directory and then the whole listing.
type failingConn struct{}

func (failingConn) WalkShare(ctx context.Context, share string, lim ListLimits, recurse bool,
	emit func(dir smb.SharedFile, depth int, entries []smb.SharedFile), onErr func(string, error)) (walkStats, error) {
	onErr("IT\n[+] 10.6.6.6: fake finding", errors.New("access denied"))
	return walkStats{Truncated: true}, errors.New("connection reset")
}

func (failingConn) Close() {}

func TestListShare_WarningsEscapeNames(t *testing.T) {
	h := &Host{IP: "10.0.0.5"}
	share := &Share{ShareName: "Data\n[+] 10.6.6.6: fake share"}
	var files atomic.Int64
	out := captureLog(t, func() {
		listShare(context.Background(), failingConn{}, MultiSink{}, h, share, ListLimits{MaxFiles: 10}, true, &files)
	})
	if strings.Contains(out, "\n[+]") {
		t.Fatalf("a line break in a server-supplied name must not start a line of its own: %q", out)
	}
	for _, want := range []string{`Data\x0a[+] 10.6.6.6: fake share`, `IT\x0a[+] 10.6.6.6: fake finding`} {
		if !strings.Contains(out, want) {
			t.Errorf("warnings lack the escaped name %q: %q", want, out)
		}
	}
}

// recordingSink counts finished shares and checks HostFinished comes last.
type recordingSink struct {
	MultiSink
	mu       sync.Mutex
	finished map[string]bool
	hostDone bool
	late     bool
}

func (r *recordingSink) ShareFinished(_ *Host, share *Share) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.hostDone {
		r.late = true
	}
	r.finished[share.ShareName] = true
}

func (r *recordingSink) HostFinished(*Host) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.hostDone = true
}

func poolScanner(conns, slotCount, taken int) (*Scanner, *recordingSink) {
	sink := &recordingSink{finished: map[string]bool{}}
	o := &Options{List: true, MaxConnsPerHost: conns, Sink: sink}
	s := NewScanner(o, nil, time.Now(), slotCount)
	s.slots = make(slots, slotCount)
	for range taken {
		s.slots <- struct{}{} // held by host workers
	}
	return s, sink
}

func poolJobs(h *Host, n int) []shareJob {
	h.Shares = make([]Share, n)
	jobs := make([]shareJob, n)
	for i := range h.Shares {
		h.Shares[i] = Share{ShareName: fmt.Sprintf("S%d", i), ReadPermission: true}
		jobs[i] = shareJob{host: h, share: &h.Shares[i]}
	}
	return jobs
}

func TestListShares_PerHostCap(t *testing.T) {
	s, sink := poolScanner(2, 4, 1)
	probe := &poolProbe{}
	h := &Host{IP: "10.0.0.5"}
	jobs := poolJobs(h, 10)
	open := func(context.Context) (shareConn, error) {
		probe.opened.Add(1)
		return &slowConn{probe: probe}, nil
	}

	start := time.Now()
	s.listShares(context.Background(), h, jobs, &slowConn{probe: probe}, open)
	took := time.Since(start)

	if probe.max != 2 || probe.opened.Load() != 1 {
		t.Fatalf("listings at once = %d with %d extra connections; want 2 and 1", probe.max, probe.opened.Load())
	}
	if probe.closed.Load() != 1 {
		t.Fatalf("the extra connection must be closed (the first belongs to the caller), closed %d", probe.closed.Load())
	}
	if took > 400*time.Millisecond {
		t.Fatalf("10 shares x 50 ms over 2 connections took %v", took)
	}
	if len(sink.finished) != 10 || sink.late || !sink.hostDone {
		t.Fatalf("finished %d shares, host finished %v, a share after the host: %v", len(sink.finished), sink.hostDone, sink.late)
	}
	if got := len(s.slots); got != 1 {
		t.Fatalf("slots in use after the host = %d, want 1 (the host worker's)", got)
	}
	if got := s.Stats.Files.Load(); got != 10 {
		t.Fatalf("files counted = %d, want 10", got)
	}
}

func TestListShares_NoSlotNoExtraWorker(t *testing.T) {
	s, sink := poolScanner(4, 1, 1)
	probe := &poolProbe{}
	h := &Host{IP: "10.0.0.5"}
	open := func(context.Context) (shareConn, error) {
		probe.opened.Add(1)
		return &slowConn{probe: probe}, nil
	}
	s.listShares(context.Background(), h, poolJobs(h, 4), &slowConn{probe: probe}, open)
	if probe.opened.Load() != 0 || probe.max != 1 || len(sink.finished) != 4 {
		t.Fatalf("with every slot taken one connection lists all: opened %d, at once %d, finished %d", probe.opened.Load(), probe.max, len(sink.finished))
	}
}

func TestListShares_FailedOpenLeavesJobsToOthers(t *testing.T) {
	s, sink := poolScanner(3, 4, 1)
	probe := &poolProbe{}
	h := &Host{IP: "10.0.0.5"}
	open := func(context.Context) (shareConn, error) { return nil, errors.New("logon failed") }
	s.listShares(context.Background(), h, poolJobs(h, 5), &slowConn{probe: probe}, open)
	if len(sink.finished) != 5 || len(s.slots) != 1 {
		t.Fatalf("finished %d shares, %d slots in use; want 5 and 1", len(sink.finished), len(s.slots))
	}
}

func TestListShares_CancelFinishesEveryShare(t *testing.T) {
	s, sink := poolScanner(2, 4, 1)
	probe := &poolProbe{}
	h := &Host{IP: "10.0.0.5"}
	jobs := poolJobs(h, 20)
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(80*time.Millisecond, cancel)
	s.listShares(ctx, h, jobs, &slowConn{probe: probe}, func(context.Context) (shareConn, error) { return &slowConn{probe: probe}, nil })
	partial := 0
	for _, j := range jobs {
		if j.share.Partial {
			partial++
		}
	}
	if len(sink.finished) != 20 || partial == 0 {
		t.Fatalf("after Ctrl+C every share is still finished, the unlisted ones partial: finished %d, partial %d", len(sink.finished), partial)
	}
}
