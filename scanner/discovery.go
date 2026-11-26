package scanner

import (
	"context"
	"net"
	"strconv"
	"sync"
	"time"
)

// SweepConfig configures the discovery sweep: a TCP connect to the SMB port
// of every target, with its own large pool and short timeout, so that only
// hosts that answer wait for an SMB worker.
type SweepConfig struct {
	Enabled bool          // --discovery
	Threads int           // --discovery-threads
	Timeout time.Duration // --connect-timeout
}

// sweep admits the targets from in (resolution, --exclude-hosts, duplicates)
// and sends those that accept a TCP connection on the SMB port to out. It
// returns when in is drained or ctx is done; it does not close out.
func (s *Scanner) sweep(ctx context.Context, in <-chan DNHost, out chan<- DNHost) {
	threads := max(s.Options.Discovery.Threads, 1)
	var wg sync.WaitGroup
	for range threads {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case target, ok := <-in:
					if !ok {
						return
					}
					host, ok := s.admit(ctx, target)
					if !ok {
						continue
					}
					if !s.responds(ctx, host) {
						s.Stats.Done.Add(1)
						continue
					}
					select {
					case out <- host:
					case <-ctx.Done():
						return
					}
				}
			}
		}()
	}
	wg.Wait()
}

// responds reports whether host accepts a TCP connection on the SMB port.
func (s *Scanner) responds(ctx context.Context, host DNHost) bool {
	dialCtx := ctx
	if timeout := s.Options.Discovery.Timeout; timeout > 0 {
		var cancel context.CancelFunc
		dialCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	conn, err := s.Options.Dialer.DialContext(dialCtx, "tcp", net.JoinHostPort(host.Address(), strconv.Itoa(s.Options.SmbPort)))
	if err != nil {
		if ctx.Err() == nil {
			reportHostError(host.Address(), err)
		}
		return false
	}
	_ = conn.Close()
	return true
}
