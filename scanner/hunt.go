package scanner

import (
	"context"
	"net"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/vflame6/sharefinder/logger"
)

// huntResolvers is how many domain computer names are resolved at once.
const huntResolvers = 32

// HuntTargets returns a Producer that resolves domain computer names with
// resolve, huntResolvers at a time, and sends each host on as soon as it
// resolves, so the discovery sweep starts with the first answers instead of
// waiting for the whole domain.
func (s *Scanner) HuntTargets(names []DNHost, resolve func(context.Context, string) (net.IP, error)) Producer {
	return func(ctx context.Context, out chan<- DNHost) error {
		in := make(chan DNHost)
		go func() {
			defer close(in)
			for _, name := range names {
				select {
				case in <- name:
				case <-ctx.Done():
					return
				}
			}
		}()
		failed, duplicates := resolvePool(ctx, resolve, in, out, huntResolvers)
		// names that are not scanned are done for the progress line
		s.Stats.Done.Add(int64(failed + duplicates))
		if failed > 0 {
			logger.Warnf("%d domain computer(s) did not resolve (--debug lists them)", failed)
		}
		return nil
	}
}

// resolvePool resolves the hostnames from in with workers lookups at a time
// and sends the hosts with their address to out. A name that does not
// resolve is dropped with a debug message, a name|address pair seen before
// is dropped as a duplicate. It returns when in is drained or ctx is done.
func resolvePool(ctx context.Context, resolve func(context.Context, string) (net.IP, error), in <-chan DNHost, out chan<- DNHost, workers int) (failed, duplicates int) {
	var mu sync.Mutex
	seen := make(map[string]bool)
	var nFailed, nDuplicates atomic.Int64

	var wg sync.WaitGroup
	for range max(workers, 1) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				var host DNHost
				var ok bool
				select {
				case <-ctx.Done():
					return
				case host, ok = <-in:
					if !ok {
						return
					}
				}
				ip, err := resolve(ctx, host.Hostname)
				if err != nil {
					if ctx.Err() == nil {
						nFailed.Add(1)
						logger.Debugf("Cannot resolve %s: %v", host.Hostname, err)
					}
					continue
				}
				key := strings.ToLower(host.Hostname) + "|" + ip.String()
				mu.Lock()
				duplicate := seen[key]
				seen[key] = true
				mu.Unlock()
				if duplicate {
					nDuplicates.Add(1)
					continue
				}
				host.IP = ip
				select {
				case out <- host:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	wg.Wait()
	return int(nFailed.Load()), int(nDuplicates.Load())
}
