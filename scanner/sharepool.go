package scanner

import (
	"context"
	"sync"

	"github.com/jfjallid/go-smb/smb"
	"github.com/vflame6/sharefinder/logger"
)

// slots bounds the SMB connections in use at once (--threads): a host worker
// holds one, and each extra connection that lists shares of a host holds one.
type slots chan struct{}

// tryAcquire takes a slot only if one is free now; a nil slots has none.
func (sl slots) tryAcquire() bool {
	if sl == nil {
		return false
	}
	select {
	case sl <- struct{}{}:
		return true
	default:
		return false
	}
}

func (sl slots) release() { <-sl }

// shareJob is one share to list.
type shareJob struct {
	host  *Host
	share *Share
}

// shareConn is an SMB connection that lists shares.
type shareConn interface {
	WalkShare(ctx context.Context, share string, lim ListLimits, recurse bool,
		emit func(dir smb.SharedFile, depth int, entries []smb.SharedFile),
		onErr func(dir string, err error)) (walkStats, error)
	Close()
}

// listShares lists the shares of h and then finishes the host. The first
// connection, whose slot the host worker holds, takes jobs at once; up to
// --max-conns-per-host - 1 more connections are opened with open, each only
// while a slot is free, so busy scans never exceed --threads connections.
// Every job is finished, also after Ctrl+C (as partial).
func (s *Scanner) listShares(ctx context.Context, h *Host, jobs []shareJob, first shareConn, open func(context.Context) (shareConn, error)) {
	o := s.Options
	sink := s.sink()
	limits := ListLimits{MaxDepth: o.Depth, FollowLinks: o.FollowLinks, MaxFiles: o.MaxFiles}

	var mu sync.Mutex
	next := 0
	take := func() (shareJob, bool) {
		mu.Lock()
		defer mu.Unlock()
		if next == len(jobs) {
			return shareJob{}, false
		}
		next++
		return jobs[next-1], true
	}
	work := func(conn shareConn) {
		for job, ok := take(); ok; job, ok = take() {
			if ctx.Err() != nil {
				job.share.Partial = true
			} else {
				listShare(ctx, conn, sink, h, job.share, limits, o.Recurse, &s.Stats.Files)
			}
			sink.ShareFinished(h, job.share)
			s.Stats.Shares.Add(1)
		}
	}

	var wg sync.WaitGroup
	for extra := min(o.MaxConnsPerHost, len(jobs)) - 1; extra > 0 && s.slots.tryAcquire(); extra-- {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer s.slots.release()
			conn, err := open(ctx)
			if err != nil {
				if ctx.Err() == nil {
					logger.Debugf("Listing %s over one connection less: %v", h.IP, err)
				}
				return
			}
			defer conn.Close()
			work(conn)
		}()
	}
	work(first)
	wg.Wait()
	sink.HostFinished(h)
}
