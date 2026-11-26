package scanner

import (
	"context"
	"sync"
)

// Producer sends scan targets to out. It must return when ctx is done.
type Producer func(ctx context.Context, out chan<- DNHost) error

// Run enumerates every target the producer sends with s.Threads workers.
//
// When ctx is cancelled (Ctrl+C) every connection the dialer handed out is
// closed, so in-flight hosts fail at once instead of being waited for; workers
// stop taking new targets and Run returns the cancellation cause. A producer
// error, or the AuthGuard tripping, stops the run the same way and is returned.
func (s *Scanner) Run(ctx context.Context, produce Producer) error {
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	// Registered after cancel so it is unregistered first: a run that ends
	// normally must not close the dialer for later phases.
	stop := context.AfterFunc(ctx, s.Options.Dialer.CloseAll)
	defer stop()

	// Too many rejected logons stop the whole run, not only the host.
	if guard := s.Options.AuthGuard; guard != nil {
		go func() {
			select {
			case <-guard.Done():
				cancel(guard.Err())
			case <-ctx.Done():
			}
		}()
	}

	if s.Options.Progress {
		stopProgress := s.startProgress()
		defer stopProgress()
	}

	// producer -> discovery sweep (its own large pool) -> SMB workers; with
	// --no-discovery every target goes straight to an SMB worker
	targets := make(chan DNHost, 256)
	queue, enumerate := (<-chan DNHost)(targets), s.processHost
	sweepDone := make(chan struct{})
	if s.Options.Discovery.Enabled {
		live := make(chan DNHost, 256)
		queue, enumerate = live, s.enumerateHost // the sweep admitted them
		go func() {
			defer close(sweepDone)
			s.sweep(ctx, targets, live)
			close(live)
		}()
	} else {
		close(sweepDone)
	}

	var wg sync.WaitGroup
	for i := 0; i < s.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.worker(ctx, queue, enumerate)
		}()
	}

	err := produce(ctx, targets)
	if err != nil && ctx.Err() == nil {
		cancel(err)
	}
	close(targets)
	wg.Wait()
	<-sweepDone

	if ctx.Err() != nil {
		return context.Cause(ctx)
	}
	return err
}

// worker enumerates hosts from queue until it is drained or ctx is done.
func (s *Scanner) worker(ctx context.Context, queue <-chan DNHost, enumerate func(context.Context, DNHost)) {
	for {
		select {
		case <-ctx.Done():
			return
		case host, ok := <-queue:
			if !ok {
				return
			}
			enumerate(ctx, host)
		}
	}
}
