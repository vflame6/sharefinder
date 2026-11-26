package scanner

import (
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/vflame6/sharefinder/logger"
)

// progressInterval is how often the progress line is redrawn.
const progressInterval = 500 * time.Millisecond

// ProgressLine is the status line shown on a terminal during a scan.
func (st *Stats) ProgressLine(elapsed time.Duration) string {
	targets := strconv.FormatInt(st.Done.Load(), 10)
	if total := st.Total.Load(); total > 0 {
		targets += "/" + strconv.FormatInt(total, 10)
	}
	return fmt.Sprintf("[*] %s  targets %s  reachable %d  shares %d  files %d",
		elapsed.Round(time.Second), targets, st.Reachable.Load(), st.Shares.Load(), st.Files.Load())
}

// startProgress keeps the progress line at the bottom of stderr until the
// returned stop function is called; stop erases it.
func (s *Scanner) startProgress() (stop func()) {
	start := s.TimeStart
	if start.IsZero() {
		start = time.Now()
	}
	logger.SetStatus(func() string { return s.Stats.ProgressLine(time.Since(start)) })

	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(progressInterval)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				logger.RedrawStatus()
			}
		}
	}()
	return func() {
		close(done)
		wg.Wait()
		logger.ClearStatus()
	}
}
