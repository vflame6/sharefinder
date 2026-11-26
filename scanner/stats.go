package scanner

import (
	"errors"
	"fmt"
	"sync/atomic"

	"github.com/vflame6/sharefinder/logger"
)

// Stats counts what happened to the targets of a scan.
type Stats struct {
	Total         atomic.Int64 // targets expected; 0 while unknown
	Done          atomic.Int64 // targets processed, skipped ones included
	Resumed       atomic.Int64 // hosts skipped: done in the resumed scan
	Targets       atomic.Int64 // targets taken up, after exclusions
	Reachable     atomic.Int64 // accepted a TCP connection on the SMB port
	Authenticated atomic.Int64 // accepted the identity
	Failed        atomic.Int64 // reachable, but negotiation, authentication or enumeration failed
	Shares        atomic.Int64 // shares finished
	Files         atomic.Int64 // entries listed
}

// SummaryLine is the count line printed at the end of a scan.
func (st *Stats) SummaryLine() string {
	return fmt.Sprintf("Summary: %d targets, %d reachable, %d authenticated, %d failed",
		st.Targets.Load(), st.Reachable.Load(), st.Authenticated.Load(), st.Failed.Load())
}

// endRecord closes the JSONL output with the scan's counts.
func (s *Scanner) endRecord() EndRecord {
	return EndRecord{
		Time:          s.TimeEnd,
		Targets:       int(s.Stats.Targets.Load()),
		Reachable:     int(s.Stats.Reachable.Load()),
		Authenticated: int(s.Stats.Authenticated.Load()),
		Failed:        int(s.Stats.Failed.Load()),
		Interrupted:   s.Interrupted,
		Error:         s.StopReason,
	}
}

// classify tells which stage an error belongs to; errors without a stage,
// such as a refused or timed-out dial, are connection failures.
func classify(err error) Stage {
	var stageErr *StageError
	if errors.As(err, &stageErr) {
		return stageErr.Stage
	}
	return StageConnect
}

// reportHostError prints a host's failure with an honest label. Unreachable
// hosts are only shown with --debug: on a sparse network they are most of the
// targets.
func reportHostError(host string, err error) {
	reason := err
	var stageErr *StageError
	if errors.As(err, &stageErr) {
		reason = stageErr.Err
	}
	switch stage := classify(err); stage {
	case StageConnect:
		logger.Debugf("[-] %s: connection failed: %v", host, reason)
	default:
		logger.Warnf("[-] %s: %s failed: %v", host, stage, reason)
	}
}
