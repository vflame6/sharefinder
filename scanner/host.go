package scanner

import (
	"context"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jfjallid/go-smb/dcerpc/mssrvs"
	"github.com/jfjallid/go-smb/smb"
	"github.com/vflame6/sharefinder/logger"
)

// sink returns the scan's outputs, or a sink that drops everything.
func (s *Scanner) sink() Sink {
	if s.Options.Sink == nil {
		return MultiSink{}
	}
	return s.Options.Sink
}

// processHost admits one target and enumerates it.
func (s *Scanner) processHost(ctx context.Context, target DNHost) {
	if host, ok := s.admit(ctx, target); ok {
		s.enumerateHost(ctx, host)
	}
}

// admit resolves a hostname target, applies --exclude-hosts and skips
// duplicates. A target that is not admitted is done.
func (s *Scanner) admit(ctx context.Context, target DNHost) (DNHost, bool) {
	host, ok, err := s.resolveTarget(ctx, target)
	if err != nil {
		s.Stats.Targets.Add(1)
		s.Stats.Done.Add(1)
		if ctx.Err() == nil {
			logger.Warnf("[-] %v", err)
		}
		return host, false
	}
	if !ok {
		s.Stats.Done.Add(1)
		logger.Debugf("Skipping %s: excluded or already scanned", host.Address())
		return host, false
	}
	if s.Options.Resume.HostDone(s.Options.Identity(), host.Address()) {
		s.Stats.Done.Add(1)
		s.Stats.Resumed.Add(1)
		logger.Debugf("Skipping %s: done in the resumed scan", host.Address())
		return host, false
	}
	s.Stats.Targets.Add(1)
	return host, true
}

// enumerateHost scans an admitted host and reports it through the sinks as it
// goes: the host and its share permissions first, then each share's listing,
// so no listing is held in memory.
func (s *Scanner) enumerateHost(ctx context.Context, host DNHost) {
	o := s.Options
	sink := s.sink()
	defer s.Stats.Done.Add(1)

	logger.Debugf("Trying to establish SMB connection to %s (%s)", host.Address(), host.Hostname)
	conn, err := NewSMBConnection(ctx, host, o)
	if err != nil {
		if classify(err) != StageConnect {
			s.Stats.Reachable.Add(1)
			s.Stats.Failed.Add(1)
		}
		if ctx.Err() == nil {
			reportHostError(host.Address(), err)
		}
		return
	}
	defer conn.Close()
	s.Stats.Reachable.Add(1)
	s.Stats.Authenticated.Add(1)
	logger.Debugf("Successfully established SMB connection to %s (%s)", host.Address(), host.Hostname)

	h := describeHost(conn, host, o)

	logger.Debugf("Trying to list shares on %s (%s)", host.Address(), host.Hostname)
	shares, err := conn.GetSharesList()
	if err != nil {
		// cut short by Ctrl+C: nothing is recorded, a resumed scan redoes it
		if ctx.Err() != nil {
			return
		}
		h.Error = "listing shares: " + err.Error()
		sink.HostEnumerated(h)
		sink.HostFinished(h)
		s.Stats.Failed.Add(1)
		reportHostError(host.Address(), &StageError{Stage: StageEnumerate, Host: host.Address(), Err: err})
		return
	}
	// every share a complete scan covers, also when Ctrl+C stops the checks
	// early: --resume takes the host for done only once all are recorded
	for _, share := range shares {
		if !slices.Contains(o.Exclude, share.Name) {
			h.Declared = append(h.Declared, share.Name)
		}
	}
	// shares the resumed scan finished are neither checked nor listed again
	if o.Resume != nil {
		identity := o.Identity()
		shares = slices.DeleteFunc(shares, func(share mssrvs.NetShare) bool {
			return o.Resume.ShareDone(identity, h.IP, share.Name)
		})
	}
	h.Shares = checkShares(ctx, conn, shares, o)
	sink.HostEnumerated(h)

	// shares that are not listed are finished now; listings are jobs that
	// may run over several connections
	var jobs []shareJob
	for i := range h.Shares {
		share := &h.Shares[i]
		if o.List && share.ReadPermission {
			jobs = append(jobs, shareJob{host: h, share: share})
			continue
		}
		sink.ShareFinished(h, share)
		s.Stats.Shares.Add(1)
	}
	open := func(ctx context.Context) (shareConn, error) {
		return NewSMBConnection(ctx, host, o)
	}
	s.listShares(ctx, h, jobs, conn, open)
}

// describeHost collects the facts of a connected host.
func describeHost(conn *Connection, host DNHost, o *Options) *Host {
	h := &Host{
		IP:      host.Address(),
		Time:    time.Now(),
		Version: "unknown",
		Signing: conn.session.IsSigningRequired(),
		Session: conn.SessionType,
	}
	if strings.Contains(host.Hostname, ".") {
		h.FQDN = host.Hostname
	}
	if info := conn.GetTargetInfo(); info != nil {
		if info.GuessedOSVersion != "" {
			h.Version = info.GuessedOSVersion
		}
		h.Hostname = info.NBComputerName
		h.Domain = info.DnsDomainName
	} else {
		// Kerberos auth doesn't provide NTLM target info
		h.Hostname = host.Hostname
		h.Domain = o.Domain
	}
	if !o.NullSession {
		isAdmin, adminErr := conn.CheckLocalAdmin()
		if adminErr != nil {
			// Access-denied is the common, expected case for non-admin sessions; keep it debug-only.
			logger.Debugf("Failed to determine local admin rights on %s: %v", h.IP, adminErr)
		} else {
			h.Admin = &isAdmin
			if isAdmin {
				version, versionErr := conn.DetectWindowsVersion(h.Version)
				if versionErr != nil {
					logger.Debugf("Failed to query registry version on %s: %v", h.IP, versionErr)
				} else {
					h.Version = version
				}
			}
		}
	}
	return h
}

// listShare lists a readable share within limits, sending each directory to
// the sink as it is listed and counting its files in files.
func listShare(ctx context.Context, conn shareConn, sink Sink, h *Host, share *Share, limits ListLimits, recurse bool, files *atomic.Int64) {
	share.Listed = true
	onErr := func(dir string, err error) {
		if ctx.Err() == nil {
			logger.Warnf("Failed to list directory %s\\%s\\%s: %v", h.IP, printable(share.ShareName), printable(dir), err)
		}
	}
	emit := listingEmitter(sink, h, share)
	counted := func(dir smb.SharedFile, depth int, entries []smb.SharedFile) {
		n := 0
		for _, e := range entries {
			if !e.IsDir {
				n++
			}
		}
		files.Add(int64(n))
		emit(dir, depth, entries)
	}
	stats, err := conn.WalkShare(ctx, share.ShareName, limits, recurse, counted, onErr)
	share.FileCount, share.DirCount, share.Truncated = stats.Files, stats.Dirs, stats.Truncated
	switch {
	case ctx.Err() != nil:
		share.Partial = true
	case err != nil:
		share.ListError = err.Error()
		logger.Warnf("Failed to list share %s\\%s: %v", h.IP, printable(share.ShareName), err)
	}
	if stats.Truncated {
		logger.Warnf("\\\\%s\\%s: listing truncated at %d entries (--max-files)", h.IP, printable(share.ShareName), limits.MaxFiles)
	}
	if stats.DepthLimited {
		logger.Warnf("\\\\%s\\%s: directories deeper than --depth %d were not listed", h.IP, printable(share.ShareName), limits.MaxDepth)
	}
}
