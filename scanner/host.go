package scanner

import (
	"context"
	"strings"
	"sync/atomic"
	"time"

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

// processHost scans one target and reports it through the sinks as it goes:
// the host and its share permissions first, then each share's listing, so no
// listing is held in memory.
func (s *Scanner) processHost(ctx context.Context, target DNHost) {
	o := s.Options
	sink := s.sink()
	defer s.Stats.Done.Add(1)

	// resolve hostnames, apply --exclude-hosts and skip duplicates
	host, ok, err := s.resolveTarget(ctx, target)
	if err != nil {
		s.Stats.Targets.Add(1)
		if ctx.Err() == nil {
			logger.Warnf("[-] %v", err)
		}
		return
	}
	if !ok {
		logger.Debugf("Skipping %s: excluded or already scanned", host.Address())
		return
	}
	s.Stats.Targets.Add(1)

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
		sink.HostEnumerated(h)
		sink.HostFinished(h)
		s.Stats.Failed.Add(1)
		if ctx.Err() == nil {
			reportHostError(host.Address(), &StageError{Stage: StageEnumerate, Host: host.Address(), Err: err})
		}
		return
	}
	h.Shares = checkShares(ctx, conn, shares, o)
	sink.HostEnumerated(h)

	limits := ListLimits{MaxDepth: o.Depth, FollowLinks: o.FollowLinks, MaxFiles: o.MaxFiles}
	for i := range h.Shares {
		share := &h.Shares[i]
		if o.List && share.ReadPermission {
			if ctx.Err() != nil {
				share.Partial = true
			} else {
				listShare(ctx, conn, sink, h, share, limits, o.Recurse, &s.Stats.Files)
			}
		}
		sink.ShareFinished(h, share)
		s.Stats.Shares.Add(1)
	}
	sink.HostFinished(h)
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
func listShare(ctx context.Context, conn *Connection, sink Sink, h *Host, share *Share, limits ListLimits, recurse bool, files *atomic.Int64) {
	share.Listed = true
	onErr := func(dir string, err error) {
		if ctx.Err() == nil {
			logger.Warnf("Failed to list directory %s\\%s\\%s: %v", conn.host, share.ShareName, dir, err)
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
		logger.Warnf("Failed to list share %s\\%s: %v", conn.host, share.ShareName, err)
	}
	if stats.Truncated {
		logger.Warnf("\\\\%s\\%s: listing truncated at %d entries (--max-files)", conn.host, share.ShareName, limits.MaxFiles)
	}
	if stats.DepthLimited {
		logger.Warnf("\\\\%s\\%s: directories deeper than --depth %d were not listed", conn.host, share.ShareName, limits.MaxDepth)
	}
}
