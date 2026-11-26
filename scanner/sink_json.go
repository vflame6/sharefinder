package scanner

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/vflame6/sharefinder/logger"
)

// jsonlSink writes one JSON record per line and flushes after every event, so
// whatever was written survives a killed process.
type jsonlSink struct {
	mu       sync.Mutex
	w        *bufio.Writer
	scanID   string
	identity string
	now      func() time.Time
	// seen reports a host whose record a resumed scan wrote already; nil
	// for a new scan
	seen func(identity, host string) bool
}

// ResumeJSONLSink continues the JSONL output of an interrupted scan on w: it
// writes no scan record, keeps the scan's id and does not record a host
// again.
func ResumeJSONLSink(w io.Writer, r *ResumeState, identity string) Sink {
	return &jsonlSink{w: bufio.NewWriterSize(w, 64<<10), scanID: r.ScanID, identity: identity, now: time.Now, seen: r.HostSeen}
}

// NewJSONLSink starts a JSONL output on w with the scan record.
func NewJSONLSink(w io.Writer, scan ScanRecord) Sink {
	s := &jsonlSink{w: bufio.NewWriterSize(w, 64<<10), scanID: scan.ScanID, identity: scan.Identity, now: time.Now}
	scan.Type = RecordScan
	if scan.Time.IsZero() {
		scan.Time = s.now()
	}
	s.write(scan)
	s.flush()
	return s
}

func (s *jsonlSink) write(record any) {
	line, err := json.Marshal(record)
	if err != nil {
		logger.Error(fmt.Errorf("encoding JSONL record: %w", err))
		return
	}
	_, _ = s.w.Write(line)
	_ = s.w.WriteByte('\n')
}

func (s *jsonlSink) flush() {
	if err := s.w.Flush(); err != nil {
		logger.Error(fmt.Errorf("writing JSONL output: %w", err))
	}
}

func (s *jsonlSink) HostEnumerated(h *Host) {
	if s.seen != nil && s.seen(s.identity, h.IP) {
		return
	}
	// the declared shares, so a host cut short by Ctrl+C lists the shares it
	// has not recorded yet
	shares := make([]string, 0, len(h.Shares))
	if h.Declared != nil {
		shares = append(shares, h.Declared...)
	} else {
		for _, share := range h.Shares {
			shares = append(shares, share.ShareName)
		}
	}
	record := HostRecord{
		Type: RecordHost, ScanID: s.scanID, Time: h.Time, Identity: s.identity,
		Host: h.IP, Hostname: h.Hostname, Domain: h.Domain, UNC: UNC(uncHost(h)),
		OS: h.Version, Signing: h.Signing, Session: h.Session, Admin: h.Admin, Shares: shares, Error: h.Error,
	}
	if record.Time.IsZero() {
		record.Time = s.now()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.write(record)
	s.flush()
}

func (s *jsonlSink) DirListed(h *Host, share *Share, dir Directory, depth int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	host := uncHost(h)
	for _, f := range dir.Files {
		s.write(FileRecord{
			Type: RecordFile, ScanID: s.scanID, Identity: s.identity, Host: h.IP, Share: share.ShareName,
			UNC: UNC(host, share.ShareName, dir.Name, f.Name), Kind: f.Type, Size: f.Size, Modified: f.LastModified,
			Tags: FileTags(f.Name),
		})
	}
	s.flush()
}

func (s *jsonlSink) ShareFinished(h *Host, share *Share) {
	var writeAccess []string
	if share.WriteAccess != "" {
		writeAccess = strings.Split(share.WriteAccess, ",")
	}
	record := ShareRecord{
		Type: RecordShare, ScanID: s.scanID, Time: s.now(), Identity: s.identity,
		Host: h.IP, Hostname: h.Hostname, Share: share.ShareName, UNC: UNC(uncHost(h), share.ShareName),
		Read: share.ReadPermission, Write: share.WritePermission, WriteAccess: writeAccess,
		Remark: share.Description, ShareType: share.ShareType, Listed: share.Listed,
		Files: share.FileCount, Dirs: share.DirCount, Truncated: share.Truncated, Partial: share.Partial, Error: share.ListError,
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.write(record)
	s.flush()
}

func (s *jsonlSink) HostFinished(*Host) {}

func (s *jsonlSink) Close(end EndRecord) error {
	end.Type, end.ScanID, end.Identity = RecordEnd, s.scanID, s.identity
	if end.Time.IsZero() {
		end.Time = s.now()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.write(end)
	return s.w.Flush()
}
