package scanner

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ResumeState is what an interrupted JSONL scan already finished. Its
// methods are safe on a nil *ResumeState, which has finished nothing.
type ResumeState struct {
	ScanID  string // records appended on resume keep it
	Command string // the interrupted scan's command, credentials masked

	hosts map[resumeHost][]string // shares each host record declared
	done  map[resumeShare]bool    // shares with a finished share record
}

type resumeHost struct{ identity, host string }

type resumeShare struct{ identity, host, share string }

func newResumeHost(identity, host string) resumeHost {
	return resumeHost{identity, strings.ToLower(host)}
}

func newResumeShare(identity, host, share string) resumeShare {
	return resumeShare{identity, strings.ToLower(host), strings.ToLower(share)}
}

// LoadResume reads the JSONL file of an interrupted scan and compacts it for
// appending: the records of shares that were not finished (their file records
// and partial share records), end records and unreadable lines are removed,
// so the resumed scan writes each share once.
func LoadResume(path string) (*ResumeState, error) {
	r := &ResumeState{hosts: make(map[resumeHost][]string), done: make(map[resumeShare]bool)}
	scans := 0
	if _, err := readRecordsFile(path, func(typ string, raw []byte) error {
		switch typ {
		case RecordScan:
			var rec ScanRecord
			if json.Unmarshal(raw, &rec) == nil {
				if scans++; scans == 1 {
					r.ScanID, r.Command = rec.ScanID, rec.Command
				}
			}
		case RecordHost:
			var rec HostRecord
			if json.Unmarshal(raw, &rec) == nil {
				r.hosts[newResumeHost(rec.Identity, rec.Host)] = rec.Shares
			}
		case RecordShare:
			var rec ShareRecord
			if json.Unmarshal(raw, &rec) == nil && !rec.Partial {
				r.done[newResumeShare(rec.Identity, rec.Host, rec.Share)] = true
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}
	if scans == 0 {
		return nil, fmt.Errorf("%s cannot be resumed: it is not a sharefinder JSONL file (no scan record)", path)
	}
	if err := r.compact(path); err != nil {
		return nil, fmt.Errorf("compacting %s: %w", path, err)
	}
	return r, nil
}

// compact rewrites path without what the resumed scan writes again.
func (r *ResumeState) compact(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".sharefinder-resume-*.jsonl")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // a no-op once renamed
	defer tmp.Close()

	bw := bufio.NewWriterSize(tmp, 256<<10)
	if _, err := readRecordsFile(path, func(typ string, raw []byte) error {
		keep := true
		switch typ {
		case RecordEnd:
			keep = false
		case RecordShare:
			var rec ShareRecord
			keep = json.Unmarshal(raw, &rec) == nil && !rec.Partial
		case RecordFile:
			var rec FileRecord
			keep = json.Unmarshal(raw, &rec) == nil && r.done[newResumeShare(rec.Identity, rec.Host, rec.Share)]
		}
		if keep {
			_, _ = bw.Write(raw)
			_ = bw.WriteByte('\n')
		}
		return nil
	}); err != nil {
		return err
	}
	if err := bw.Flush(); err != nil {
		return err
	}
	if err := tmp.Chmod(info.Mode().Perm()); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// HostDone reports whether the scan recorded host and finished every share
// the host declared: the resumed scan does not contact it.
func (r *ResumeState) HostDone(identity, host string) bool {
	if r == nil {
		return false
	}
	shares, ok := r.hosts[newResumeHost(identity, host)]
	if !ok {
		return false
	}
	for _, share := range shares {
		if !r.ShareDone(identity, host, share) {
			return false
		}
	}
	return true
}

// ShareDone reports whether the scan finished share: the resumed scan
// neither checks its permissions nor lists it.
func (r *ResumeState) ShareDone(identity, host, share string) bool {
	return r != nil && r.done[newResumeShare(identity, host, share)]
}

// HostSeen reports whether the scan wrote a host record for host, which the
// resumed scan then does not write again.
func (r *ResumeState) HostSeen(identity, host string) bool {
	if r == nil {
		return false
	}
	_, ok := r.hosts[newResumeHost(identity, host)]
	return ok
}
