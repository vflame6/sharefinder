package scanner

import (
	"io"
	"strings"
	"sync"
	"unicode"

	"github.com/vflame6/sharefinder/logger"
)

// uncSink writes //host/share for each readable disk share, one per line, for
// content scanners that take direct UNC paths. Each line is written as its
// share finishes.
type uncSink struct {
	mu   sync.Mutex
	w    io.Writer
	seen map[string]bool // lower-cased: share and host names are case-insensitive
	err  error           // the first write error, returned by Close
}

// NewUNCSink starts a UNC list on w.
func NewUNCSink(w io.Writer) Sink {
	return &uncSink{w: w, seen: make(map[string]bool)}
}

func (s *uncSink) HostEnumerated(*Host)                    {}
func (s *uncSink) DirListed(*Host, *Share, Directory, int) {}
func (s *uncSink) HostFinished(*Host)                      {}

func (s *uncSink) ShareFinished(h *Host, share *Share) {
	// printers, devices and IPC$ hold no files to scan
	if !share.ReadPermission || (share.ShareType != "" && share.ShareType != "disk") {
		return
	}
	unc := UNC(uncHost(h), share.ShareName)
	if strings.IndexFunc(unc, unicode.IsControl) >= 0 {
		// a line break in a server-supplied name would add a line of its
		// choosing to the list
		logger.Warnf("Not adding %s to the UNC list: the name has control characters", printable(unc))
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := strings.ToLower(unc)
	if s.seen[key] {
		return
	}
	s.seen[key] = true
	if _, err := io.WriteString(s.w, unc+"\n"); err != nil && s.err == nil {
		s.err = err
	}
}

func (s *uncSink) Close(EndRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}
