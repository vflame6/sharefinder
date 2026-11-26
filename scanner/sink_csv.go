package scanner

import (
	"encoding/csv"
	"io"
	"strconv"
	"strings"
	"sync"
)

// csvHeader names the columns of --output-csv.
var csvHeader = []string{"identity", "host", "hostname", "share", "unc", "read", "write", "write_access", "remark"}

// csvSink writes one row per share, for client deliverables. Each row is
// flushed as its share finishes.
type csvSink struct {
	mu       sync.Mutex
	w        *csv.Writer
	identity string
	err      error // the first write error, returned by Close
}

// NewCSVSink starts a CSV output on w with its header row. identity fills the
// identity column: who the scan logged on as.
func NewCSVSink(w io.Writer, identity string) Sink {
	s := &csvSink{w: csv.NewWriter(w), identity: identity}
	s.writeRow(csvHeader)
	return s
}

func (s *csvSink) writeRow(row []string) {
	if err := s.w.Write(row); err != nil && s.err == nil {
		s.err = err
	}
	s.w.Flush()
	if err := s.w.Error(); err != nil && s.err == nil {
		s.err = err
	}
}

// csvCell keeps a spreadsheet from running a cell as a formula: share names,
// remarks and host names come from the scanned servers, so a cell starting
// with = + - @ tab or carriage return gets a leading apostrophe.
func csvCell(s string) string {
	if s != "" && strings.IndexByte("=+-@\t\r", s[0]) >= 0 {
		return "'" + s
	}
	return s
}

func (s *csvSink) HostEnumerated(*Host)                    {}
func (s *csvSink) DirListed(*Host, *Share, Directory, int) {}
func (s *csvSink) HostFinished(*Host)                      {}

func (s *csvSink) ShareFinished(h *Host, share *Share) {
	identity := s.identity
	if h.Identity != "" {
		identity = h.Identity // a matrix reports each identity
	}
	row := []string{
		identity, h.IP, h.Hostname, share.ShareName, UNC(uncHost(h), share.ShareName),
		strconv.FormatBool(share.ReadPermission), strconv.FormatBool(share.WritePermission),
		strings.ReplaceAll(share.WriteAccess, ",", ";"), share.Description,
	}
	for i := range row {
		row[i] = csvCell(row[i])
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.writeRow(row)
}

func (s *csvSink) Close(EndRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}
