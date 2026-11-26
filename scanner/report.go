package scanner

import (
	"bufio"
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/vflame6/sharefinder/logger"
)

// The HTML report is vendor.html (the libraries), report_head.html (styles
// and page skeleton), the scan as JSON blocks, and report_tail.html (the
// script that fills the page). Names, remarks and paths reach the page only as
// JSON data rendered as text, never as markup.
var (
	//go:embed report_head.html
	reportHead string
	//go:embed report_tail.html
	reportTail string
)

// ReadRecords calls fn with the type and raw bytes of each JSONL record in r.
// Lines that are not JSON records, such as the half line a killed scan leaves
// at the end, are skipped and counted in bad.
func ReadRecords(r io.Reader, fn func(typ string, raw []byte) error) (bad int, err error) {
	br := bufio.NewReaderSize(r, 64<<10)
	for {
		line, readErr := br.ReadBytes('\n')
		if line = bytes.TrimSpace(line); len(line) > 0 {
			var head struct {
				Type string `json:"type"`
			}
			if json.Unmarshal(line, &head) != nil || head.Type == "" {
				bad++
			} else if err := fn(head.Type, line); err != nil {
				return bad, err
			}
		}
		if errors.Is(readErr, io.EOF) {
			return bad, nil
		}
		if readErr != nil {
			return bad, readErr
		}
	}
}

// reportSummary is the sf-summary block: what ran and the summary cards.
type reportSummary struct {
	Version     string `json:"version"`
	Command     string `json:"command"`
	Identity    string `json:"identity"`
	ScanID      string `json:"scan_id"`
	Start       string `json:"start"`
	End         string `json:"end"`
	Complete    bool   `json:"complete"` // the end record was written
	Interrupted bool   `json:"interrupted"`
	Skipped     int    `json:"skipped"` // unreadable lines

	Targets       int `json:"targets"`
	Reachable     int `json:"reachable"`
	Authenticated int `json:"authenticated"`
	Failed        int `json:"failed"`

	Hosts    int `json:"hosts"`
	Shares   int `json:"shares"`
	Readable int `json:"readable"`
	Writable int `json:"writable"`
	Admin    int `json:"admin"`
	Files    int `json:"files"`
}

// report holds what the first pass over a JSONL file collects. Host and share
// rows are few; file rows are streamed in the second pass.
type report struct {
	scans   int
	summary reportSummary
	hosts   [][]any // ip, hostname, domain, os, signing, dialect, session, admin, shares
	shares  [][]any // host, hostname, share, remark, type, read, write, write access, files, notes
}

func (rep *report) collect(typ string, raw []byte) error {
	switch typ {
	case RecordScan:
		var rec ScanRecord
		if json.Unmarshal(raw, &rec) != nil {
			return nil
		}
		rep.scans++
		if rep.scans == 1 {
			s := &rep.summary
			s.Version, s.Command, s.Identity, s.ScanID, s.Start = rec.Version, rec.Command, rec.Identity, rec.ScanID, isoTime(rec.Time)
		}
	case RecordHost:
		var rec HostRecord
		if json.Unmarshal(raw, &rec) != nil {
			return nil
		}
		var admin any // unknown
		if rec.Admin != nil {
			admin = *rec.Admin
			if *rec.Admin {
				rep.summary.Admin++
			}
		}
		rep.hosts = append(rep.hosts, []any{rec.Host, rec.Hostname, rec.Domain, rec.OS, rec.Signing, rec.Dialect, rec.Session, admin, len(rec.Shares)})
	case RecordShare:
		var rec ShareRecord
		if json.Unmarshal(raw, &rec) != nil {
			return nil
		}
		if rec.Read {
			rep.summary.Readable++
		}
		if rec.Write {
			rep.summary.Writable++
		}
		rep.shares = append(rep.shares, []any{rec.Host, rec.Hostname, rec.Share, rec.Remark, rec.ShareType,
			rec.Read, rec.Write, strings.Join(rec.WriteAccess, "; "), rec.Files, shareNotes(rec)})
	case RecordFile:
		var rec struct {
			Kind string `json:"kind"`
		}
		if json.Unmarshal(raw, &rec) == nil && rec.Kind != "dir" {
			rep.summary.Files++
		}
	case RecordEnd:
		var rec EndRecord
		if json.Unmarshal(raw, &rec) != nil {
			return nil
		}
		s := &rep.summary
		s.Complete, s.Interrupted, s.End = true, rec.Interrupted, isoTime(rec.Time)
		s.Targets, s.Reachable, s.Authenticated, s.Failed = rec.Targets, rec.Reachable, rec.Authenticated, rec.Failed
	}
	return nil
}

// shareNotes says why a share's listing is incomplete.
func shareNotes(rec ShareRecord) string {
	var notes []string
	if rec.Truncated {
		notes = append(notes, "listing truncated (--max-files)")
	}
	if rec.Partial {
		notes = append(notes, "listing interrupted")
	}
	if rec.Error != "" {
		notes = append(notes, "listing failed: "+rec.Error)
	}
	return strings.Join(notes, "; ")
}

// isoTime formats t in UTC, or returns "" for the zero time.
func isoTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// uncPath returns the path inside the share of //host/share/path.
func uncPath(unc string) string {
	parts := strings.SplitN(strings.TrimPrefix(unc, "//"), "/", 3)
	if len(parts) < 3 {
		return ""
	}
	return parts[2]
}

// WriteReport renders the HTML report of a JSONL scan file to w. It reads the
// file twice: hosts, shares and counts first, then the file rows, which are
// streamed, so a listing of millions of files is never held in memory.
func WriteReport(jsonlPath string, w io.Writer) error {
	rep := &report{}
	bad, err := readRecordsFile(jsonlPath, rep.collect)
	if err != nil {
		return err
	}
	if rep.scans == 0 {
		return fmt.Errorf("%s is not a sharefinder JSONL file: it has no scan record", jsonlPath)
	}
	if bad > 0 {
		logger.Warnf("Skipped %d unreadable line(s) in %s", bad, jsonlPath)
	}
	rep.summary.Skipped = bad
	rep.summary.Hosts, rep.summary.Shares = len(rep.hosts), len(rep.shares)

	bw := bufio.NewWriterSize(w, 256<<10)
	_, _ = bw.WriteString(HTMLHeader)
	_, _ = bw.WriteString(reportHead)
	for _, block := range []struct {
		id   string
		data any
	}{{"sf-summary", rep.summary}, {"sf-hosts", nonNil(rep.hosts)}, {"sf-shares", nonNil(rep.shares)}} {
		data, err := json.Marshal(block.data) // escapes < > & so no data can close the script element
		if err != nil {
			return err
		}
		fmt.Fprintf(bw, "<script type=\"application/json\" id=\"%s\">%s</script>\n", block.id, data)
	}

	_, _ = bw.WriteString(`<script type="application/json" id="sf-files">[`)
	rows := 0
	if _, err := readRecordsFile(jsonlPath, func(typ string, raw []byte) error {
		if typ != RecordFile {
			return nil
		}
		var rec FileRecord
		if json.Unmarshal(raw, &rec) != nil || rec.Kind == "dir" {
			return nil
		}
		row, err := json.Marshal([]any{rec.Host, rec.Share, uncPath(rec.UNC), rec.Size, isoTime(rec.Modified), strings.Join(rec.Tags, ", ")})
		if err != nil {
			return err
		}
		if rows > 0 {
			_ = bw.WriteByte(',')
		}
		rows++
		_, err = bw.Write(row)
		return err
	}); err != nil {
		return err
	}
	_, _ = bw.WriteString("]</script>\n")
	_, _ = bw.WriteString(reportTail)
	return bw.Flush()
}

func readRecordsFile(path string, fn func(typ string, raw []byte) error) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	bad, err := ReadRecords(f, fn)
	if err != nil {
		return bad, fmt.Errorf("reading %s: %w", path, err)
	}
	return bad, nil
}

// nonNil keeps an empty table an empty JSON array rather than null.
func nonNil(rows [][]any) [][]any {
	if rows == nil {
		return [][]any{}
	}
	return rows
}
