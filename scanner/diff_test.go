package scanner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// scanFile writes a JSONL scan with the given share records.
func scanFile(t *testing.T, name string, end bool, shares ...ShareRecord) string {
	t.Helper()
	var b strings.Builder
	line, _ := json.Marshal(ScanRecord{Type: RecordScan, ScanID: name, Time: sinkTime, Identity: "tester"})
	b.Write(append(line, '\n'))
	for _, s := range shares {
		s.Type, s.ScanID, s.Time = RecordShare, name, sinkTime
		if s.UNC == "" {
			s.UNC = UNC(s.Host, s.Share)
		}
		line, _ := json.Marshal(s)
		b.Write(append(line, '\n'))
	}
	if end {
		line, _ := json.Marshal(EndRecord{Type: RecordEnd, ScanID: name, Time: sinkTime})
		b.Write(append(line, '\n'))
	}
	path := filepath.Join(t.TempDir(), name+".jsonl")
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDiffScans(t *testing.T) {
	old := scanFile(t, "old", true,
		ShareRecord{Identity: "tester", Host: "10.0.0.5", Hostname: "FS01", Share: "Data", Read: true},
		ShareRecord{Identity: "guest", Host: "10.0.0.5", Hostname: "FS01", Share: "DATA", Read: true},
		ShareRecord{Identity: "tester", Host: "10.0.0.5", Hostname: "FS01", Share: "OLD", Read: true},
		// another host with the same NetBIOS name is another host
		ShareRecord{Identity: "tester", Host: "10.0.0.6", Hostname: "FS01", Share: "Data", Read: true},
	)
	newer := scanFile(t, "new", true,
		ShareRecord{Identity: "tester", Host: "10.0.0.5", Hostname: "FS01", Share: "DATA", Read: true, Write: true, WriteAccess: []string{"WRITE", "WRITE (SUBDIR)"}},
		ShareRecord{Identity: "guest", Host: "10.0.0.5", Hostname: "FS01", Share: "DATA", Read: true},
		// a resumed scan writes a share again: the last record wins
		ShareRecord{Identity: "tester", Host: "10.0.0.5", Hostname: "FS01", Share: "NEW", Partial: true},
		ShareRecord{Identity: "tester", Host: "10.0.0.5", Hostname: "FS01", Share: "NEW", Read: true},
		ShareRecord{Identity: "tester", Host: "10.0.0.6", Hostname: "FS01", Share: "Data", Read: true},
	)

	changes, err := DiffScans(old, newer)
	if err != nil {
		t.Fatal(err)
	}
	want := []ShareChange{
		{Kind: "new", Identity: "tester", UNC: "//10.0.0.5/NEW", New: "READ"},
		{Kind: "removed", Identity: "tester", UNC: "//10.0.0.5/OLD", Old: "READ"},
		{Kind: "changed", Identity: "tester", UNC: "//10.0.0.5/DATA", Old: "READ", New: "READ,WRITE,WRITE (SUBDIR)"},
	}
	if len(changes) != len(want) {
		t.Fatalf("changes = %+v, want %+v", changes, want)
	}
	for i := range want {
		if changes[i] != want[i] {
			t.Errorf("change %d = %+v, want %+v", i, changes[i], want[i])
		}
	}
}

// recordsFile writes a scan record and the given records as a JSONL file.
func recordsFile(t *testing.T, records ...any) string {
	t.Helper()
	var b strings.Builder
	b.WriteString(jsonLine(t, ScanRecord{Type: RecordScan, ScanID: "01J", Time: sinkTime, Identity: "tester"}))
	for _, r := range records {
		b.WriteString(jsonLine(t, r))
	}
	path := filepath.Join(t.TempDir(), "scan.jsonl")
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func hostRec(host string, shares ...string) HostRecord {
	return HostRecord{Type: RecordHost, Identity: "tester", Host: host, Shares: shares}
}

func shareRec(host, share string) ShareRecord {
	return ShareRecord{Type: RecordShare, Identity: "tester", Host: host, Share: share, UNC: UNC(host, share), Read: true}
}

// A retest that was stopped early must not present the shares it never
// checked as fixed.
func TestDiffScans_UncheckedSharesAreNotRemoved(t *testing.T) {
	old := recordsFile(t,
		hostRec("10.0.0.5", "DATA", "OLD"), shareRec("10.0.0.5", "DATA"), shareRec("10.0.0.5", "OLD"),
		hostRec("10.0.0.6", "HR", "IT"), shareRec("10.0.0.6", "HR"), shareRec("10.0.0.6", "IT"),
		EndRecord{Type: RecordEnd})
	// 10.0.0.5 still lists DATA (not checked before Ctrl+C) but no longer OLD;
	// 10.0.0.6 was not reached
	newer := recordsFile(t,
		hostRec("10.0.0.5", "DATA", "LOGS"), shareRec("10.0.0.5", "LOGS"),
		EndRecord{Type: RecordEnd, Interrupted: true})

	var changes []ShareChange
	logs := captureLog(t, func() {
		var err error
		if changes, err = DiffScans(old, newer); err != nil {
			t.Error(err)
		}
	})
	want := []ShareChange{
		{Kind: "new", Identity: "tester", UNC: "//10.0.0.5/LOGS", New: "READ"},
		{Kind: "removed", Identity: "tester", UNC: "//10.0.0.5/OLD", Old: "READ"},
		{Kind: "unchecked", Identity: "tester", UNC: "//10.0.0.5/DATA", Old: "READ"},
		{Kind: "unreached", Identity: "tester", UNC: "//10.0.0.6", Shares: 2},
	}
	if len(changes) != len(want) {
		t.Fatalf("changes = %+v, want %+v", changes, want)
	}
	for i := range want {
		if changes[i] != want[i] {
			t.Errorf("change %d = %+v, want %+v", i, changes[i], want[i])
		}
	}
	if !strings.Contains(logs, "was interrupted") {
		t.Errorf("an interrupted scan must be called out: %q", logs)
	}
}

func TestDiffScans_RefusesNonScanFiles(t *testing.T) {
	scan := scanFile(t, "ok", true)
	notes := filepath.Join(t.TempDir(), "notes.txt")
	if err := os.WriteFile(notes, []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := DiffScans(scan, notes); err == nil {
		t.Fatal("a file without a scan record must be refused")
	}
}

func TestDiffScans_WarnsAboutUnfinishedScans(t *testing.T) {
	old := scanFile(t, "old", true, ShareRecord{Identity: "tester", Host: "10.0.0.5", Share: "DATA", Read: true})
	cut := scanFile(t, "cut", false)
	out := captureLog(t, func() {
		changes, err := DiffScans(old, cut)
		if err != nil || len(changes) != 1 {
			t.Errorf("changes = %v, err = %v", changes, err)
		}
	})
	if !strings.Contains(out, "did not finish") {
		t.Fatalf("an unfinished scan must be called out, its missing shares are not removed: %q", out)
	}
}

func TestFormatDiff(t *testing.T) {
	if got := FormatDiff(nil); got != "No changes\n" {
		t.Fatalf("FormatDiff(nil) = %q", got)
	}
	changes := []ShareChange{
		{Kind: "new", Identity: "tester", UNC: "//10.0.0.5/NEW", New: "READ"},
		{Kind: "removed", Identity: "tester", UNC: "//10.0.0.5/OLD", Old: "READ"},
		{Kind: "changed", Identity: "tester", UNC: "//10.0.0.5/DATA", Old: "READ", New: "READ,WRITE"},
		{Kind: "removed", Identity: "tester", UNC: "//10.0.0.7/IPC$", Old: ""},
	}
	want := "New shares\n" +
		"+ //10.0.0.5/NEW  READ\n" +
		"\n" +
		"Removed shares\n" +
		"- //10.0.0.5/OLD  READ\n" +
		"- //10.0.0.7/IPC$  no access\n" +
		"\n" +
		"Permission changes\n" +
		"~ //10.0.0.5/DATA  READ -> READ,WRITE\n"
	if got := FormatDiff(changes); got != want {
		t.Fatalf("FormatDiff:\n%s\nwant\n%s", got, want)
	}

	notChecked := []ShareChange{
		{Kind: "unreached", Identity: "tester", UNC: "//10.0.0.6", Shares: 2},
		{Kind: "unchecked", Identity: "tester", UNC: "//10.0.0.5/DATA", Old: "READ"},
	}
	want = "Not checked in the new scan\n" +
		"? //10.0.0.5/DATA  READ\n" +
		"? //10.0.0.6  host not scanned, 2 shares\n"
	if got := FormatDiff(notChecked); got != want {
		t.Fatalf("FormatDiff:\n%s\nwant\n%s", got, want)
	}

	// changes seen as different identities say whose they are
	two := []ShareChange{
		{Kind: "new", Identity: "tester", UNC: "//10.0.0.5/NEW", New: "READ"},
		{Kind: "new", Identity: `CORP\jdoe`, UNC: "//10.0.0.5/NEW", New: "READ,WRITE"},
	}
	want = "New shares\n" +
		"+ //10.0.0.5/NEW  READ,WRITE  (as CORP\\jdoe)\n" +
		"+ //10.0.0.5/NEW  READ  (as tester)\n"
	if got := FormatDiff(two); got != want {
		t.Fatalf("FormatDiff:\n%s\nwant\n%s", got, want)
	}
}
