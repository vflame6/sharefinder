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
