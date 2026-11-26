package scanner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func jsonLine(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b) + "\n"
}

// resumeFixture is a scan killed while listing: host A finished with two
// shares; host B finished share X, was listing Y (3 file records, no share
// record) and had Z cut short by Ctrl+C (a partial share record).
func resumeFixture(t *testing.T) string {
	t.Helper()
	id := "01JRESUME"
	file := func(host, share, name string) FileRecord {
		return FileRecord{Type: RecordFile, ScanID: id, Identity: "tester", Host: host, Share: share, UNC: UNC(host, share, name), Kind: "file"}
	}
	var b strings.Builder
	b.WriteString(jsonLine(t, ScanRecord{Type: RecordScan, ScanID: id, Time: sinkTime, Command: "--output-json scan auth 10.0.0.0/30 -u tester -p ***", Identity: "tester"}))
	b.WriteString(jsonLine(t, HostRecord{Type: RecordHost, ScanID: id, Identity: "tester", Host: "10.0.0.1", Shares: []string{"S1", "S2"}}))
	b.WriteString(jsonLine(t, file("10.0.0.1", "S1", "a.txt")))
	b.WriteString(jsonLine(t, ShareRecord{Type: RecordShare, ScanID: id, Identity: "tester", Host: "10.0.0.1", Share: "S1", Read: true, Listed: true, Files: 1}))
	b.WriteString(jsonLine(t, ShareRecord{Type: RecordShare, ScanID: id, Identity: "tester", Host: "10.0.0.1", Share: "S2"}))
	b.WriteString(jsonLine(t, HostRecord{Type: RecordHost, ScanID: id, Identity: "tester", Host: "10.0.0.2", Shares: []string{"X", "Y", "Z"}}))
	b.WriteString(jsonLine(t, ShareRecord{Type: RecordShare, ScanID: id, Identity: "tester", Host: "10.0.0.2", Share: "X", Read: true}))
	for _, name := range []string{"y1", "y2", "y3"} {
		b.WriteString(jsonLine(t, file("10.0.0.2", "Y", name)))
	}
	b.WriteString(jsonLine(t, file("10.0.0.2", "Z", "z1")))
	b.WriteString(jsonLine(t, ShareRecord{Type: RecordShare, ScanID: id, Identity: "tester", Host: "10.0.0.2", Share: "Z", Read: true, Partial: true}))
	b.WriteString(jsonLine(t, EndRecord{Type: RecordEnd, ScanID: id, Identity: "tester", Interrupted: true}))
	b.WriteString(`{"type":"file","scan_id":"01JRESUME","identity":"tester","host":"10.0.0.2","sha`)

	path := filepath.Join(t.TempDir(), "scan.jsonl")
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadResume_CompactsPartialShares(t *testing.T) {
	path := resumeFixture(t)
	r, err := LoadResume(path)
	if err != nil {
		t.Fatal(err)
	}
	if r.ScanID != "01JRESUME" || !strings.Contains(r.Command, "auth 10.0.0.0/30") {
		t.Fatalf("scan id %q, command %q", r.ScanID, r.Command)
	}
	if !r.HostDone("tester", "10.0.0.1") || r.HostDone("tester", "10.0.0.2") {
		t.Error("A is done, B is not")
	}
	if !r.ShareDone("tester", "10.0.0.2", "X") || r.ShareDone("tester", "10.0.0.2", "Y") || r.ShareDone("tester", "10.0.0.2", "Z") {
		t.Error("B's share X is done, Y and Z are not")
	}
	if !r.HostSeen("tester", "10.0.0.2") || r.HostSeen("tester", "10.0.0.3") {
		t.Error("B has a host record, 10.0.0.3 has none")
	}
	if r.HostDone("other", "10.0.0.1") || r.HostSeen("other", "10.0.0.1") {
		t.Error("another identity has not scanned anything")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	bad, _ := ReadRecords(strings.NewReader(string(data)), func(typ string, raw []byte) error {
		counts[typ]++
		return nil
	})
	if bad != 0 || !strings.HasSuffix(string(data), "\n") {
		t.Errorf("the half line must be gone: %d bad lines", bad)
	}
	// kept: scan, 2 hosts, A's S1 file, S1, S2, X; dropped: Y's and Z's files,
	// Z's partial record, the end record of the interrupted run
	want := map[string]int{"scan": 1, "host": 2, "file": 1, "share": 3}
	for typ, n := range want {
		if counts[typ] != n {
			t.Errorf("%s records after compaction = %d, want %d (all: %v)", typ, counts[typ], n, counts)
		}
	}
	if counts["end"] != 0 {
		t.Errorf("the interrupted run's end record must go: %v", counts)
	}
	if strings.Contains(string(data), `"y1"`) || strings.Contains(string(data), "z1") {
		t.Error("file records of unfinished shares must go")
	}
}

func TestLoadResume_FailedHostsAreScannedAgain(t *testing.T) {
	var b strings.Builder
	b.WriteString(jsonLine(t, ScanRecord{Type: RecordScan, ScanID: "01J", Identity: "tester"}))
	b.WriteString(jsonLine(t, HostRecord{Type: RecordHost, ScanID: "01J", Identity: "tester", Host: "10.0.0.1", Shares: []string{}, Error: "listing shares: access denied"}))
	path := filepath.Join(t.TempDir(), "scan.jsonl")
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	r, err := LoadResume(path)
	if err != nil {
		t.Fatal(err)
	}
	if r.HostDone("tester", "10.0.0.1") || r.HostSeen("tester", "10.0.0.1") {
		t.Fatal("a host whose shares could not be listed is not done, and its new record must be written")
	}
	if data, _ := os.ReadFile(path); strings.Contains(string(data), `"type":"host"`) {
		t.Fatalf("its failed record is dropped: %s", data)
	}
}

func TestLoadResume_RefusesNonScanFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notes.jsonl")
	if err := os.WriteFile(path, []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadResume(path); err == nil {
		t.Fatal("a file without a scan record cannot be resumed")
	}
	if data, _ := os.ReadFile(path); string(data) != "hello\n" {
		t.Fatalf("a refused file must be left alone: %q", data)
	}
}
