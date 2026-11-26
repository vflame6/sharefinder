package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jfjallid/go-smb/smb"
)

var (
	sinkTime  = time.Date(2026, 11, 26, 10, 0, 0, 0, time.UTC)
	sinkMtime = time.Date(2026, 11, 25, 21, 34, 51, 0, time.UTC)
)

func jsonLines(t *testing.T, data string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(data), "\n") {
		if !json.Valid([]byte(line)) {
			t.Fatalf("invalid JSONL line: %q", line)
		}
		var m map[string]any
		_ = json.Unmarshal([]byte(line), &m)
		out = append(out, m)
	}
	return out
}

func newTestJSONLSink(buf *bytes.Buffer) Sink {
	sink := NewJSONLSink(buf, ScanRecord{ScanID: "01JDK4", Time: sinkTime, Version: "test", Command: "auth", Identity: `CORP\jdoe`})
	sink.(*jsonlSink).now = func() time.Time { return sinkTime }
	return sink
}

func TestJSONLSink_ShareRecord(t *testing.T) {
	var buf bytes.Buffer
	sink := newTestJSONLSink(&buf)
	h := &Host{IP: "10.0.0.5", Hostname: "FS01", Time: sinkTime}
	sink.ShareFinished(h, &Share{ShareName: "Data", Description: "Department data", ReadPermission: true, WritePermission: true})

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("want a scan record and a share record, got %q", buf.String())
	}
	// the roadmap's proposed share record, with the UNC host rule: FQDN when known, else IP
	want := `{"type":"share","scan_id":"01JDK4","time":"2026-11-26T10:00:00Z","identity":"CORP\\jdoe","host":"10.0.0.5","hostname":"FS01","share":"Data","unc":"//10.0.0.5/Data","read":true,"write":true,"remark":"Department data"}`
	if lines[1] != want {
		t.Fatalf("share record:\n%s\nwant\n%s", lines[1], want)
	}
	if scan := jsonLines(t, lines[0])[0]; scan["type"] != "scan" || scan["scan_id"] != "01JDK4" {
		t.Fatalf("first line must be the scan record: %q", lines[0])
	}
}

func TestJSONLSink_HostFileAndEndRecords(t *testing.T) {
	var buf bytes.Buffer
	sink := newTestJSONLSink(&buf)
	admin := false
	h := &Host{IP: "10.0.0.5", Hostname: "FS01", FQDN: "fs01.corp.local", Domain: "corp.local", Version: "Windows Server 2022", Signing: true, Session: "user", Admin: &admin, Time: sinkTime,
		Shares: []Share{{ShareName: "Data", ReadPermission: true, WritePermission: true, WriteAccess: "WRITE (SUBDIR),WRITE (ACL)", ShareType: "disk"}}}
	sink.HostEnumerated(h)
	sink.DirListed(h, &h.Shares[0], Directory{Name: "IT", Files: []File{{Type: "file", Name: "web.config", Size: 109, LastModified: sinkMtime}}}, 1)
	if err := sink.Close(EndRecord{Time: sinkTime, Targets: 1, Reachable: 1, Authenticated: 1}); err != nil {
		t.Fatal(err)
	}

	records := jsonLines(t, buf.String())
	if len(records) != 4 {
		t.Fatalf("want scan, host, file and end records, got %d: %s", len(records), buf.String())
	}
	host, file, end := records[1], records[2], records[3]
	if host["type"] != "host" || host["unc"] != "//fs01.corp.local" || host["os"] != "Windows Server 2022" || host["session"] != "user" || host["admin"] != false {
		t.Errorf("host record: %v", host)
	}
	if shares, _ := host["shares"].([]any); len(shares) != 1 || shares[0] != "Data" {
		t.Errorf("host record must list its shares: %v", host["shares"])
	}
	wantFile := map[string]any{"type": "file", "scan_id": "01JDK4", "identity": `CORP\jdoe`, "host": "10.0.0.5", "share": "Data",
		"unc": "//fs01.corp.local/Data/IT/web.config", "kind": "file", "size": float64(109), "modified": "2026-11-25T21:34:51Z"}
	for k, v := range wantFile {
		if file[k] != v {
			t.Errorf("file record %s = %v, want %v", k, file[k], v)
		}
	}
	if tags, _ := file["tags"].([]any); len(tags) != 1 || tags[0] != "config" {
		t.Errorf("file tags = %v", file["tags"])
	}
	if end["type"] != "end" || end["targets"] != float64(1) || end["scan_id"] != "01JDK4" {
		t.Errorf("end record: %v", end)
	}
}

func TestJSONLSink_ShareWriteAccessList(t *testing.T) {
	var buf bytes.Buffer
	sink := newTestJSONLSink(&buf)
	sink.ShareFinished(&Host{IP: "10.0.0.5"}, &Share{ShareName: "Drop", WritePermission: true, WriteAccess: "WRITE (SUBDIR),WRITE (ACL)", ShareType: "disk",
		Listed: true, FileCount: 3, DirCount: 1, Truncated: true, Partial: true, ListError: "access denied"})
	share := jsonLines(t, buf.String())[1]
	if wa, _ := share["write_access"].([]any); len(wa) != 2 || wa[0] != "WRITE (SUBDIR)" || wa[1] != "WRITE (ACL)" {
		t.Errorf("write_access = %v", share["write_access"])
	}
	for k, v := range map[string]any{"share_type": "disk", "listed": true, "files": float64(3), "dirs": float64(1), "truncated": true, "partial": true, "error": "access denied"} {
		if share[k] != v {
			t.Errorf("share %s = %v, want %v", k, share[k], v)
		}
	}
}

func TestXMLSink_MatchesLegacyShape(t *testing.T) {
	rootFiles := []File{
		{Type: "dir", Name: "IT", LastModified: sinkMtime},
		{Type: "file", Name: "readme.txt", Size: 5, LastModified: sinkMtime},
	}
	itFiles := []File{{Parent: "IT", Type: "file", Name: "web.config", Size: 109, LastModified: sinkMtime}}
	admin := true
	facts := Host{Time: sinkTime, IP: "10.0.0.5", Version: "Windows", Hostname: "FS01", Domain: "corp.local", Signing: true, Session: "user", Admin: &admin}

	legacyHost := facts
	legacyHost.Shares = []Share{
		{ShareName: "Data", Description: "Department data", ReadPermission: true, WritePermission: true, WriteAccess: "WRITE",
			Files: rootFiles, Directories: []Directory{{Name: "IT", LastModified: sinkMtime, Files: itFiles}}},
		{ShareName: "Public", ReadPermission: true},
	}
	var legacy bytes.Buffer
	if err := NewOutputWriter().WriteXMLHost(legacyHost, &legacy); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	sink := NewXMLSink(&out, t.TempDir())
	h := facts
	h.Shares = []Share{
		{ShareName: "Data", Description: "Department data", ReadPermission: true, WritePermission: true, WriteAccess: "WRITE"},
		{ShareName: "Public", ReadPermission: true},
	}
	sink.HostEnumerated(&h)
	sink.DirListed(&h, &h.Shares[0], Directory{Files: rootFiles}, 0)
	sink.DirListed(&h, &h.Shares[0], Directory{Name: "IT", LastModified: sinkMtime, Files: itFiles}, 1)
	sink.ShareFinished(&h, &h.Shares[0])
	sink.ShareFinished(&h, &h.Shares[1])
	sink.HostFinished(&h)

	if out.String() != legacy.String() {
		t.Fatalf("XML host element:\n%s\nwant (legacy)\n%s", out.String(), legacy.String())
	}
	if err := sink.Close(EndRecord{Time: sinkTime}); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(out.String(), "</SharefinderRun>") {
		t.Fatalf("Close must write the footer: %q", out.String())
	}
}

func TestXMLSink_CloseWritesUnfinishedHosts(t *testing.T) {
	var out bytes.Buffer
	sink := NewXMLSink(&out, t.TempDir())
	h := &Host{IP: "10.0.0.5", Time: sinkTime, Shares: []Share{{ShareName: "Data", ReadPermission: true}}}
	sink.HostEnumerated(h)
	sink.DirListed(h, &h.Shares[0], Directory{Files: []File{{Type: "file", Name: "a.txt"}}}, 0)
	// Ctrl+C: the host never finishes
	if err := sink.Close(EndRecord{Time: sinkTime}); err != nil {
		t.Fatal(err)
	}
	doc := `<?xml version="1.0" encoding="UTF-8"?><SharefinderRun><hosts>` + out.String()
	run, err := ParseSharefinderRun([]byte(doc))
	if err != nil {
		t.Fatalf("XML after an interrupted host does not parse: %v\n%s", err, doc)
	}
	if len(run.Hosts) != 1 || len(run.Hosts[0].Shares[0].Files) != 1 {
		t.Fatalf("the interrupted host and its listing must be kept: %+v", run.Hosts)
	}
}

func TestTextBlock_EscapesControlChars(t *testing.T) {
	var file bytes.Buffer
	console := captureLog(t, func() {
		sink := NewTextSink(&file)
		h := &Host{IP: "10.0.0.5", Hostname: "FS\x1b[31m01", Shares: []Share{{ShareName: "Data", Description: "evil\r\nremark", ReadPermission: true}}}
		sink.HostEnumerated(h)
		sink.DirListed(h, &h.Shares[0], Directory{Files: []File{{Type: "file", Name: "a\nb"}}}, 0)
	})
	for name, out := range map[string]string{"console": console, "file": file.String()} {
		if !strings.Contains(out, `a\x0ab`) || strings.Contains(out, "a\nb") {
			t.Errorf("%s: a newline in a file name must be escaped: %q", name, out)
		}
		if strings.Contains(out, "\x1b") || strings.Contains(out, "\r") {
			t.Errorf("%s: control characters from the server must be escaped: %q", name, out)
		}
		if !strings.Contains(out, `Listing share \\10.0.0.5\Data`) && !strings.Contains(out, `Listing share 10.0.0.5\Data`) {
			t.Errorf("%s: missing listing header: %q", name, out)
		}
	}
}

// lazyLister invents a share of dirs directories with files files each,
// without holding the tree in memory.
type lazyLister struct{ dirs, files int }

func (l lazyLister) ListDirectory(share, dir, pattern string) ([]smb.SharedFile, error) {
	if dir == "" {
		entries := make([]smb.SharedFile, l.dirs)
		for i := range entries {
			name := fmt.Sprintf("dir%04d", i)
			entries[i] = smb.SharedFile{Name: name, FullPath: name, IsDir: true}
		}
		return entries, nil
	}
	entries := make([]smb.SharedFile, l.files)
	for i := range entries {
		name := fmt.Sprintf("file%05d.docx", i)
		entries[i] = smb.SharedFile{Name: name, FullPath: dir + `\` + name, Size: uint64(i)}
	}
	return entries, nil
}

func TestWalk_FlatMemory(t *testing.T) {
	if testing.Short() {
		t.Skip("allocates a million records")
	}
	sink := NewJSONLSink(io.Discard, ScanRecord{ScanID: NewScanID()})
	h := &Host{IP: "10.0.0.5", Shares: []Share{{ShareName: "Huge", ReadPermission: true}}}
	share := &h.Shares[0]

	var peak uint64
	var ms runtime.MemStats
	emit := listingEmitter(sink, h, share)
	listed := 0
	stats, err := walkShare(context.Background(), lazyLister{dirs: 1000, files: 1000}, "Huge", ListLimits{MaxDepth: 5}, true,
		func(dir smb.SharedFile, depth int, entries []smb.SharedFile) {
			emit(dir, depth, entries)
			if listed++; listed%100 == 0 {
				runtime.GC()
				runtime.ReadMemStats(&ms)
				if ms.HeapInuse > peak {
					peak = ms.HeapInuse
				}
			}
		}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Files != 1_000_000 {
		t.Fatalf("walked %d files, want 1,000,000", stats.Files)
	}
	if peak > 64<<20 {
		t.Fatalf("heap peaked at %d MiB while streaming a million files, want under 64 MiB", peak>>20)
	}
}
