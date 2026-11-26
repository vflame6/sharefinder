package scanner

import (
	"bytes"
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// reportScan writes a JSONL scan through the JSONL sink: FS01 (admin) with a
// writable Data share holding files, FS02 with a read-only Public share and
// an inaccessible one.
func reportScan(t *testing.T, fileNames ...string) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	sink := newTestJSONLSink(&buf)
	admin := true
	fs01 := &Host{IP: "10.0.0.5", Hostname: "FS01", Domain: "corp.local", Version: "Windows Server 2022", Signing: true, Session: "user", Admin: &admin, Time: sinkTime,
		Shares: []Share{{ShareName: "Data", Description: "Department data", ReadPermission: true, WritePermission: true, WriteAccess: "WRITE,WRITE (ACL)", ShareType: "disk"}}}
	sink.HostEnumerated(fs01)
	var files []File
	for _, name := range fileNames {
		files = append(files, File{Type: "file", Name: name, Size: 1234, LastModified: sinkMtime})
	}
	sink.DirListed(fs01, &fs01.Shares[0], Directory{Files: append([]File{{Type: "dir", Name: "IT", LastModified: sinkMtime}}, files...)}, 0)
	fs01.Shares[0].Listed, fs01.Shares[0].FileCount, fs01.Shares[0].DirCount = true, int64(len(files)), 1
	sink.ShareFinished(fs01, &fs01.Shares[0])

	fs02 := &Host{IP: "10.0.0.6", Hostname: "FS02", Session: "user", Time: sinkTime,
		Shares: []Share{{ShareName: "Public", ReadPermission: true, ShareType: "disk"}, {ShareName: "Finance", ShareType: "disk"}}}
	sink.HostEnumerated(fs02)
	sink.ShareFinished(fs02, &fs02.Shares[0])
	sink.ShareFinished(fs02, &fs02.Shares[1])
	return &buf
}

func writeTemp(t *testing.T, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "scan.jsonl")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func renderReport(t *testing.T, jsonl []byte) string {
	t.Helper()
	var out bytes.Buffer
	if err := WriteReport(writeTemp(t, jsonl), &out); err != nil {
		t.Fatalf("WriteReport: %v", err)
	}
	return out.String()
}

// jsonBlock decodes the <script type="application/json" id="..."> block.
func jsonBlock(t *testing.T, html, id string, v any) {
	t.Helper()
	m := regexp.MustCompile(`(?s)<script type="application/json" id="` + id + `">(.*?)</script>`).FindStringSubmatch(html)
	if m == nil {
		t.Fatalf("no %s block in the report", id)
	}
	if err := json.Unmarshal([]byte(m[1]), v); err != nil {
		t.Fatalf("%s block is not valid JSON: %v\n%s", id, err, m[1])
	}
}

type summaryCounts struct {
	Hosts, Shares, Readable, Writable, Admin, Files int
	Complete                                        bool
	Skipped                                         int
}

func TestReport_TruncatedLastLine(t *testing.T) {
	jsonl := reportScan(t, "web.config").Bytes()
	// kill -9 in the middle of a write leaves half a line
	jsonl = append(jsonl, `{"type":"file","scan_id":"01JDK4","host":"10.0.0.6","sha`...)

	counts := map[string]int{}
	bad, err := ReadRecords(bytes.NewReader(jsonl), func(typ string, raw []byte) error {
		counts[typ]++
		return nil
	})
	if err != nil || bad != 1 {
		t.Fatalf("ReadRecords: bad = %d, err = %v; want 1 skipped line", bad, err)
	}
	if counts["host"] != 2 || counts["share"] != 3 || counts["file"] != 2 || counts["scan"] != 1 {
		t.Fatalf("records read: %v", counts)
	}

	html := renderReport(t, jsonl)
	var hosts [][]any
	jsonBlock(t, html, "sf-hosts", &hosts)
	if len(hosts) != 2 || hosts[0][0] != "10.0.0.5" || hosts[1][0] != "10.0.0.6" {
		t.Fatalf("both finished hosts must be in the report: %v", hosts)
	}
	var summary summaryCounts
	jsonBlock(t, html, "sf-summary", &summary)
	if summary.Complete || summary.Skipped != 1 {
		t.Fatalf("a scan without an end record is incomplete and the bad line is counted: %+v", summary)
	}
}

func TestReport_HostileNames(t *testing.T) {
	hostile := []string{`<img src=x onerror=alert(1)>`, `</script><script>alert(1)</script>`, "<!--<script>", " line"}
	html := renderReport(t, reportScan(t, hostile...).Bytes())

	for _, name := range hostile[:3] {
		if strings.Contains(html, name) {
			t.Errorf("the report contains the raw name %q", name)
		}
	}
	var files [][]any
	jsonBlock(t, html, "sf-files", &files)
	got := map[string]bool{}
	for _, row := range files {
		got[row[2].(string)] = true
	}
	for _, name := range hostile {
		if !got[name] {
			t.Errorf("file %q must reach the report as data, rows: %v", name, files)
		}
	}
	for _, id := range []string{"sf-summary", "sf-hosts", "sf-shares"} {
		var v any
		jsonBlock(t, html, id, &v)
	}
	// every text column is rendered as text, never as HTML: 19 text columns
	// across the three tables, and no string column without a renderer
	if !strings.Contains(html, "var text = DataTable.render.text();") {
		t.Error("the report must render text columns with DataTable.render.text()")
	}
	if n := strings.Count(html, "{type: 'string', render: text"); n != 19 {
		t.Errorf("text columns rendered with render.text: %d, want 19", n)
	}
	if strings.Contains(html, "{type: 'string'}") {
		t.Error("a string column has no renderer, so its data would be drawn as HTML")
	}
}

func TestReport_Counts(t *testing.T) {
	html := renderReport(t, reportScan(t, "web.config", "backup.zip", "notes.txt").Bytes())
	var summary summaryCounts
	jsonBlock(t, html, "sf-summary", &summary)
	want := summaryCounts{Hosts: 2, Shares: 3, Readable: 2, Writable: 1, Admin: 1, Files: 3}
	if summary != want {
		t.Fatalf("summary = %+v, want %+v", summary, want)
	}

	var shares, files [][]any
	jsonBlock(t, html, "sf-shares", &shares)
	jsonBlock(t, html, "sf-files", &files)
	// the listing of each share shows its directories too: they are rows,
	// but not counted as files
	if len(shares) != 3 || len(files) != 4 {
		t.Fatalf("want 3 share rows and 4 entry rows (the IT directory and 3 files): %d, %d", len(shares), len(files))
	}
	// [host, share, path, size, modified, tags, kind]
	if d := files[0]; d[2] != "IT" || d[6] != "dir" {
		t.Errorf("directory row: %v", d)
	}
	if f := files[1]; f[0] != "10.0.0.5" || f[1] != "Data" || f[2] != "web.config" || f[3] != float64(1234) || f[4] != "2026-11-25T21:34:51Z" || f[5] != "config" || f[6] != "file" {
		t.Errorf("file row: %v", f)
	}
	// [host, hostname, share, remark, type, read, write, write access, files, status, identity]
	if s := shares[0]; s[0] != "10.0.0.5" || s[2] != "Data" || s[5] != true || s[6] != true || s[7] != "WRITE; WRITE (ACL)" || s[8] != float64(3) || s[10] != `CORP\jdoe` {
		t.Errorf("share row: %v", s)
	}
	// a matrix scan records a host once per identity: rows say whose they are
	var hosts [][]any
	jsonBlock(t, html, "sf-hosts", &hosts)
	if h := hosts[0]; h[len(h)-1] != `CORP\jdoe` {
		t.Errorf("host row: %v", h)
	}
}

// The report shows each host with its shares and the listing of each share,
// directory by directory, as the reports before 1.5.0 did: the entries carry
// their path inside the share, directories included.
func TestReport_ListingByHost(t *testing.T) {
	var buf bytes.Buffer
	sink := newTestJSONLSink(&buf)
	h := &Host{IP: "10.0.0.5", Hostname: "FS01", Session: "user", Time: sinkTime,
		Shares: []Share{{ShareName: "Data", ReadPermission: true, ShareType: "disk"}}}
	sink.HostEnumerated(h)
	sink.DirListed(h, &h.Shares[0], Directory{Files: []File{
		{Type: "dir", Name: "IT", LastModified: sinkMtime},
		{Type: "file", Name: "readme.txt", Size: 5, LastModified: sinkMtime},
	}}, 0)
	sink.DirListed(h, &h.Shares[0], Directory{Name: `IT\scripts`, Files: []File{
		{Type: "file", Name: "run.ps1", Size: 10, LastModified: sinkMtime},
	}}, 2)
	h.Shares[0].Listed, h.Shares[0].FileCount, h.Shares[0].DirCount = true, 2, 1
	sink.ShareFinished(h, &h.Shares[0])

	html := renderReport(t, buf.Bytes())
	if !strings.Contains(html, `id="sf-details"`) {
		t.Fatal("the report has no place for each host's details and listings")
	}
	var rows [][]any
	jsonBlock(t, html, "sf-files", &rows)
	got := map[string]string{}
	for _, r := range rows {
		if r[0] != "10.0.0.5" || r[1] != "Data" {
			t.Errorf("entry of another share: %v", r)
		}
		got[r[2].(string)] = r[6].(string)
	}
	want := map[string]string{"IT": "dir", "readme.txt": "file", "IT/scripts/run.ps1": "file"}
	if !maps.Equal(got, want) {
		t.Fatalf("entries %v, want %v", got, want)
	}
}

// The scan record says whether --recurse descended into links, so the report
// can tell a link it did not enter from an empty one; scans before
// follow_links existed did not.
func TestReport_FollowLinks(t *testing.T) {
	for _, follow := range []bool{true, false} {
		var buf bytes.Buffer
		buf.WriteString(jsonLine(t, ScanRecord{Type: RecordScan, ScanID: "01J", Identity: "tester", FollowLinks: follow}))
		var summary struct {
			FollowLinks bool `json:"follow_links"`
		}
		jsonBlock(t, renderReport(t, buf.Bytes()), "sf-summary", &summary)
		if summary.FollowLinks != follow {
			t.Errorf("a scan with follow_links %v reports %v", follow, summary.FollowLinks)
		}
	}

	f, err := os.Create(filepath.Join(t.TempDir(), "scan.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	s := NewScanner(&Options{FileJSON: f, FollowLinks: true}, []string{"auth"}, sinkTime, 1)
	s.StartOutputs()
	s.CloseOutputter()
	data, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	var rec ScanRecord
	if err := json.Unmarshal(bytes.SplitN(data, []byte("\n"), 2)[0], &rec); err != nil || rec.Type != RecordScan || !rec.FollowLinks {
		t.Fatalf("scan record %s (%v): follow_links must be recorded", bytes.SplitN(data, []byte("\n"), 2)[0], err)
	}
}

// The report's own script builds the page with textContent and DataTables'
// text renderer: no data can become markup. The list holds the calls the
// script must not make; nothing here is run.
func TestReport_ScriptWritesNoMarkup(t *testing.T) {
	for _, call := range []string{"innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval("} {
		if strings.Contains(reportTail, call) {
			t.Errorf("the report script uses %s", call)
		}
	}
}

func TestReport_CompleteScan(t *testing.T) {
	buf := reportScan(t, "a.txt")
	end, _ := json.Marshal(EndRecord{Type: RecordEnd, ScanID: "01JDK4", Time: sinkTime, Targets: 2, Reachable: 2, Authenticated: 2})
	buf.Write(append(end, '\n'))

	var summary summaryCounts
	jsonBlock(t, renderReport(t, buf.Bytes()), "sf-summary", &summary)
	if !summary.Complete || summary.Skipped != 0 {
		t.Fatalf("a scan with an end record is complete: %+v", summary)
	}
}

func TestReport_RejectsNonScanFile(t *testing.T) {
	var out bytes.Buffer
	if err := WriteReport(writeTemp(t, []byte("not json\nat all\n")), &out); err == nil {
		t.Fatal("a file without a single scan record must be refused")
	}
}
