package scanner

import (
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vflame6/sharefinder/internal/smbtest"
)

// Integration tests: real SMB exchanges against go-smb's in-process server.

const (
	testUser     = "tester"
	testPassword = "Testpass1!"
)

func labShares() []smbtest.Share {
	return []smbtest.Share{
		{Name: "DATA", Remark: "Department data", Writable: true, Files: map[string]string{"IT/web.config": "secret", "readme.txt": "hello"}},
		{Name: "PUBLIC", Remark: "Read only", Files: map[string]string{"notice.txt": "hi"}},
	}
}

func integrationOptions(port int, ioTimeout time.Duration) *Options {
	d, _ := NewDialer("", 2*time.Second, ioTimeout)
	return &Options{
		Dialer:     d,
		IOTimeout:  ioTimeout,
		Timeout:    2 * time.Second,
		SmbPort:    port,
		Writer:     NewOutputWriter(),
		Exclude:    []string{"IPC$"},
		WriteCheck: WriteCheckFile,
		Depth:      5,
	}
}

func asUser(o *Options, password string) *Options {
	o.Username, o.Password, o.LocalAuth = testUser, password, true
	o.Mode, o.AuthGuard = AuthUser, NewAuthGuard(1)
	return o
}

func asGuest(o *Options) *Options {
	o.Username, o.Mode = "anonymous_probe", AuthGuest
	return o
}

func asNull(o *Options) *Options {
	o.NullSession, o.Mode = true, AuthNull
	return o
}

// scanXML scans 127.0.0.1 with o and returns the parsed XML output and the
// error Run returned.
func scanXML(t *testing.T, ctx context.Context, o *Options) (*SharefinderRun, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "out.xml")
	f, err := o.Writer.CreateFile(path, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := o.Writer.WriteXMLHeader("test", nil, time.Now(), f); err != nil {
		t.Fatal(err)
	}
	o.FileXML, o.OutputXMLFileName = f, path

	s := NewScanner(o, nil, time.Now(), 2)
	s.StartOutputs()
	runErr := s.Run(ctx, TargetsFromList([]DNHost{{IP: net.ParseIP("127.0.0.1")}}))
	s.CloseOutputter()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	run, err := ParseSharefinderRun(data)
	if err != nil {
		t.Fatalf("XML output does not parse: %v", err)
	}
	return run, runErr
}

func findShare(t *testing.T, run *SharefinderRun, name string) Share {
	t.Helper()
	if len(run.Hosts) != 1 {
		t.Fatalf("got %d hosts, want 1", len(run.Hosts))
	}
	for _, s := range run.Hosts[0].Shares {
		if s.ShareName == name {
			return s
		}
	}
	t.Fatalf("share %s not in results", name)
	return Share{}
}

func dirEntries(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func TestHarness_ListsShares(t *testing.T) {
	srv := smbtest.Start(t, smbtest.Config{User: testUser, Password: testPassword, Shares: labShares()})
	run, err := scanXML(t, context.Background(), asUser(integrationOptions(srv.Port(), 5*time.Second), testPassword))
	if err != nil {
		t.Fatal(err)
	}
	if got := findShare(t, run, "DATA"); got.Description != "Department data" {
		t.Fatalf("DATA = %+v", got)
	}
	findShare(t, run, "PUBLIC")
}

func TestIntegration_Permissions(t *testing.T) {
	srv := smbtest.Start(t, smbtest.Config{User: testUser, Password: testPassword, Shares: labShares()})
	before := dirEntries(t, srv.Root("DATA"))

	tests := []struct {
		mode                   WriteCheckMode
		dataWrite, publicWrite bool
		checkPublic            bool
	}{
		{WriteCheckFile, true, false, true},
		{WriteCheckOff, false, false, true},
		// go-smb's server does not enforce ACLs on write-access opens, so
		// only the positive mask result is meaningful here.
		{WriteCheckMask, true, false, false},
	}
	for _, tt := range tests {
		t.Run(string(tt.mode), func(t *testing.T) {
			o := asUser(integrationOptions(srv.Port(), 5*time.Second), testPassword)
			o.WriteCheck = tt.mode
			run, err := scanXML(t, context.Background(), o)
			if err != nil {
				t.Fatal(err)
			}
			data, public := findShare(t, run, "DATA"), findShare(t, run, "PUBLIC")
			if !data.ReadPermission || !public.ReadPermission {
				t.Fatalf("both shares must be readable: %+v %+v", data, public)
			}
			if data.WritePermission != tt.dataWrite {
				t.Errorf("DATA write = %v, want %v", data.WritePermission, tt.dataWrite)
			}
			if tt.checkPublic && public.WritePermission != tt.publicWrite {
				t.Errorf("PUBLIC write = %v, want %v", public.WritePermission, tt.publicWrite)
			}
			if after := dirEntries(t, srv.Root("DATA")); strings.Join(after, ",") != strings.Join(before, ",") {
				t.Errorf("the write check left %v in the share root (was %v)", after, before)
			}
		})
	}
}

func TestIntegration_GuestFallbackRejected(t *testing.T) {
	srv := smbtest.Start(t, smbtest.Config{User: testUser, Password: testPassword, AllowGuest: true, Shares: labShares()})
	run, err := scanXML(t, context.Background(), asUser(integrationOptions(srv.Port(), 5*time.Second), "wrong password"))
	if !errors.Is(err, ErrAuthLimitReached) || !errors.Is(err, ErrGuestFallback) {
		t.Fatalf("Run error = %v, want the guard to stop on the guest fallback", err)
	}
	if len(run.Hosts) != 0 {
		t.Fatalf("a guest-mapped logon must produce no results, got %+v", run.Hosts)
	}
}

func TestIntegration_NullAndGuestSessionTypes(t *testing.T) {
	srv := smbtest.Start(t, smbtest.Config{User: testUser, Password: testPassword, AllowGuest: true, AllowAnonymous: true, Shares: labShares()})
	for _, tt := range []struct {
		name string
		opts *Options
		want string
	}{
		{"null", asNull(integrationOptions(srv.Port(), 5*time.Second)), SessionNull},
		{"guest", asGuest(integrationOptions(srv.Port(), 5*time.Second)), SessionGuest},
		{"user", asUser(integrationOptions(srv.Port(), 5*time.Second), testPassword), SessionUser},
	} {
		t.Run(tt.name, func(t *testing.T) {
			run, err := scanXML(t, context.Background(), tt.opts)
			if err != nil {
				t.Fatal(err)
			}
			if len(run.Hosts) != 1 || run.Hosts[0].Session != tt.want {
				t.Fatalf("hosts %+v, want session %q", run.Hosts, tt.want)
			}
		})
	}
}

func TestIntegration_DepthLimit(t *testing.T) {
	files := map[string]string{"l1/l2/l3/l4/l5/l6/l7/l8/bottom.txt": "x"}
	srv := smbtest.Start(t, smbtest.Config{User: testUser, Password: testPassword,
		Shares: []smbtest.Share{{Name: "DEEP", Files: files}}})
	o := asUser(integrationOptions(srv.Port(), 5*time.Second), testPassword)
	o.List, o.Recurse, o.Depth = true, true, 3
	run, err := scanXML(t, context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	deep := findShare(t, run, "DEEP")
	var names []string
	for _, d := range deep.Directories {
		names = append(names, d.Name)
	}
	want := []string{`l1`, `l1\l2`, `l1\l2\l3`}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("listed directories %v, want %v", names, want)
	}
}

func TestIntegration_SilentListener(t *testing.T) {
	port := smbtest.StartSilent(t)
	o := asNull(integrationOptions(port, 500*time.Millisecond))
	start := time.Now()
	if _, err := NewSMBConnection(context.Background(), DNHost{IP: net.ParseIP("127.0.0.1")}, o); err == nil {
		t.Fatal("a server that never answers must fail")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("gave up after %v, want under 3s", elapsed)
	}
}

func TestIntegration_WrongPasswordSixConnections(t *testing.T) {
	srv := smbtest.Start(t, smbtest.Config{User: testUser, Password: testPassword, Shares: labShares()})
	o := asUser(integrationOptions(srv.Port(), 5*time.Second), "wrong password")
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			host := DNHost{Hostname: fmt.Sprintf("t%d", i), IP: net.ParseIP("127.0.0.1")}
			if conn, err := NewSMBConnection(context.Background(), host, o); err == nil {
				conn.Close()
				t.Errorf("connection %d logged on with a wrong password", i)
			}
		}(i)
	}
	wg.Wait()
	if n := srv.LogonAttempts(); n != 1 {
		t.Fatalf("the server received %d logons with a wrong password, want 1", n)
	}
}

func TestIntegration_CancelDuringRecursiveListing(t *testing.T) {
	if testing.Short() {
		t.Skip("slow")
	}
	files := map[string]string{}
	for i := 0; i < 40; i++ {
		for j := 0; j < 25; j++ {
			files[fmt.Sprintf("d%d/s%d/", i, j)] = ""
		}
	}
	srv := smbtest.Start(t, smbtest.Config{User: testUser, Password: testPassword, Latency: 2 * time.Millisecond,
		Shares: []smbtest.Share{{Name: "WIDE", Files: files}}})
	o := asUser(integrationOptions(srv.Port(), 5*time.Second), testPassword)
	o.List, o.Recurse = true, true

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(1500*time.Millisecond, cancel)
	start := time.Now()
	_, err := scanXML(t, ctx, o) // fails the test if the XML does not parse
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error = %v, want context.Canceled (the listing finished before the cancel?)", err)
	}
	if elapsed := time.Since(start); elapsed > 3500*time.Millisecond {
		t.Fatalf("Run returned %v after start, want within 2s of the cancel", elapsed)
	}
}

func TestIntegration_JSONL(t *testing.T) {
	srv := smbtest.Start(t, smbtest.Config{User: testUser, Password: testPassword, Shares: labShares()})
	o := asUser(integrationOptions(srv.Port(), 5*time.Second), testPassword)
	o.List = true
	var buf bytes.Buffer
	o.Sink = NewJSONLSink(&buf, ScanRecord{ScanID: NewScanID(), Identity: o.Identity()})

	s := NewScanner(o, nil, time.Now(), 2)
	if err := s.Run(context.Background(), TargetsFromList([]DNHost{{IP: net.ParseIP("127.0.0.1")}})); err != nil {
		t.Fatal(err)
	}
	s.CloseOutputter()

	// jq -r 'select(.type=="share" and .write) | .unc'
	var writable, files []string
	for _, rec := range jsonLines(t, buf.String()) {
		if rec["type"] == "share" && rec["write"] == true {
			writable = append(writable, rec["unc"].(string))
		}
		if rec["type"] == "file" {
			files = append(files, rec["unc"].(string))
			if rec["identity"] != testUser || rec["scan_id"] == "" || rec["host"] != "127.0.0.1" {
				t.Errorf("file record lacks scan_id, identity or host: %v", rec)
			}
		}
	}
	if strings.Join(writable, ",") != "//127.0.0.1/DATA" {
		t.Fatalf("writable shares = %v, want [//127.0.0.1/DATA]", writable)
	}
	if !slices.Contains(files, "//127.0.0.1/DATA/readme.txt") {
		t.Fatalf("file records = %v, want //127.0.0.1/DATA/readme.txt among them", files)
	}
}

// resumeFile writes a JSONL scan in which 127.0.0.1 declared DATA and PUBLIC
// and finished the given shares.
func resumeFile(t *testing.T, done ...string) string {
	t.Helper()
	var b strings.Builder
	b.WriteString(jsonLine(t, ScanRecord{Type: RecordScan, ScanID: "01JPREVIOUS", Time: sinkTime, Identity: testUser}))
	b.WriteString(jsonLine(t, HostRecord{Type: RecordHost, ScanID: "01JPREVIOUS", Identity: testUser, Host: "127.0.0.1", Shares: []string{"DATA", "PUBLIC"}}))
	for _, share := range done {
		b.WriteString(jsonLine(t, ShareRecord{Type: RecordShare, ScanID: "01JPREVIOUS", Identity: testUser, Host: "127.0.0.1", Share: share, Read: true}))
	}
	path := filepath.Join(t.TempDir(), "scan.jsonl")
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// resumeRun continues the scan in path against srv and returns the file.
func resumeRun(t *testing.T, srv *smbtest.Server, path string) string {
	t.Helper()
	o := asUser(integrationOptions(srv.Port(), 5*time.Second), testPassword)
	o.List = true
	r, err := LoadResume(path)
	if err != nil {
		t.Fatal(err)
	}
	f, err := o.Writer.CreateFile(path, true)
	if err != nil {
		t.Fatal(err)
	}
	o.Resume, o.FileJSON, o.OutputJSONFileName = r, f, path

	s := NewScanner(o, nil, time.Now(), 2)
	s.StartOutputs()
	if err := s.Run(context.Background(), TargetsFromList([]DNHost{{IP: net.ParseIP("127.0.0.1")}})); err != nil {
		t.Fatal(err)
	}
	s.CloseOutputter()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestIntegration_ResumeSkipsDoneHosts(t *testing.T) {
	srv := smbtest.Start(t, smbtest.Config{User: testUser, Password: testPassword, Shares: labShares()})
	resumeRun(t, srv, resumeFile(t, "DATA", "PUBLIC"))
	if got := srv.LogonAttempts(); got != 0 {
		t.Fatalf("a host done in the resumed scan must not be contacted, %d logons", got)
	}
}

func TestIntegration_ResumeFinishesOpenShares(t *testing.T) {
	srv := smbtest.Start(t, smbtest.Config{User: testUser, Password: testPassword, Shares: labShares()})
	data := resumeRun(t, srv, resumeFile(t, "DATA"))

	counts := map[string]int{}
	var shares []string
	for _, rec := range jsonLines(t, data) {
		counts[rec["type"].(string)]++
		if rec["type"] == "share" {
			shares = append(shares, rec["share"].(string))
		}
		if rec["type"] != "scan" && rec["scan_id"] != "01JPREVIOUS" {
			t.Errorf("appended records keep the scan id: %v", rec)
		}
	}
	if counts["scan"] != 1 || counts["host"] != 1 || counts["end"] != 1 {
		t.Errorf("one scan, one host and one end record, got %v", counts)
	}
	if strings.Join(shares, ",") != "DATA,PUBLIC" {
		t.Errorf("only PUBLIC is scanned again, share records: %v", shares)
	}
}

func TestIntegration_TwoSharesTwoConns(t *testing.T) {
	for _, tc := range []struct{ conns, logons int }{{2, 2}, {1, 1}} {
		srv := smbtest.Start(t, smbtest.Config{User: testUser, Password: testPassword, Shares: labShares()})
		o := asUser(integrationOptions(srv.Port(), 5*time.Second), testPassword)
		o.List, o.Recurse, o.Sink, o.MaxConnsPerHost = true, true, MultiSink{}, tc.conns

		s := NewScanner(o, nil, time.Now(), 2)
		if err := s.Run(context.Background(), TargetsFromList([]DNHost{{IP: net.ParseIP("127.0.0.1")}})); err != nil {
			t.Fatal(err)
		}
		if got := srv.LogonAttempts(); got != tc.logons {
			t.Errorf("--max-conns-per-host %d: %d logons, want %d", tc.conns, got, tc.logons)
		}
		if shares, files := s.Stats.Shares.Load(), s.Stats.Files.Load(); shares != 2 || files != 3 {
			t.Errorf("--max-conns-per-host %d: shares %d, files %d; want 2, 3", tc.conns, shares, files)
		}
	}
}

func TestIntegration_DiscoverySweep(t *testing.T) {
	srv := smbtest.Start(t, smbtest.Config{User: testUser, Password: testPassword, Shares: labShares()})
	o := asUser(integrationOptions(srv.Port(), 5*time.Second), testPassword)
	o.Sink = MultiSink{}
	o.Discovery = SweepConfig{Enabled: true, Threads: 50, Timeout: 500 * time.Millisecond}

	s := NewScanner(o, nil, time.Now(), 2)
	targets := []DNHost{{IP: net.ParseIP("192.0.2.1")}, {IP: net.ParseIP("127.0.0.1")}, {IP: net.ParseIP("203.0.113.9")}}
	if err := s.Run(context.Background(), TargetsFromList(targets)); err != nil {
		t.Fatal(err)
	}
	if got, want := s.Stats.SummaryLine(), "Summary: 3 targets, 1 reachable, 1 authenticated, 0 failed"; got != want {
		t.Fatalf("%s, want %s", got, want)
	}
	if done := s.Stats.Done.Load(); done != 3 {
		t.Fatalf("done = %d, want 3", done)
	}
	if srv.LogonAttempts() != 1 {
		t.Fatalf("logons = %d, want 1: the sweep itself never logs on", srv.LogonAttempts())
	}
}

func TestIntegration_ProgressCounts(t *testing.T) {
	srv := smbtest.Start(t, smbtest.Config{User: testUser, Password: testPassword, Shares: labShares()})
	o := asUser(integrationOptions(srv.Port(), 5*time.Second), testPassword)
	o.List, o.Recurse, o.Sink = true, true, MultiSink{}

	s := NewScanner(o, nil, time.Now(), 2)
	if err := s.Run(context.Background(), TargetsFromList([]DNHost{{IP: net.ParseIP("127.0.0.1")}})); err != nil {
		t.Fatal(err)
	}
	// DATA holds readme.txt and IT/web.config, PUBLIC holds notice.txt
	if done, shares, files := s.Stats.Done.Load(), s.Stats.Shares.Load(), s.Stats.Files.Load(); done != 1 || shares != 2 || files != 3 {
		t.Fatalf("done %d, shares %d, files %d; want 1, 2, 3", done, shares, files)
	}
}

// A host scanned by address is named by that address in UNC paths: the DNS
// name a server reports for itself may resolve to another host (a cloned VM,
// a lying server), which a content scanner fed the UNC list would then hit.
func TestIntegration_UNCNamesTheScannedAddress(t *testing.T) {
	srv := smbtest.Start(t, smbtest.Config{User: testUser, Password: testPassword, Shares: labShares(), DNSName: "fs01.corp.local"})
	o := asUser(integrationOptions(srv.Port(), 5*time.Second), testPassword)
	var buf bytes.Buffer
	o.Sink = NewUNCSink(&buf)

	s := NewScanner(o, nil, time.Now(), 2)
	if err := s.Run(context.Background(), TargetsFromList([]DNHost{{IP: net.ParseIP("127.0.0.1")}})); err != nil {
		t.Fatal(err)
	}
	s.CloseOutputter()

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	slices.Sort(lines)
	if got, want := strings.Join(lines, ","), "//127.0.0.1/DATA,//127.0.0.1/PUBLIC"; got != want {
		t.Fatalf("UNC list = %q, want %q", got, want)
	}
}

func TestIntegration_OutputFormats(t *testing.T) {
	srv := smbtest.Start(t, smbtest.Config{User: testUser, Password: testPassword, Shares: labShares()})
	dir := t.TempDir()
	// --html without --output-json renders from a temporary JSONL file
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	o := asUser(integrationOptions(srv.Port(), 5*time.Second), testPassword)
	o.List = true
	txtPath := filepath.Join(dir, "out.txt")
	txt, err := o.Writer.CreateFile(txtPath, false)
	if err != nil {
		t.Fatal(err)
	}
	o.FileTXT, o.OutputRawFileName = txt, txtPath
	o.OutputHTML, o.OutputHTMLFileName = true, filepath.Join(dir, "out.html")
	csvPath, uncFile := filepath.Join(dir, "out.csv"), filepath.Join(dir, "out.unc.txt")
	if o.FileCSV, err = o.Writer.CreateFile(csvPath, false); err != nil {
		t.Fatal(err)
	}
	if o.FileUNC, err = o.Writer.CreateFile(uncFile, false); err != nil {
		t.Fatal(err)
	}

	run, err := scanXML(t, context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if len(findShare(t, run, "DATA").Files) == 0 {
		t.Fatal("XML lacks the DATA listing")
	}
	raw, err := os.ReadFile(txtPath)
	if err != nil || !strings.Contains(string(raw), "readme.txt") {
		t.Fatalf("text output lacks the listing: %v\n%s", err, raw)
	}
	html, err := os.ReadFile(o.OutputHTMLFileName)
	if err != nil || !strings.Contains(string(html), "Sharefinder Scan Report") {
		t.Fatalf("HTML report missing: %v", err)
	}
	var files [][]any
	jsonBlock(t, string(html), "sf-files", &files)
	if !slices.ContainsFunc(files, func(row []any) bool { return row[1] == "DATA" && row[2] == "readme.txt" }) {
		t.Fatalf("HTML report lacks DATA/readme.txt: %v", files)
	}
	if left, _ := filepath.Glob(filepath.Join(tmp, "*")); len(left) > 0 {
		t.Errorf("the temporary JSONL must be removed, found %v", left)
	}
	csvData, err := os.ReadFile(csvPath)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(bytes.NewReader(csvData)).ReadAll()
	if err != nil || len(rows) != 3 {
		t.Fatalf("CSV: want a header and a row per share, got %q (%v)", rows, err)
	}
	wantRow := []string{testUser, "127.0.0.1", "SMBTEST", "DATA", "//127.0.0.1/DATA", "true", "true", "WRITE", "Department data"}
	if !slices.ContainsFunc(rows, func(row []string) bool { return slices.Equal(row, wantRow) }) {
		t.Errorf("CSV lacks the DATA row: %q", rows)
	}
	unc, err := os.ReadFile(uncFile)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(unc)), "\n")
	slices.Sort(lines)
	if got := strings.Join(lines, ","); got != "//127.0.0.1/DATA,//127.0.0.1/PUBLIC" {
		t.Errorf("UNC list = %q", unc)
	}
}
