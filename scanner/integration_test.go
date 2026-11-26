package scanner

import (
	"bytes"
	"context"
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

func TestIntegration_OutputFormats(t *testing.T) {
	srv := smbtest.Start(t, smbtest.Config{User: testUser, Password: testPassword, Shares: labShares()})
	dir := t.TempDir()
	o := asUser(integrationOptions(srv.Port(), 5*time.Second), testPassword)
	o.List = true
	txtPath := filepath.Join(dir, "out.txt")
	txt, err := o.Writer.CreateFile(txtPath, false)
	if err != nil {
		t.Fatal(err)
	}
	o.FileTXT, o.OutputRawFileName = txt, txtPath
	o.OutputHTML, o.OutputHTMLFileName = true, filepath.Join(dir, "out.html")

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
	if err != nil || !strings.Contains(string(html), "Sharefinder Scan Report") || !strings.Contains(string(html), "readme.txt") {
		t.Fatalf("HTML report missing or incomplete: %v", err)
	}
}
