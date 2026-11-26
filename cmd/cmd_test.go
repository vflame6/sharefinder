package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vflame6/sharefinder/logger"
	"github.com/vflame6/sharefinder/scanner"
)

func validConfig() Config {
	return Config{
		Version:    "test",
		Threads:    1,
		Timeout:    time.Second,
		IOTimeout:  time.Second,
		SmbPort:    445,
		WriteCheck: "file",
		Depth:      0,

		DiscoveryThreads: 64,
		ConnectTimeout:   2 * time.Second,
		MaxConnsPerHost:  2,
	}
}

func TestCreateScanner_RejectsBadTimeouts(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
		flag   string
	}{
		{"zero connect timeout", func(c *Config) { c.Timeout = 0 }, "--timeout"},
		{"negative connect timeout", func(c *Config) { c.Timeout = -time.Second }, "--timeout"},
		{"negative I/O timeout", func(c *Config) { c.IOTimeout = -time.Second }, "--io-timeout"},
		{"no connection per host", func(c *Config) { c.MaxConnsPerHost = 0 }, "--max-conns-per-host"},
		{"no threads", func(c *Config) { c.Threads = 0 }, "--threads"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			tt.mutate(&cfg)
			_, err := CreateScanner(cfg)
			if err == nil || !strings.Contains(err.Error(), tt.flag) {
				t.Fatalf("CreateScanner error = %v, want one naming %s", err, tt.flag)
			}
		})
	}
}

func TestCreateScanner_OutputNamesAndOverwrite(t *testing.T) {
	dir := t.TempDir()
	cfg := validConfig()
	cfg.OutputRaw = filepath.Join(dir, "plain.txt")
	s, err := CreateScanner(cfg)
	if err != nil {
		t.Fatal(err)
	}
	s.CloseOutputter()
	if _, err := os.Stat(filepath.Join(dir, "plain.txt")); err != nil {
		t.Fatalf("-o plain.txt must write plain.txt: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "plain.txt.txt")); err == nil {
		t.Fatal("-o plain.txt must not write plain.txt.txt")
	}

	// a second run must not silently overwrite the first one's results
	if _, err := CreateScanner(cfg); err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("existing output must be refused without --force, got %v", err)
	}
	cfg.Force = true
	s, err = CreateScanner(cfg)
	if err != nil {
		t.Fatalf("--force must allow overwriting: %v", err)
	}
	// Windows cannot remove the test directory while the file is open
	s.CloseOutputter()
}

func TestCreateScanner_RefusesBeforeCreatingAnything(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "scan.xml"), []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := validConfig()
	cfg.OutputAll = filepath.Join(dir, "scan")
	if _, err := CreateScanner(cfg); err == nil {
		t.Fatal("--output-all over an existing scan.xml must be refused")
	}
	if _, err := os.Stat(filepath.Join(dir, "scan.txt")); err == nil {
		t.Fatal("no output file may be created when the overwrite check fails")
	}
	if old, _ := os.ReadFile(filepath.Join(dir, "scan.xml")); string(old) != "old" {
		t.Fatal("the existing file must be left alone")
	}
}

func TestCreateScanner_CSVAndUNCOutputs(t *testing.T) {
	dir := t.TempDir()
	cfg := validConfig()
	cfg.OutputCSV = filepath.Join(dir, "shares.csv")
	cfg.OutputUNC = filepath.Join(dir, "shares.unc.txt")
	s, err := CreateScanner(cfg)
	if err != nil {
		t.Fatal(err)
	}
	s.CloseOutputter()
	for _, name := range []string{"shares.csv", "shares.unc.txt"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s not written: %v", name, err)
		}
	}
	if csv, _ := os.ReadFile(filepath.Join(dir, "shares.csv")); !strings.HasPrefix(string(csv), "identity,host,") {
		t.Errorf("CSV lacks its header: %q", csv)
	}

	all := validConfig()
	all.OutputAll = filepath.Join(dir, "scan")
	s, err = CreateScanner(all)
	if err != nil {
		t.Fatal(err)
	}
	s.CloseOutputter()
	for _, name := range []string{"scan.txt", "scan.xml", "scan.jsonl", "scan.csv", "scan.unc.txt", "scan.html"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("--output-all must write %s: %v", name, err)
		}
	}

	both := validConfig()
	both.OutputAll, both.OutputCSV = filepath.Join(dir, "other"), filepath.Join(dir, "x.csv")
	if _, err := CreateScanner(both); err == nil || !strings.Contains(err.Error(), "--output-csv") {
		t.Fatalf("--output-all with --output-csv must be refused, got %v", err)
	}
}

// --recurse descends into directory symlinks and junctions unless
// --disable-follow-links: the domain folder in SYSVOL is one.
func TestCreateScanner_FollowsLinksByDefault(t *testing.T) {
	s, err := CreateScanner(validConfig())
	if err != nil {
		t.Fatal(err)
	}
	if !s.Options.FollowLinks {
		t.Error("links are not followed by default")
	}
	cfg := validConfig()
	cfg.DisableFollowLinks = true
	if s, err = CreateScanner(cfg); err != nil {
		t.Fatal(err)
	}
	if s.Options.FollowLinks {
		t.Error("--disable-follow-links still follows links")
	}
}

// --output-html names the report like every other output, and needs no
// other output: without --output-json the report is rendered from a
// temporary JSONL file.
func TestCreateScanner_OutputHTML(t *testing.T) {
	dir := t.TempDir()
	for name, want := range map[string]string{
		"report":      "report.html",
		"report.html": "report.html",
	} {
		cfg := validConfig()
		cfg.OutputHTML = filepath.Join(dir, name)
		s, err := CreateScanner(cfg)
		if err != nil {
			t.Fatalf("--output-html %s alone: %v", name, err)
		}
		if !s.Options.OutputHTML || s.Options.OutputHTMLFileName != filepath.Join(dir, want) {
			t.Fatalf("--output-html %s writes %q (enabled %v), want %s", name, s.Options.OutputHTMLFileName, s.Options.OutputHTML, want)
		}
		s.CloseOutputter()
		if _, err := os.Stat(filepath.Join(dir, want)); err != nil {
			t.Fatalf("--output-html %s: %v", name, err)
		}
		_ = os.Remove(filepath.Join(dir, want))
	}

	// with --output-json too, the report is still named by --output-html
	cfg := validConfig()
	cfg.OutputJSON, cfg.OutputHTML = filepath.Join(dir, "scan.jsonl"), filepath.Join(dir, "client")
	s, err := CreateScanner(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := s.Options.OutputHTMLFileName, filepath.Join(dir, "client.html"); got != want {
		t.Fatalf("--output-json scan.jsonl --output-html client writes %s, want %s", got, want)
	}
	s.CloseOutputter()

	// an existing report is not overwritten without --force
	cfg = validConfig()
	cfg.OutputHTML = filepath.Join(dir, "client.html")
	if _, err := CreateScanner(cfg); err == nil || !strings.Contains(err.Error(), "client.html") {
		t.Fatalf("an existing --output-html file must be refused, got %v", err)
	}

	both := validConfig()
	both.OutputAll, both.OutputHTML = filepath.Join(dir, "all"), filepath.Join(dir, "x.html")
	if _, err := CreateScanner(both); err == nil || !strings.Contains(err.Error(), "--output-html") {
		t.Fatalf("--output-all with --output-html must be refused, got %v", err)
	}
}

func TestExecuteReport(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "scan.jsonl")
	scan := `{"type":"scan","scan_id":"01JDK4","time":"2026-11-26T10:00:00Z","identity":"tester"}` + "\n" +
		`{"type":"host","scan_id":"01JDK4","time":"2026-11-26T10:00:00Z","identity":"tester","host":"10.0.0.5","unc":"//10.0.0.5","signing":false,"shares":["Data"]}` + "\n"
	if err := os.WriteFile(input, []byte(scan), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := ExecuteReport(input, "", false); err != nil {
		t.Fatal(err)
	}
	html, err := os.ReadFile(filepath.Join(dir, "scan.html"))
	if err != nil || !strings.Contains(string(html), `"10.0.0.5"`) {
		t.Fatalf("report scan.jsonl must write scan.html with the host: %v", err)
	}

	if err := ExecuteReport(input, "", false); err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("an existing report must not be overwritten without --force, got %v", err)
	}
	if err := ExecuteReport(input, "", true); err != nil {
		t.Fatalf("--force overwrites: %v", err)
	}

	if err := ExecuteReport(input, filepath.Join(dir, "client"), false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "client.html")); err != nil {
		t.Fatalf("-o client writes client.html: %v", err)
	}

	same := filepath.Join(dir, "same.html")
	if err := os.WriteFile(same, []byte(scan), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ExecuteReport(same, "", true); err == nil {
		t.Fatal("the report must never overwrite its own input")
	}

	bad := filepath.Join(dir, "notes.txt")
	if err := os.WriteFile(bad, []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ExecuteReport(bad, "", false); err == nil {
		t.Fatal("a file without scan records must be refused")
	}
	if _, err := os.Stat(filepath.Join(dir, "notes.html")); err == nil {
		t.Fatal("a failed report must not leave a file behind")
	}
}

func TestLoadTargets_SetsProgressTotal(t *testing.T) {
	cfg := validConfig()
	cfg.ExcludeHosts = "10.0.0.2"
	s, err := CreateScanner(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := loadTargets(s, "10.0.0.1-4"); err != nil {
		t.Fatal(err)
	}
	if got := s.Stats.Total.Load(); got != 3 {
		t.Fatalf("progress total = %d, want 3 (4 targets, 1 excluded)", got)
	}
}

func TestExecuteDiff(t *testing.T) {
	dir := t.TempDir()
	scan := `{"type":"scan","scan_id":"01JDK4","time":"2026-11-26T10:00:00Z","identity":"tester"}` + "\n"
	share := `{"type":"share","scan_id":"01JDK4","time":"2026-11-26T10:00:00Z","identity":"tester","host":"10.0.0.5","share":"DATA","unc":"//10.0.0.5/DATA","read":true,"write":%t}` + "\n"
	end := `{"type":"end","scan_id":"01JDK4","time":"2026-11-26T10:00:00Z","identity":"tester","targets":1,"reachable":1,"authenticated":1,"failed":0}` + "\n"
	old, newer := filepath.Join(dir, "old.jsonl"), filepath.Join(dir, "new.jsonl")
	if err := os.WriteFile(old, []byte(scan+fmt.Sprintf(share, false)+end), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(newer, []byte(scan+fmt.Sprintf(share, true)+end), 0o644); err != nil {
		t.Fatal(err)
	}

	var out, errOut bytes.Buffer
	logger.SetWriters(&out, &errOut)
	t.Cleanup(func() { logger.SetWriters(os.Stdout, os.Stderr) })
	if err := ExecuteDiff(old, newer); err != nil {
		t.Fatal(err)
	}
	if got, want := out.String(), "Permission changes\n~ //10.0.0.5/DATA  READ -> READ,WRITE\n"; got != want {
		t.Fatalf("diff on stdout = %q, want %q", got, want)
	}

	out.Reset()
	if err := ExecuteDiff(old, old); err != nil || out.String() != "No changes\n" {
		t.Fatalf("a scan diffed with itself: %q, %v", out.String(), err)
	}
}

// The sweep is on unless --disable-discovery and runs as --discovery-threads
// and --connect-timeout say, through --proxy too: no other values there.
func TestCreateScanner_DiscoveryDefaults(t *testing.T) {
	s, err := CreateScanner(validConfig())
	if err != nil {
		t.Fatal(err)
	}
	if got, want := s.Options.Discovery, (scanner.SweepConfig{Enabled: true, Threads: 64, Timeout: 2 * time.Second}); got != want {
		t.Fatalf("discovery = %+v, want %+v", got, want)
	}

	proxied := validConfig()
	proxied.Proxy, proxied.Timeout = "127.0.0.1:1080", 7*time.Second
	if s, err = CreateScanner(proxied); err != nil {
		t.Fatal(err)
	}
	if got, want := s.Options.Discovery, (scanner.SweepConfig{Enabled: true, Threads: 64, Timeout: 2 * time.Second}); got != want {
		t.Fatalf("proxied discovery = %+v, want %+v", got, want)
	}

	proxied.DiscoveryThreads, proxied.ConnectTimeout = 200, 3*time.Second
	if s, err = CreateScanner(proxied); err != nil {
		t.Fatal(err)
	}
	if got, want := s.Options.Discovery, (scanner.SweepConfig{Enabled: true, Threads: 200, Timeout: 3 * time.Second}); got != want {
		t.Fatalf("user-set discovery = %+v, want %+v", got, want)
	}

	for _, bad := range []func(*Config){
		func(c *Config) { c.DiscoveryThreads = 0 },
		func(c *Config) { c.ConnectTimeout = 0 },
	} {
		cfg := validConfig()
		bad(&cfg)
		if _, err := CreateScanner(cfg); err == nil {
			t.Errorf("invalid discovery settings accepted: %+v", cfg)
		}
	}
	off := validConfig()
	off.DisableDiscovery, off.DiscoveryThreads = true, 0
	if s, err = CreateScanner(off); err != nil || s.Options.Discovery.Enabled {
		t.Fatalf("--disable-discovery: %+v, %v", s.Options.Discovery, err)
	}
}

func TestCreateScanner_Resume(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "scan.jsonl")
	previous := `{"type":"scan","scan_id":"01JPREV","time":"2026-11-26T10:00:00Z","command":"--quiet --output-json scan auth 10.0.0.0/30 -u tester -p ***","identity":"tester"}` + "\n" +
		`{"type":"host","scan_id":"01JPREV","time":"2026-11-26T10:00:00Z","identity":"tester","host":"10.0.0.1","unc":"//10.0.0.1","signing":false,"shares":[]}` + "\n"
	if err := os.WriteFile(path, []byte(previous), 0o644); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	logger.SetWriters(&bytes.Buffer{}, &stderr)
	t.Cleanup(func() { logger.SetWriters(os.Stdout, os.Stderr) })

	cfg := validConfig()
	cfg.Resume = path
	cfg.CommandLine = []string{"--resume", path, "--threads=50", "--disable-discovery", "-o", "notes", "--output-json", "scan", "auth", "10.0.0.0/30", "-u", "tester", "-p", "secret"}
	s, err := CreateScanner(cfg)
	if err != nil {
		t.Fatalf("--resume continues an existing file without --force: %v", err)
	}
	if s.Options.Resume == nil || s.Options.Resume.ScanID != "01JPREV" || s.Options.OutputJSONFileName != path {
		t.Fatalf("resume state %+v, JSONL output %q", s.Options.Resume, s.Options.OutputJSONFileName)
	}
	if strings.Contains(stderr.String(), "different command") {
		t.Errorf("output, verbosity and speed flags do not make a different command: %q", stderr.String())
	}
	s.CloseOutputter()
	data, _ := os.ReadFile(path)
	if !strings.HasPrefix(string(data), previous) || strings.Count(string(data), `"type":"scan"`) != 1 || !strings.Contains(string(data), `"type":"end"`) {
		t.Fatalf("the resumed scan appends to the file, without a second scan record:\n%s", data)
	}

	other := validConfig()
	other.Resume, other.OutputJSON = path, filepath.Join(dir, "other")
	if _, err := CreateScanner(other); err == nil || !strings.Contains(err.Error(), "--resume") {
		t.Fatalf("--output-json naming another file must be refused, got %v", err)
	}

	changed := validConfig()
	changed.Resume = path
	changed.CommandLine = []string{"--resume=" + path, "auth", "10.0.0.0/24", "-u", "tester", "-p", "secret"}
	if s, err = CreateScanner(changed); err != nil {
		t.Fatal(err)
	}
	s.CloseOutputter()
	if !strings.Contains(stderr.String(), "different command") {
		t.Errorf("a different command must be called out: %q", stderr.String())
	}

	missing := validConfig()
	missing.Resume = filepath.Join(dir, "nope.jsonl")
	if _, err := CreateScanner(missing); err == nil {
		t.Fatal("nothing to resume must be an error")
	}
}

// --resume warns when the scan file was written by another command. Output
// flags and their values do not make a command another one.
func TestResumeCommand_IgnoresOutputs(t *testing.T) {
	base := []string{"hunt", "-u", `corp\jdoe`, "-p", "secret", "10.0.0.5"}
	with := []string{"hunt", "--output-html", "client.html", "--output-relay-list", "relay.txt", "--output-json=scan.jsonl",
		"-u", `corp\jdoe`, "-p", "secret", "10.0.0.5"}
	if a, b := resumeCommand(base), resumeCommand(with); a != b {
		t.Errorf("output flags made another command:\n%s\n%s", a, b)
	}
}

func TestCreateScanner_ResumeRefusesOutputsItCannotContinue(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "scan.jsonl")
	scan := `{"type":"scan","scan_id":"01JPREV","time":"2026-11-26T10:00:00Z","identity":"tester"}` + "\n"
	if err := os.WriteFile(path, []byte(scan), 0o644); err != nil {
		t.Fatal(err)
	}
	// a text, XML, CSV or UNC file of the first run would be recreated empty
	for name, set := range map[string]func(*Config){
		"-o":           func(c *Config) { c.OutputRaw = filepath.Join(dir, "scan") },
		"--output-xml": func(c *Config) { c.OutputXML = filepath.Join(dir, "scan") },
		"--output-csv": func(c *Config) { c.OutputCSV = filepath.Join(dir, "scan") },
		"--output-unc": func(c *Config) { c.OutputUNC = filepath.Join(dir, "scan") },
		"--output-all": func(c *Config) { c.OutputAll = filepath.Join(dir, "scan") },
	} {
		cfg := validConfig()
		cfg.Resume, cfg.Force = path, true
		set(&cfg)
		if _, err := CreateScanner(cfg); err == nil || !strings.Contains(err.Error(), name) {
			t.Errorf("--resume with %s must be refused, got %v", name, err)
		}
	}
	if data, _ := os.ReadFile(path); string(data) != scan {
		t.Fatalf("a refused resume must leave the scan file alone: %q", data)
	}

	// the HTML report is built from the whole JSONL file, so it is complete
	cfg := validConfig()
	cfg.Resume, cfg.OutputHTML = path, filepath.Join(dir, "resumed")
	s, err := CreateScanner(cfg)
	if err != nil {
		t.Fatalf("--resume with --output-html: %v", err)
	}
	s.CloseOutputter()
	if _, err := os.Stat(filepath.Join(dir, "resumed.html")); err != nil {
		t.Fatalf("--resume scan.jsonl --output-html resumed writes resumed.html: %v", err)
	}
}

// A run the lockout guard stops is as unfinished as one stopped by Ctrl+C:
// report and diff must not take it for complete.
func TestRunScan_StoppedRunIsInterrupted(t *testing.T) {
	dir := t.TempDir()
	cfg := validConfig()
	cfg.OutputJSON = filepath.Join(dir, "scan")
	s, err := CreateScanner(cfg)
	if err != nil {
		t.Fatal(err)
	}
	stop := errors.New("stopping: credentials rejected by 10.0.0.9 (Logon failed)")
	err = runScan(context.Background(), s, "auth", func(context.Context, chan<- scanner.DNHost) error { return stop })
	if !errors.Is(err, stop) {
		t.Fatalf("runScan = %v, want %v", err, stop)
	}
	s.CloseOutputter()
	data, _ := os.ReadFile(filepath.Join(dir, "scan.jsonl"))
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	end := lines[len(lines)-1]
	if !strings.Contains(end, `"type":"end"`) || !strings.Contains(end, `"interrupted":true`) || !strings.Contains(end, `"error":"stopping: credentials rejected`) {
		t.Fatalf("end record of a stopped run: %s", end)
	}
}

func TestCreateScanner_RelayList(t *testing.T) {
	dir := t.TempDir()
	cfg := validConfig()
	cfg.OutputRelay = filepath.Join(dir, "targets")
	s, err := CreateScanner(cfg)
	if err != nil {
		t.Fatal(err)
	}
	s.CloseOutputter()
	if _, err := os.Stat(filepath.Join(dir, "targets.relay.txt")); err != nil {
		t.Fatalf("--output-relay-list targets writes targets.relay.txt: %v", err)
	}

	all := validConfig()
	all.OutputAll = filepath.Join(dir, "scan")
	if s, err = CreateScanner(all); err != nil {
		t.Fatal(err)
	}
	s.CloseOutputter()
	if _, err := os.Stat(filepath.Join(dir, "scan.relay.txt")); err != nil {
		t.Fatalf("--output-all writes scan.relay.txt: %v", err)
	}

	both := validConfig()
	both.OutputAll, both.OutputRelay = filepath.Join(dir, "other"), filepath.Join(dir, "x")
	if _, err := CreateScanner(both); err == nil || !strings.Contains(err.Error(), "--output-relay-list") {
		t.Fatalf("--output-all with --output-relay-list must be refused, got %v", err)
	}
}

func TestExecuteHunt_ChecksActiveWithinFirst(t *testing.T) {
	s, err := CreateScanner(validConfig())
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	err = ExecuteHunt(context.Background(), s, `CORP\jdoe`, "x", "", "", false, "", HuntConfig{DC: net.ParseIP("192.0.2.1"), ActiveWithin: "90y"})
	if err == nil || !strings.Contains(err.Error(), "--active-within") {
		t.Fatalf("ExecuteHunt = %v, want an --active-within error", err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("a bad --active-within must be refused before the DC is contacted")
	}
}

func TestExecuteMatrix(t *testing.T) {
	ids, err := scanner.BuildIdentities([]string{`CORP\a`, `CORP\b`}, []string{"x", "y"}, nil, nil, false, true, true, "")
	if err != nil {
		t.Fatal(err)
	}
	listing := validConfig()
	listing.List = true
	s, err := CreateScanner(listing)
	if err != nil {
		t.Fatal(err)
	}
	if err := ExecuteMatrix(context.Background(), s, "192.0.2.1", ids, MatrixConfig{}); err == nil || !strings.Contains(err.Error(), "--list") {
		t.Fatalf("matrix with --list: %v", err)
	}

	cfg := validConfig()
	cfg.MaxAuthFailures = 1
	if s, err = CreateScanner(cfg); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // the identities' set-up is of interest, not the scan
	_ = ExecuteMatrix(ctx, s, "192.0.2.1", ids, MatrixConfig{})
	guards := map[*scanner.AuthGuard]bool{}
	for _, id := range s.Options.Matrix {
		if id.Mode == scanner.AuthUser {
			if id.Guard == nil || id.Guard.Max() != 1 {
				t.Fatalf("user %s has no guard of its own: %+v", id.Label, id.Guard)
			}
			guards[id.Guard] = true
		}
	}
	if len(guards) != 2 {
		t.Fatalf("each user has a guard of its own, got %d guards", len(guards))
	}
}

func TestCreateScanner_AcceptsDisabledIOTimeout(t *testing.T) {
	cfg := validConfig()
	cfg.IOTimeout = 0
	if _, err := CreateScanner(cfg); err != nil {
		t.Fatalf("--io-timeout 0 disables the I/O bound and must be accepted: %v", err)
	}
}
