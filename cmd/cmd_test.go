package cmd

import (
	"bytes"
	"fmt"
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
		Depth:      5,

		Discovery:        true,
		DiscoveryThreads: 500,
		ConnectTimeout:   time.Second,
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

func TestCreateScanner_HTMLNames(t *testing.T) {
	dir := t.TempDir()
	cfg := validConfig()
	cfg.OutputHTML = true
	if _, err := CreateScanner(cfg); err == nil || !strings.Contains(err.Error(), "--output-json") {
		t.Fatalf("--html alone must ask for a file name, got %v", err)
	}

	cfg.OutputJSON = filepath.Join(dir, "scan.jsonl")
	s, err := CreateScanner(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := s.Options.OutputHTMLFileName, filepath.Join(dir, "scan.html"); got != want {
		t.Fatalf("--output-json scan.jsonl --html writes %s, want %s", got, want)
	}
	s.CloseOutputter()

	xml := validConfig()
	xml.OutputHTML, xml.OutputXML = true, filepath.Join(dir, "legacy")
	if s, err = CreateScanner(xml); err != nil {
		t.Fatalf("--output-xml with --html keeps working: %v", err)
	}
	if got, want := s.Options.OutputHTMLFileName, filepath.Join(dir, "legacy.html"); got != want {
		t.Fatalf("HTML name = %s, want %s", got, want)
	}
	s.CloseOutputter()
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

func TestCreateScanner_DiscoveryDefaults(t *testing.T) {
	s, err := CreateScanner(validConfig())
	if err != nil {
		t.Fatal(err)
	}
	if got, want := s.Options.Discovery, (scanner.SweepConfig{Enabled: true, Threads: 500, Timeout: time.Second}); got != want {
		t.Fatalf("discovery = %+v, want %+v", got, want)
	}

	// through a proxy every probe is a SOCKS request: fewer at once, and the
	// connect timeout of the SMB stage, so slow tunnels do not hide hosts
	proxied := validConfig()
	proxied.Proxy, proxied.Timeout = "127.0.0.1:1080", 7*time.Second
	if s, err = CreateScanner(proxied); err != nil {
		t.Fatal(err)
	}
	if got, want := s.Options.Discovery, (scanner.SweepConfig{Enabled: true, Threads: 50, Timeout: 7 * time.Second}); got != want {
		t.Fatalf("proxied discovery = %+v, want %+v", got, want)
	}

	// values the user set are kept
	proxied.DiscoveryThreadsSet, proxied.DiscoveryThreads = true, 200
	proxied.ConnectTimeoutSet, proxied.ConnectTimeout = true, 3*time.Second
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
	off.Discovery, off.DiscoveryThreads = false, 0
	if s, err = CreateScanner(off); err != nil || s.Options.Discovery.Enabled {
		t.Fatalf("--no-discovery: %+v, %v", s.Options.Discovery, err)
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
	cfg.CommandLine = []string{"--resume", path, "--threads=50", "--no-discovery", "-o", "notes", "--output-json", "scan", "auth", "10.0.0.0/30", "-u", "tester", "-p", "secret"}
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
	cfg.Resume, cfg.OutputHTML = path, true
	s, err := CreateScanner(cfg)
	if err != nil {
		t.Fatalf("--resume with --html: %v", err)
	}
	s.CloseOutputter()
	if _, err := os.Stat(filepath.Join(dir, "scan.html")); err != nil {
		t.Fatalf("--resume scan.jsonl --html writes scan.html: %v", err)
	}
}

func TestCreateScanner_AcceptsDisabledIOTimeout(t *testing.T) {
	cfg := validConfig()
	cfg.IOTimeout = 0
	if _, err := CreateScanner(cfg); err != nil {
		t.Fatalf("--io-timeout 0 disables the I/O bound and must be accepted: %v", err)
	}
}
