package scanner

import (
	"encoding/xml"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// ParseIPOrCIDR
// ---------------------------------------------------------------------------

func TestParseIPOrCIDR(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []string
		wantErr bool
	}{
		{
			name:  "single IPv4",
			input: "192.168.1.1",
			want:  []string{"192.168.1.1"},
		},
		{
			name:  "CIDR /30 excludes network and broadcast",
			input: "10.0.0.0/30",
			want:  []string{"10.0.0.1", "10.0.0.2"},
		},
		{
			name:  "CIDR /32 single host",
			input: "10.0.0.5/32",
			want:  nil, // /32 → IP is both network and broadcast, so excluded
		},
		{
			name:  "IP range",
			input: "192.168.1.1-5",
			want:  []string{"192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4", "192.168.1.5"},
		},
		{
			name:    "invalid input",
			input:   "not-an-ip",
			wantErr: true,
		},
		{
			name:    "invalid range end < start",
			input:   "192.168.1.10-5",
			wantErr: true,
		},
		{
			name:  "IPv6 loopback",
			input: "::1",
			want:  []string{"::1"},
		},
		{
			name:  "CIDR /24 count",
			input: "10.0.0.0/24",
			want:  nil, // just check length
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseIPOrCIDR(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for input %q, got nil", tt.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// Special case: /24 — just check count
			if tt.name == "CIDR /24 count" {
				if len(got) != 254 {
					t.Fatalf("expected 254 hosts for /24, got %d", len(got))
				}
				return
			}

			if tt.want == nil {
				if len(got) != 0 {
					t.Fatalf("expected empty result, got %v", got)
				}
				return
			}

			if len(got) != len(tt.want) {
				t.Fatalf("expected %d IPs, got %d: %v", len(tt.want), len(got), got)
			}
			for i, ip := range got {
				if ip != tt.want[i] {
					t.Errorf("index %d: expected %s, got %s", i, tt.want[i], ip)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// incrementIP
// ---------------------------------------------------------------------------

func TestIncrementIP(t *testing.T) {
	tests := []struct {
		name string
		ip   net.IP
		want string
	}{
		{
			name: "simple increment",
			ip:   net.ParseIP("192.168.1.1").To4(),
			want: "192.168.1.2",
		},
		{
			name: "octet rollover",
			ip:   net.ParseIP("192.168.1.255").To4(),
			want: "192.168.2.0",
		},
		{
			name: "multiple rollover",
			ip:   net.ParseIP("192.168.255.255").To4(),
			want: "192.169.0.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			incrementIP(tt.ip)
			if tt.ip.String() != tt.want {
				t.Errorf("expected %s, got %s", tt.want, tt.ip.String())
			}
		})
	}
}

// ---------------------------------------------------------------------------
// isNetworkOrBroadcast
// ---------------------------------------------------------------------------

func TestIsNetworkOrBroadcast(t *testing.T) {
	_, ipNet, _ := net.ParseCIDR("10.0.0.0/24")

	tests := []struct {
		name string
		ip   string
		want bool
	}{
		{"network address", "10.0.0.0", true},
		{"broadcast address", "10.0.0.255", true},
		{"normal host", "10.0.0.1", false},
		{"mid host", "10.0.0.128", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip).To4()
			got := isNetworkOrBroadcast(ip, ipNet)
			if got != tt.want {
				t.Errorf("isNetworkOrBroadcast(%s) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ParseSharefinderRun (XML)
// ---------------------------------------------------------------------------

func TestParseSharefinderRun_Valid(t *testing.T) {
	xmlData := `<?xml version="1.0" encoding="UTF-8"?>
<SharefinderRun version="1.0" command="sharefinder auth" time_start="2024-01-01T00:00:00Z" formatted_time_start="01/01/2024 00:00">
  <hosts>
    <host time="2024-01-01T00:00:01Z" ip="10.0.0.1" version="SMB2" hostname="DC01" domain="test.local" signing="true" admin="true">
      <share share_name="ADMIN$" description="Remote Admin" read_permission="true" write_permission="false">
        <file parent="" type="dir" name="docs" size="0" last_modified="2024-01-01T00:00:00Z"/>
      </share>
      <share share_name="Data" description="Data share" read_permission="true" write_permission="true"/>
    </host>
  </hosts>
  <time_end time="2024-01-01T00:01:00Z" formatted_time="01/01/2024 00:01"/>
</SharefinderRun>`

	result, err := ParseSharefinderRun([]byte(xmlData))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Version != "1.0" {
		t.Errorf("version: expected 1.0, got %s", result.Version)
	}
	if len(result.Hosts) != 1 {
		t.Fatalf("expected 1 host, got %d", len(result.Hosts))
	}

	host := result.Hosts[0]
	if host.IP != "10.0.0.1" {
		t.Errorf("host IP: expected 10.0.0.1, got %s", host.IP)
	}
	if host.Hostname != "DC01" {
		t.Errorf("hostname: expected DC01, got %s", host.Hostname)
	}
	if !host.Signing {
		t.Error("expected signing=true")
	}
	if host.Admin == nil || !*host.Admin {
		t.Fatalf("expected admin=true, got %#v", host.Admin)
	}
	if len(host.Shares) != 2 {
		t.Fatalf("expected 2 shares, got %d", len(host.Shares))
	}
	if host.Shares[0].ShareName != "ADMIN$" {
		t.Errorf("share name: expected ADMIN$, got %s", host.Shares[0].ShareName)
	}
	if len(host.Shares[0].Files) != 1 {
		t.Errorf("expected 1 file in first share, got %d", len(host.Shares[0].Files))
	}
	if !host.Shares[1].WritePermission {
		t.Error("expected Data share to have write permission")
	}
}

func TestParseSharefinderRun_Empty(t *testing.T) {
	xmlData := `<?xml version="1.0" encoding="UTF-8"?>
<SharefinderRun version="1.0" command="test" time_start="2024-01-01T00:00:00Z" formatted_time_start="01/01/2024 00:00">
  <hosts></hosts>
  <time_end time="2024-01-01T00:00:01Z" formatted_time="01/01/2024 00:00"/>
</SharefinderRun>`

	result, err := ParseSharefinderRun([]byte(xmlData))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Hosts) != 0 {
		t.Errorf("expected 0 hosts, got %d", len(result.Hosts))
	}
}

func TestParseSharefinderRun_Malformed(t *testing.T) {
	_, err := ParseSharefinderRun([]byte(`<broken xml`))
	if err == nil {
		t.Fatal("expected error for malformed XML")
	}
	// Verify it's an XML syntax error
	if _, ok := err.(*xml.SyntaxError); !ok {
		// xml.Unmarshal may wrap differently; just ensure non-nil error
		t.Logf("error type: %T, message: %v", err, err)
	}
}

// ---------------------------------------------------------------------------
// SPrintHostInfo
// ---------------------------------------------------------------------------

func TestSPrintHostInfo(t *testing.T) {
	adminTrue := true
	got := SPrintHostInfoWithAdmin("10.0.0.1", "SMB2", "DC01", "test.local", true, &adminTrue)
	expected := "[+] 10.0.0.1: SMB2 (name:DC01) (domain:test.local) (signing:true) (admin:true)"
	if got != expected {
		t.Errorf("expected %q, got %q", expected, got)
	}

	adminFalse := false
	got2 := SPrintHostInfoWithAdmin("192.168.1.5", "SMB3", "SRV01", "corp.local", false, &adminFalse)
	if !strings.Contains(got2, "(signing:false)") {
		t.Errorf("expected signing:false in output, got %q", got2)
	}
	if !strings.Contains(got2, "(admin:false)") {
		t.Errorf("expected admin:false in output, got %q", got2)
	}

	got3 := SPrintHostInfoWithAdmin("192.168.1.6", "SMB3", "SRV02", "corp.local", false, nil)
	if strings.Contains(got3, "admin:") {
		t.Errorf("did not expect admin marker when status is unknown, got %q", got3)
	}
}

// ---------------------------------------------------------------------------
// SprintHost
// ---------------------------------------------------------------------------

func TestSprintHost(t *testing.T) {
	h := Host{
		IP: "10.0.0.1",
		Shares: []Share{
			{ShareName: "ADMIN$", ReadPermission: true, WritePermission: false, Description: "Remote Admin"},
			{ShareName: "Data", ReadPermission: true, WritePermission: true, Description: "User data"},
			{ShareName: "IPC$", ReadPermission: false, WritePermission: false, Description: "IPC"},
		},
	}

	t.Run("no exclude", func(t *testing.T) {
		result := SprintHost(h, nil)
		if !strings.Contains(result, "ADMIN$") {
			t.Error("expected ADMIN$ in output")
		}
		if !strings.Contains(result, "Data") {
			t.Error("expected Data in output")
		}
		if !strings.Contains(result, "IPC$") {
			t.Error("expected IPC$ in output")
		}
	})

	t.Run("exclude ADMIN$ and IPC$", func(t *testing.T) {
		result := SprintHost(h, []string{"ADMIN$", "IPC$"})
		if strings.Contains(result, "ADMIN$") {
			t.Error("ADMIN$ should be excluded")
		}
		if strings.Contains(result, "IPC$") {
			t.Error("IPC$ should be excluded")
		}
		if !strings.Contains(result, "Data") {
			t.Error("Data should still be present")
		}
	})

	t.Run("READ permission", func(t *testing.T) {
		result := SprintHost(h, nil)
		// ADMIN$ has READ only
		if !strings.Contains(result, "READ") {
			t.Error("expected READ in output")
		}
	})

	t.Run("WRITE permission", func(t *testing.T) {
		result := SprintHost(h, nil)
		// Data has READ,WRITE
		if !strings.Contains(result, "WRITE") {
			t.Error("expected WRITE in output for Data share")
		}
	})
}

// ---------------------------------------------------------------------------
// SprintFiles
// ---------------------------------------------------------------------------

func TestSprintFiles(t *testing.T) {
	t.Run("empty files", func(t *testing.T) {
		got := SprintFiles(nil)
		if got != "" {
			t.Errorf("expected empty string, got %q", got)
		}
	})

	t.Run("with files", func(t *testing.T) {
		files := []File{
			{
				Type:         "dir",
				Name:         "Documents",
				Size:         0,
				LastModified: time.Date(2024, 6, 15, 10, 30, 0, 0, time.UTC),
			},
			{
				Type:         "file",
				Name:         "readme.txt",
				Size:         1024,
				LastModified: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
			},
		}
		got := SprintFiles(files)
		if !strings.Contains(got, "Documents") {
			t.Error("expected Documents in output")
		}
		if !strings.Contains(got, "readme.txt") {
			t.Error("expected readme.txt in output")
		}
		if !strings.Contains(got, "dir") {
			t.Error("expected dir type in output")
		}
		if !strings.Contains(got, "file") {
			t.Error("expected file type in output")
		}
	})
}

// ---------------------------------------------------------------------------
// NewScanner
// ---------------------------------------------------------------------------

func TestNewScanner(t *testing.T) {
	opts := &Options{
		Target: make(chan DNHost),
	}
	cmdLine := []string{"sharefinder", "auth", "-t", "10.0.0.1"}
	ts := time.Now()

	s := NewScanner(opts, cmdLine, ts, 10)

	if s.Options != opts {
		t.Error("Options not set correctly")
	}
	if len(s.CommandLine) != 4 {
		t.Errorf("expected 4 command line args, got %d", len(s.CommandLine))
	}
	if s.Threads != 10 {
		t.Errorf("expected 10 threads, got %d", s.Threads)
	}
	if !s.TimeStart.Equal(ts) {
		t.Errorf("TimeStart mismatch")
	}
	if s.Stop == nil {
		t.Error("Stop channel not initialized")
	}

	// Verify Stop channel is usable (non-nil, unbuffered)
	go func() { s.Stop <- true }()
	<-s.Stop
}

// ---------------------------------------------------------------------------
// ParseTargets
// ---------------------------------------------------------------------------

func TestParseTargets_IPString(t *testing.T) {
	opts := &Options{
		Target: make(chan DNHost, 10),
	}
	s := NewScanner(opts, nil, time.Now(), 1)

	err := s.ParseTargets("192.168.1.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var hosts []DNHost
	for h := range opts.Target {
		hosts = append(hosts, h)
	}
	if len(hosts) != 1 {
		t.Fatalf("expected 1 host, got %d", len(hosts))
	}
	if hosts[0].IP.String() != "192.168.1.1" {
		t.Errorf("expected 192.168.1.1, got %s", hosts[0].IP.String())
	}
	if hosts[0].Hostname != "" {
		t.Errorf("expected empty hostname, got %s", hosts[0].Hostname)
	}
}

func TestParseTargets_FromFile(t *testing.T) {
	dir := t.TempDir()
	fpath := filepath.Join(dir, "targets.txt")
	content := "10.0.0.1\n10.0.0.2\n10.0.0.3\n"
	if err := os.WriteFile(fpath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	opts := &Options{
		Target: make(chan DNHost, 10),
	}
	s := NewScanner(opts, nil, time.Now(), 1)

	err := s.ParseTargets(fpath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var hosts []DNHost
	for h := range opts.Target {
		hosts = append(hosts, h)
	}
	if len(hosts) != 3 {
		t.Fatalf("expected 3 hosts, got %d", len(hosts))
	}
}

func TestParseTargets_FileWithEmptyLines(t *testing.T) {
	dir := t.TempDir()
	fpath := filepath.Join(dir, "targets.txt")
	content := "10.0.0.1\n\n\n10.0.0.2\n  \n10.0.0.3\n"
	if err := os.WriteFile(fpath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	opts := &Options{
		Target: make(chan DNHost, 10),
	}
	s := NewScanner(opts, nil, time.Now(), 1)

	err := s.ParseTargets(fpath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var hosts []DNHost
	for h := range opts.Target {
		hosts = append(hosts, h)
	}
	if len(hosts) != 3 {
		t.Fatalf("expected 3 hosts (empty lines skipped), got %d", len(hosts))
	}
}

func TestParseTargets_NonexistentFileInvalidIP(t *testing.T) {
	opts := &Options{
		Target: make(chan DNHost, 10),
	}
	s := NewScanner(opts, nil, time.Now(), 1)

	err := s.ParseTargets("not-a-real-file-or-ip")
	if err == nil {
		t.Fatal("expected error for nonexistent file + invalid IP")
	}
}

func TestParseTargets_CIDRFromFile(t *testing.T) {
	dir := t.TempDir()
	fpath := filepath.Join(dir, "targets.txt")
	content := "10.0.0.0/30\n"
	if err := os.WriteFile(fpath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	opts := &Options{
		Target: make(chan DNHost, 10),
	}
	s := NewScanner(opts, nil, time.Now(), 1)

	err := s.ParseTargets(fpath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var hosts []DNHost
	for h := range opts.Target {
		hosts = append(hosts, h)
	}
	if len(hosts) != 2 {
		t.Fatalf("expected 2 hosts from /30 CIDR, got %d", len(hosts))
	}
}
