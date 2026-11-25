package scanner

import (
	"encoding/xml"
	"strings"
	"testing"
	"time"
)

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
// SprintHostLine
// ---------------------------------------------------------------------------

func TestSprintHostLine(t *testing.T) {
	adminTrue, adminFalse := true, false
	tests := []struct {
		name string
		host Host
		want string
	}{
		{
			name: "all facts",
			host: Host{IP: "10.0.0.1", Version: "SMB2", Hostname: "DC01", Domain: "test.local", Signing: true, Session: "user", Admin: &adminTrue},
			want: "[+] 10.0.0.1: SMB2 (name:DC01) (domain:test.local) (signing:true) (session:user) (admin:true)",
		},
		{
			name: "guest session, not admin",
			host: Host{IP: "192.168.1.5", Version: "SMB3", Hostname: "SRV01", Domain: "corp.local", Session: "guest", Admin: &adminFalse},
			want: "[+] 192.168.1.5: SMB3 (name:SRV01) (domain:corp.local) (signing:false) (session:guest) (admin:false)",
		},
		{
			name: "unknown session and admin status omitted",
			host: Host{IP: "192.168.1.6", Version: "SMB3", Hostname: "SRV02", Domain: "corp.local"},
			want: "[+] 192.168.1.6: SMB3 (name:SRV02) (domain:corp.local) (signing:false)",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SprintHostLine(tt.host); got != tt.want {
				t.Fatalf("SprintHostLine() = %q, want %q", got, tt.want)
			}
		})
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
	opts := &Options{}
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
}
