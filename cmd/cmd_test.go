package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
	if _, err := CreateScanner(cfg); err != nil {
		t.Fatalf("--force must allow overwriting: %v", err)
	}
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

func TestCreateScanner_AcceptsDisabledIOTimeout(t *testing.T) {
	cfg := validConfig()
	cfg.IOTimeout = 0
	if _, err := CreateScanner(cfg); err != nil {
		t.Fatalf("--io-timeout 0 disables the I/O bound and must be accepted: %v", err)
	}
}
