package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOutputPath(t *testing.T) {
	tests := []struct {
		base, ext, want string
	}{
		{"plain.txt", ".txt", "plain.txt"},
		{"plain", ".txt", "plain.txt"},
		{"scan.jsonl", ".xml", "scan.xml"},
		{"scan.json", ".jsonl", "scan.jsonl"},
		{"r.log", ".txt", "r.log.txt"},
		{"dir/out.HTML", ".html", "dir/out.html"},
		{"s.unc.txt", ".unc.txt", "s.unc.txt"},
		{"s.unc.txt", ".txt", "s.txt"},
		{"report.relay.txt", ".csv", "report.csv"},
	}
	for _, tt := range tests {
		if got := OutputPath(tt.base, tt.ext); got != tt.want {
			t.Errorf("OutputPath(%q, %q) = %q, want %q", tt.base, tt.ext, got, tt.want)
		}
	}
}

func TestCheckOverwrite(t *testing.T) {
	dir := t.TempDir()
	existing := filepath.Join(dir, "scan.xml")
	if err := os.WriteFile(existing, []byte("old results"), 0o644); err != nil {
		t.Fatal(err)
	}
	fresh := filepath.Join(dir, "scan.txt")

	err := CheckOverwrite([]string{fresh, existing}, false)
	if err == nil || !strings.Contains(err.Error(), existing) || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("an existing output file must be refused, naming it and --force: %v", err)
	}
	if err := CheckOverwrite([]string{fresh, existing}, true); err != nil {
		t.Fatalf("--force must allow overwriting: %v", err)
	}
	if err := CheckOverwrite([]string{fresh}, false); err != nil {
		t.Fatalf("new files are fine: %v", err)
	}
	if err := CheckOverwrite([]string{fresh, fresh}, true); err == nil {
		t.Fatal("two outputs writing the same file must be refused, even with --force")
	}
}
