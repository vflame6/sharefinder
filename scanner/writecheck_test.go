package scanner

import (
	"reflect"
	"strings"
	"testing"

	"github.com/jfjallid/go-smb/dcerpc/mssrvs"
)

func TestWriteLabels(t *testing.T) {
	tests := []struct {
		name    string
		granted []string
		want    []string
	}{
		{name: "none", granted: nil, want: nil},
		{name: "duplicates removed in order", granted: []string{WriteLabelSubdir, WriteLabelACL, WriteLabelACL}, want: []string{WriteLabelSubdir, WriteLabelACL}},
		{name: "plain write suppresses the rest", granted: []string{WriteLabelACL, WriteLabel}, want: []string{WriteLabel}},
		{name: "canonical order", granted: []string{WriteLabelACL, WriteLabelSubdir}, want: []string{WriteLabelSubdir, WriteLabelACL}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := writeLabels(tt.granted); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("writeLabels(%v) = %v, want %v", tt.granted, got, tt.want)
			}
		})
	}
	if WriteLabel != "WRITE" || WriteLabelSubdir != "WRITE (SUBDIR)" || WriteLabelACL != "WRITE (ACL)" {
		t.Fatal("labels must match NetExec's: WRITE, WRITE (SUBDIR), WRITE (ACL)")
	}
}

func TestIsDiskShare(t *testing.T) {
	tests := []struct {
		name   string
		typeID uint32
		want   bool
	}{
		{"disk", mssrvs.StypeDisktree, true},
		{"cluster share", mssrvs.StypeClusterFS, true},
		{"scale-out cluster share", mssrvs.StypeClusterSOFS, true},
		{"cluster DFS share", mssrvs.StypeClusterDFS, true},
		{"print queue", mssrvs.StypePrintq, false},
		{"IPC", mssrvs.StypeIPC, false},
		{"device", mssrvs.StypeDevice, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isDiskShare(tt.typeID); got != tt.want {
				t.Fatalf("isDiskShare(%#x) = %v, want %v", tt.typeID, got, tt.want)
			}
		})
	}
}

func TestParseWriteCheckMode(t *testing.T) {
	for _, mode := range []string{"mask", "file", "off"} {
		if got, err := ParseWriteCheckMode(mode); err != nil || string(got) != mode {
			t.Fatalf("ParseWriteCheckMode(%q) = %q, %v", mode, got, err)
		}
	}
	if _, err := ParseWriteCheckMode("delete"); err == nil {
		t.Fatal("unknown modes must be rejected")
	}
}

func TestSprintHost_WriteLabels(t *testing.T) {
	h := Host{Shares: []Share{
		{ShareName: "Data", ReadPermission: true, WritePermission: true, WriteAccess: "WRITE (SUBDIR)"},
		{ShareName: "Legacy", ReadPermission: true, WritePermission: true},
		{ShareName: "Dropbox", WritePermission: true, WriteAccess: "WRITE (SUBDIR),WRITE (ACL)"},
	}}
	out := SprintHost(h, nil)
	for _, want := range []string{"READ,WRITE (SUBDIR)", "READ,WRITE ", "WRITE (SUBDIR),WRITE (ACL)"} {
		if !strings.Contains(out, want) {
			t.Errorf("SprintHost output lacks %q:\n%s", want, out)
		}
	}
}
