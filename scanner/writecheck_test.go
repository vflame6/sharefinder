package scanner

import (
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/jfjallid/go-smb/dcerpc/mssrvs"
	"github.com/jfjallid/go-smb/smb"
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

// fakeProber stands in for a connected share in file write probes.
type fakeProber struct {
	putErr, delErr error
	deleted        []string
}

func (f *fakeProber) PutFile(share, path string, offset uint64, cb func([]byte) (int, error)) error {
	return f.putErr
}

func (f *fakeProber) DeleteFile(share, path string) error {
	f.deleted = append(f.deleted, path)
	return f.delErr
}

func TestProbeWriteFile(t *testing.T) {
	notFound := fmt.Errorf("delete: %w", smb.StatusMap[smb.StatusObjectNameNotFound])
	denied := fmt.Errorf("create: %w", smb.StatusMap[smb.StatusAccessDenied])
	tests := []struct {
		name        string
		prober      *fakeProber
		wantWrite   bool
		wantDeletes int
		wantError   bool // an Error line naming the file that may remain
	}{
		{name: "created and deleted", prober: &fakeProber{}, wantWrite: true, wantDeletes: 1},
		{name: "created, delete denied", prober: &fakeProber{delErr: denied}, wantWrite: true, wantDeletes: 1, wantError: true},
		{name: "create denied", prober: &fakeProber{putErr: denied}, wantWrite: false, wantDeletes: 0},
		{name: "write failed after create, cleaned up", prober: &fakeProber{putErr: errors.New("disk full")}, wantWrite: true, wantDeletes: 1},
		{name: "write failed, nothing created", prober: &fakeProber{putErr: errors.New("disk full"), delErr: notFound}, wantWrite: false, wantDeletes: 1},
		{name: "connection cut mid-probe", prober: &fakeProber{putErr: io.ErrUnexpectedEOF, delErr: errors.New("connection closed")}, wantWrite: false, wantDeletes: 1, wantError: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got bool
			out := captureStdout(t, func() { got = probeWriteFile(tt.prober, "10.0.0.5", "Data", "probe.txt") })
			if got != tt.wantWrite {
				t.Errorf("writable = %v, want %v", got, tt.wantWrite)
			}
			if len(tt.prober.deleted) != tt.wantDeletes {
				t.Errorf("delete attempts = %d, want %d", len(tt.prober.deleted), tt.wantDeletes)
			}
			reported := strings.Contains(out, "may remain") && strings.Contains(out, `\\10.0.0.5\Data\probe.txt`)
			if reported != tt.wantError {
				t.Errorf("leftover reported = %v, want %v; output %q", reported, tt.wantError, out)
			}
		})
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
