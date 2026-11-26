package scanner

import (
	"bytes"
	"strings"
	"testing"

	"github.com/jfjallid/go-smb/smb"
)

func TestDialectLabel(t *testing.T) {
	for d, want := range map[uint16]string{
		smb.DialectSmb_2_0_2: "2.0.2",
		smb.DialectSmb_2_1:   "2.1",
		smb.DialectSmb_3_0:   "3.0",
		smb.DialectSmb_3_0_2: "3.0.2",
		smb.DialectSmb_3_1_1: "3.1.1",
		smb.DialectSmb2_ALL:  "", // the wildcard is never a negotiated dialect
		0:                    "",
		0x0399:               "",
	} {
		if got := dialectLabel(d); got != want {
			t.Errorf("dialectLabel(0x%04x) = %q, want %q", d, got, want)
		}
	}
}

func TestSprintHostLine_Dialect(t *testing.T) {
	line := SprintHostLine(Host{IP: "10.0.0.5", Version: "Windows Server 2022", Hostname: "FS01", Domain: "corp.local", Dialect: "3.1.1", Session: "user"})
	if !strings.Contains(line, "(signing:false) (dialect:3.1.1) (session:user)") {
		t.Fatalf("host line: %q", line)
	}
	if line := SprintHostLine(Host{IP: "10.0.0.5"}); strings.Contains(line, "dialect") {
		t.Fatalf("an unknown dialect is left out: %q", line)
	}
}

func TestRelaySink(t *testing.T) {
	var buf bytes.Buffer
	sink := NewRelaySink(&buf)
	for _, h := range []*Host{
		{IP: "10.0.0.5", Signing: false},
		{IP: "10.0.0.6", Signing: true},
		{IP: "10.0.0.7", Signing: false, Session: "null"},
		{IP: "10.0.0.5", Signing: false}, // the same host again
	} {
		sink.HostEnumerated(h)
		sink.HostFinished(h)
	}
	if err := sink.Close(EndRecord{}); err != nil {
		t.Fatal(err)
	}
	if got, want := buf.String(), "10.0.0.5\n10.0.0.7\n"; got != want {
		t.Fatalf("relay list = %q, want %q", got, want)
	}
}
