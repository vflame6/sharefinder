package scanner

import (
	"bytes"
	"testing"
)

func TestUNCSink_ReadableOnly(t *testing.T) {
	var buf bytes.Buffer
	sink := NewUNCSink(&buf)
	fs01 := &Host{IP: "10.0.0.5", FQDN: "fs01.corp.local"}
	sink.ShareFinished(fs01, &Share{ShareName: "Data", ReadPermission: true, ShareType: "disk"})
	sink.ShareFinished(fs01, &Share{ShareName: "Secret"})
	// the same host reached on a second address reports its shares again
	sink.ShareFinished(&Host{IP: "10.0.1.5", FQDN: "fs01.corp.local"}, &Share{ShareName: "Data", ReadPermission: true})

	other := &Host{IP: "10.0.0.6"}
	sink.ShareFinished(other, &Share{ShareName: "Public", ReadPermission: true, WritePermission: true})
	sink.ShareFinished(other, &Share{ShareName: "HP4000", ReadPermission: true, ShareType: "printer"})
	sink.ShareFinished(other, &Share{ShareName: "x\n//attacker/share", ReadPermission: true})
	sink.ShareFinished(&Host{IP: "fe80::1"}, &Share{ShareName: "Data", ReadPermission: true})
	if err := sink.Close(EndRecord{}); err != nil {
		t.Fatal(err)
	}

	want := "//fs01.corp.local/Data\n//10.0.0.6/Public\n//[fe80::1]/Data\n"
	if got := buf.String(); got != want {
		t.Fatalf("UNC list:\n%q\nwant\n%q", got, want)
	}
}
