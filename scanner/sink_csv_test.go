package scanner

import (
	"bytes"
	"encoding/csv"
	"strings"
	"testing"
)

func TestCSV_QuotesAndNeutralisesFormulas(t *testing.T) {
	var buf bytes.Buffer
	sink := NewCSVSink(&buf, `CORP\jdoe`)
	h := &Host{IP: "10.0.0.5", Hostname: "FS01", FQDN: "fs01.corp.local"}
	sink.ShareFinished(h, &Share{ShareName: "Data", Description: `=HYPERLINK("x")`, ReadPermission: true, WritePermission: true, WriteAccess: "WRITE,WRITE (SUBDIR)"})
	sink.ShareFinished(h, &Share{ShareName: "Notes", Description: "first, still first\nsecond line", ReadPermission: true})
	for _, remark := range []string{"+1", "-1", "@SUM(A1)", "\tcmd", "\rcmd"} {
		sink.ShareFinished(h, &Share{ShareName: "S", Description: remark})
	}
	if err := sink.Close(EndRecord{}); err != nil {
		t.Fatal(err)
	}

	lines := strings.Split(buf.String(), "\n")
	if lines[0] != "identity,host,hostname,share,unc,read,write,write_access,remark" {
		t.Fatalf("header: %q", lines[0])
	}
	if want := `CORP\jdoe,10.0.0.5,FS01,Data,//fs01.corp.local/Data,true,true,WRITE;WRITE (SUBDIR),"'=HYPERLINK(""x"")"`; lines[1] != want {
		t.Fatalf("row:\n%s\nwant\n%s", lines[1], want)
	}

	rows, err := csv.NewReader(strings.NewReader(buf.String())).ReadAll()
	if err != nil {
		t.Fatalf("output is not valid CSV: %v", err)
	}
	if len(rows) != 8 {
		t.Fatalf("want a header and 7 rows, got %d: %q", len(rows), rows)
	}
	if got := rows[2][8]; got != "first, still first\nsecond line" {
		t.Errorf("comma and newline in a remark must round-trip, got %q", got)
	}
	if got := rows[2][6]; got != "false" {
		t.Errorf("write column: %q", got)
	}
	for i, want := range []string{"'+1", "'-1", "'@SUM(A1)", "'\tcmd", "'\rcmd"} {
		if got := rows[3+i][8]; got != want {
			t.Errorf("remark %d: got %q, want %q", i, got, want)
		}
	}
}

func TestCSV_NeutralisesEveryColumn(t *testing.T) {
	var buf bytes.Buffer
	sink := NewCSVSink(&buf, "-jdoe")
	sink.ShareFinished(&Host{IP: "10.0.0.5", Hostname: "=cmd"}, &Share{ShareName: "@share"})
	if err := sink.Close(EndRecord{}); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(strings.NewReader(buf.String())).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if got := rows[1]; got[0] != "'-jdoe" || got[2] != "'=cmd" || got[3] != "'@share" {
		t.Fatalf("server-supplied and user-supplied cells must be neutralised: %q", got)
	}
}
