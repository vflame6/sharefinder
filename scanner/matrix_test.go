package scanner

import (
	"regexp"
	"strings"
	"testing"
)

func labels(ids []Identity) string {
	var l []string
	for _, id := range ids {
		l = append(l, id.Label)
	}
	return strings.Join(l, ",")
}

func TestBuildIdentities(t *testing.T) {
	ids, err := BuildIdentities([]string{`CORP\tester`, `CORP\jdoe`}, []string{"Pass1", "Pass2"}, nil, nil, false, true, true, "")
	if err != nil {
		t.Fatal(err)
	}
	if got := labels(ids); got != "null,guest,tester,jdoe" {
		t.Fatalf("identities %s, want null, guest, then the users in order", got)
	}
	if ids[0].Mode != AuthNull || ids[1].Mode != AuthGuest || !strings.HasPrefix(ids[1].Username, "anonymous_") {
		t.Errorf("null and guest identities: %+v %+v", ids[0], ids[1])
	}
	if u := ids[3]; u.Mode != AuthUser || u.Domain != "CORP" || u.Username != "jdoe" || u.Password != "Pass2" || u.Name() != `CORP\jdoe` {
		t.Errorf("-p pairs with -u by position: %+v", u)
	}

	hashed, err := BuildIdentities([]string{"tester"}, nil, []string{"aad3b435b51404eeaad3b435b51404ee"}, nil, true, false, false, "visitor")
	if err != nil {
		t.Fatal(err)
	}
	if len(hashed) != 1 || len(hashed[0].Hash) != 16 || !hashed[0].LocalAuth || hashed[0].Name() != "tester" {
		t.Errorf("hash identity: %+v", hashed)
	}
	if g, _ := BuildIdentities(nil, nil, nil, nil, false, false, true, "visitor"); len(g) != 1 || g[0].Username != "visitor" {
		t.Errorf("--guest-username: %+v", g)
	}

	// two accounts of the same name in different domains keep their domains
	same, err := BuildIdentities([]string{`CORP\admin`, `LAB\admin`, `CORP\jdoe`}, []string{"a", "b", "c"}, nil, nil, false, false, false, "")
	if err != nil {
		t.Fatal(err)
	}
	if got := labels(same); got != `CORP\admin,LAB\admin,jdoe` {
		t.Errorf("labels %s", got)
	}

	for name, call := range map[string]func() ([]Identity, error){
		"fewer passwords than users": func() ([]Identity, error) {
			return BuildIdentities([]string{`CORP\a`, `CORP\b`}, []string{"x"}, nil, nil, false, false, false, "")
		},
		"-p and -H mixed": func() ([]Identity, error) {
			return BuildIdentities([]string{`CORP\a`, `CORP\b`}, []string{"x"}, []string{"aad3b435b51404eeaad3b435b51404ee"}, nil, false, false, false, "")
		},
		"users without secrets": func() ([]Identity, error) {
			return BuildIdentities([]string{`CORP\a`, `CORP\b`}, nil, nil, nil, false, false, false, "")
		},
		"no domain without --local-auth": func() ([]Identity, error) {
			return BuildIdentities([]string{"tester"}, []string{"x"}, nil, nil, false, false, false, "")
		},
		"a hash that is not hex": func() ([]Identity, error) {
			return BuildIdentities([]string{`CORP\a`}, nil, []string{"zz"}, nil, false, false, false, "")
		},
		"nothing to test": func() ([]Identity, error) {
			return BuildIdentities(nil, nil, nil, nil, false, false, false, "")
		},
	} {
		if _, err := call(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestFormatMatrixRow(t *testing.T) {
	row := FormatMatrixRow("DATA", []string{"null", "guest", "tester"}, []MatrixCell{"R", "R", "RW"})
	if !regexp.MustCompile(`^DATA\s+null:R\s+guest:R\s+tester:RW$`).MatchString(row) {
		t.Fatalf("row %q", row)
	}
	if row := FormatMatrixRow("x\x1b[2J", []string{"null"}, []MatrixCell{"-"}); strings.Contains(row, "\x1b") {
		t.Fatalf("share names from the server are escaped: %q", row)
	}
}
