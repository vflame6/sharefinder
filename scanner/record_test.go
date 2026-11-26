package scanner

import (
	"strings"
	"testing"
	"time"
)

func TestNewScanID(t *testing.T) {
	const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	first := NewScanID()
	if len(first) != 26 {
		t.Fatalf("scan id %q has %d characters, want 26", first, len(first))
	}
	for _, c := range first {
		if !strings.ContainsRune(crockford, c) {
			t.Fatalf("scan id %q has %q outside the Crockford alphabet", first, c)
		}
	}
	time.Sleep(2 * time.Millisecond)
	if second := NewScanID(); second <= first {
		t.Fatalf("scan ids must sort by time: %q then %q", first, second)
	}
	if NewScanID() == NewScanID() {
		t.Fatal("scan ids must be unique")
	}
}

func TestUNC(t *testing.T) {
	tests := []struct {
		host string
		path []string
		want string
	}{
		{"fs01.corp.local", []string{"Data", `IT\web.config`}, "//fs01.corp.local/Data/IT/web.config"},
		{"10.0.0.5", []string{"Data"}, "//10.0.0.5/Data"},
		{"10.0.0.5", nil, "//10.0.0.5"},
		{"::1", []string{"Data"}, "//[::1]/Data"},
		{"10.0.0.5", []string{"Data", ""}, "//10.0.0.5/Data"},
	}
	for _, tt := range tests {
		if got := UNC(tt.host, tt.path...); got != tt.want {
			t.Errorf("UNC(%q, %q) = %q, want %q", tt.host, tt.path, got, tt.want)
		}
	}
}

func TestOptionsIdentity(t *testing.T) {
	tests := []struct {
		o    Options
		want string
	}{
		{Options{Mode: AuthNull}, "null"},
		{Options{Mode: AuthGuest, Username: "anonymous_x"}, "guest"},
		{Options{Mode: AuthUser, Domain: "CORP", Username: "jdoe"}, `CORP\jdoe`},
		{Options{Mode: AuthUser, Username: "tester", LocalAuth: true}, "tester"},
	}
	for _, tt := range tests {
		if got := tt.o.Identity(); got != tt.want {
			t.Errorf("Identity() = %q, want %q", got, tt.want)
		}
	}
}

func TestUNCHost(t *testing.T) {
	if got := uncHost(&Host{IP: "10.0.0.5", FQDN: "fs01.corp.local"}); got != "fs01.corp.local" {
		t.Errorf("an FQDN is used when known, got %q", got)
	}
	if got := uncHost(&Host{IP: "10.0.0.5", Hostname: "FS01"}); got != "10.0.0.5" {
		t.Errorf("without an FQDN the IP is used, got %q", got)
	}
}
