package scanner

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// collect lists the targets of a set in iteration order: IPs as strings,
// unresolved names as given.
func collect(set *TargetSet) []string {
	var out []string
	set.Each(func(h DNHost) bool {
		out = append(out, h.Address())
		return true
	})
	return out
}

func seq(prefix string, from, to int) []string {
	var out []string
	for i := from; i <= to; i++ {
		out = append(out, fmt.Sprintf("%s%d", prefix, i))
	}
	return out
}

func TestParseTargetSpec(t *testing.T) {
	tests := []struct {
		name    string
		spec    string
		want    []string
		wantErr bool
	}{
		{name: "single IPv4", spec: "192.168.1.1", want: []string{"192.168.1.1"}},
		{name: "CIDR /32 is one host", spec: "10.0.0.5/32", want: []string{"10.0.0.5"}},
		{name: "CIDR /31 is both hosts", spec: "10.0.0.4/31", want: []string{"10.0.0.4", "10.0.0.5"}},
		{name: "CIDR /30 drops network and broadcast", spec: "10.0.0.0/30", want: []string{"10.0.0.1", "10.0.0.2"}},
		{name: "CIDR /24 count", spec: "10.0.0.0/24", want: seq("10.0.0.", 1, 254)},
		{name: "full range", spec: "10.0.0.1-10.0.0.9", want: seq("10.0.0.", 1, 9)},
		{name: "last-octet range", spec: "10.0.0.1-3", want: seq("10.0.0.", 1, 3)},
		{name: "range across octets", spec: "10.0.0.250-10.0.1.2", want: append(seq("10.0.0.", 250, 255), seq("10.0.1.", 0, 2)...)},
		{name: "FQDN lower-cased", spec: "FS01.corp.local", want: []string{"fs01.corp.local"}},
		{name: "short hostname", spec: "fs01", want: []string{"fs01"}},
		{name: "hostname with hyphen", spec: "file-server-01.corp.local", want: []string{"file-server-01.corp.local"}},
		{name: "duplicates removed", spec: "10.0.0.1,10.0.0.1 10.0.0.2", want: []string{"10.0.0.1", "10.0.0.2"}},
		{name: "overlap merged", spec: "10.0.0.0/30,10.0.0.2", want: []string{"10.0.0.1", "10.0.0.2"}},
		{name: "sorted output", spec: "10.0.0.9,10.0.0.1", want: []string{"10.0.0.1", "10.0.0.9"}},
		{name: "duplicate names removed", spec: "fs01,FS01", want: []string{"fs01"}},
		{name: "IPv4 then IPv6 then names", spec: "fs01,::1,10.0.0.1", want: []string{"10.0.0.1", "::1", "fs01"}},
		{name: "IPv6 loopback", spec: "::1", want: []string{"::1"}},
		{name: "IPv6 CIDR", spec: "2001:db8::/126", want: []string{"2001:db8::", "2001:db8::1", "2001:db8::2", "2001:db8::3"}},
		{name: "IPv4 CIDR too large", spec: "10.0.0.0/7", wantErr: true},
		{name: "IPv6 CIDR too large", spec: "2001:db8::/64", wantErr: true},
		{name: "reversed range", spec: "10.0.0.9-10.0.0.1", wantErr: true},
		{name: "reversed last-octet range", spec: "192.168.1.10-5", wantErr: true},
		{name: "bad octet", spec: "10.0.0.300", wantErr: true},
		{name: "bad characters", spec: "bad_host!", wantErr: true},
		{name: "range end out of bounds", spec: "10.0.0.1-300", wantErr: true},
		{name: "empty", spec: "", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			set, err := ParseTargetSpec(tt.spec)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected an error for %q, got %v", tt.spec, collect(set))
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			got := collect(set)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("ParseTargetSpec(%q) = %v, want %v", tt.spec, got, tt.want)
			}
			if set.Len() != len(tt.want) {
				t.Fatalf("Len() = %d, want %d", set.Len(), len(tt.want))
			}
		})
	}
}

func TestParseTargetSpec_File(t *testing.T) {
	path := filepath.Join(t.TempDir(), "targets.txt")
	content := "10.0.0.1\r\n\r\n# a comment\n10.0.0.1\n  \n10.0.0.2 # trailing comment\nfs01\n10.0.0.0/30\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	set, err := ParseTargetSpec(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"10.0.0.1", "10.0.0.2", "fs01"}
	if got := collect(set); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestParseTargetSpec_LongList(t *testing.T) {
	// longer than any file name may be: must not be mistaken for a file path
	var parts []string
	for i := 0; i < 2000; i++ {
		parts = append(parts, fmt.Sprintf("10.%d.%d.1", i/250, i%250))
	}
	set, err := ParseTargetSpec(strings.Join(parts, ","))
	if err != nil {
		t.Fatal(err)
	}
	if set.Len() != 2000 {
		t.Fatalf("Len() = %d, want 2000", set.Len())
	}
}

func TestParseTargetSpec_MissingFileFailsClosed(t *testing.T) {
	for _, spec := range []string{"scope.txt", "out-of-scope.txt", "./targets", "lists/scope.lst", `C:\scope\hosts`, "targets.csv", "/no/such/dir/hosts"} {
		if _, err := ParseExcludeSpec(spec); err == nil {
			t.Errorf("ParseExcludeSpec(%q) must fail: a mistyped exclusion file would exclude nothing", spec)
		}
		if _, err := ParseTargetSpec(spec); err == nil {
			t.Errorf("ParseTargetSpec(%q) must fail: it names a file that does not exist", spec)
		}
	}
}

func TestParseTargetSpec_DirectoryIsNotATargetFile(t *testing.T) {
	if _, err := ParseTargetSpec(t.TempDir()); err == nil {
		t.Fatal("a directory is neither a target file nor a target")
	}
}

func TestParseTargetSpec_FileWithInvalidLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "targets.txt")
	if err := os.WriteFile(path, []byte("10.0.0.1\n10.0.0.999\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseTargetSpec(path); err == nil {
		t.Fatal("expected an error for an invalid line")
	}
}

func TestTargetSet_Subtract(t *testing.T) {
	set, err := ParseTargetSpec("10.0.0.0/29,FS01")
	if err != nil {
		t.Fatal(err)
	}
	ex, err := ParseExcludeSpec("10.0.0.3,10.0.0.5-6,fs01")
	if err != nil {
		t.Fatal(err)
	}
	set.Subtract(ex)
	want := []string{"10.0.0.1", "10.0.0.2", "10.0.0.4"}
	if got := collect(set); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if set.Len() != 3 {
		t.Fatalf("Len() = %d, want 3", set.Len())
	}
}

func TestParseExcludeSpec_KeepsWholeBlock(t *testing.T) {
	ex, err := ParseExcludeSpec("10.0.0.0/30")
	if err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{"10.0.0.0", "10.0.0.1", "10.0.0.3"} {
		if !ex.ContainsIP(net.ParseIP(ip)) {
			t.Errorf("exclusion 10.0.0.0/30 should contain %s", ip)
		}
	}
	if ex.ContainsIP(net.ParseIP("10.0.0.4")) {
		t.Error("exclusion 10.0.0.0/30 should not contain 10.0.0.4")
	}
}

func TestTargetSet_ContainsName(t *testing.T) {
	set, err := ParseTargetSpec("FS01.corp.local")
	if err != nil {
		t.Fatal(err)
	}
	if !set.ContainsName("fs01.CORP.local") {
		t.Fatal("ContainsName must be case-insensitive")
	}
	if set.ContainsName("fs01") {
		t.Fatal("ContainsName must match whole names only")
	}
}

func newResolveScanner(t *testing.T, proxy string, exclude string) *Scanner {
	t.Helper()
	d, err := NewDialer(proxy, time.Second, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	opts := &Options{Dialer: d}
	if exclude != "" {
		ex, err := ParseExcludeSpec(exclude)
		if err != nil {
			t.Fatal(err)
		}
		opts.ExcludeHosts = ex
	}
	return NewScanner(opts, nil, time.Now(), 1)
}

func TestResolveTarget_ExcludedAfterResolution(t *testing.T) {
	s := newResolveScanner(t, "", "127.0.0.1")
	_, ok, err := s.resolveTarget(context.Background(), DNHost{Hostname: "localhost"})
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("localhost resolves to an excluded address and must be skipped")
	}
}

func TestResolveTarget_ResolvesAndKeepsName(t *testing.T) {
	s := newResolveScanner(t, "", "")
	h, ok, err := s.resolveTarget(context.Background(), DNHost{Hostname: "localhost"})
	if err != nil || !ok {
		t.Fatalf("resolveTarget = %v, %v", ok, err)
	}
	if h.IP == nil || !h.IP.IsLoopback() {
		t.Fatalf("expected a loopback IP, got %v", h.IP)
	}
	if h.Hostname != "localhost" {
		t.Fatalf("hostname must be kept for the Kerberos SPN, got %q", h.Hostname)
	}
}

func TestResolveTarget_DedupesByIP(t *testing.T) {
	s := newResolveScanner(t, "", "")
	if _, ok, err := s.resolveTarget(context.Background(), DNHost{IP: net.ParseIP("127.0.0.1")}); err != nil || !ok {
		t.Fatalf("first target must be scanned: %v, %v", ok, err)
	}
	if _, ok, _ := s.resolveTarget(context.Background(), DNHost{Hostname: "localhost"}); ok {
		t.Fatal("a name resolving to an already scanned IP must be skipped")
	}
}

func TestResolveTarget_ProxyLeavesResolutionToProxy(t *testing.T) {
	s := newResolveScanner(t, "127.0.0.1:1080", "")
	h, ok, err := s.resolveTarget(context.Background(), DNHost{Hostname: "fs01.corp.local"})
	if err != nil || !ok {
		t.Fatalf("resolveTarget = %v, %v", ok, err)
	}
	if h.IP != nil || h.Address() != "fs01.corp.local" {
		t.Fatalf("with a proxy the name must be dialled as is, got IP %v address %q", h.IP, h.Address())
	}
}
