package scanner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// slowDNS answers after 100 ms: hostN resolves to 10.0.0.N, names starting
// with "gone" do not resolve.
func slowDNS(ctx context.Context, name string) (net.IP, error) {
	select {
	case <-time.After(100 * time.Millisecond):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if strings.HasPrefix(name, "gone") {
		return nil, errors.New("no such host")
	}
	var n int
	fmt.Sscanf(strings.ToLower(name), "host%d", &n)
	return net.IPv4(10, 0, byte(n/250), byte(n%250)), nil
}

func TestResolvePool_Parallel(t *testing.T) {
	var names []DNHost
	for i := 1; i <= 60; i++ {
		names = append(names, DNHost{Hostname: fmt.Sprintf("host%d.corp.local", i)})
	}
	// the same computer twice (two domains in a forest list it), and two
	// computers without a DNS record
	names = append(names, DNHost{Hostname: "HOST1.corp.local"}, DNHost{Hostname: "gone1.corp.local"}, DNHost{Hostname: "gone2.corp.local"}, DNHost{Hostname: "host2.corp.local"})

	in, out := make(chan DNHost), make(chan DNHost, len(names))
	go func() {
		defer close(in)
		for _, n := range names {
			in <- n
		}
	}()
	var failed, duplicates int
	start := time.Now()
	logs := captureLog(t, func() {
		failed, duplicates = resolvePool(context.Background(), slowDNS, in, out, 32)
	})
	took := time.Since(start)
	close(out)

	if took > 500*time.Millisecond {
		t.Fatalf("64 names at 100 ms each over 32 workers took %v", took)
	}
	got := map[string]bool{}
	for h := range out {
		if h.IP == nil {
			t.Fatalf("%s forwarded without an address", h.Hostname)
		}
		got[strings.ToLower(h.Hostname)] = true
	}
	if len(got) != 60 || failed != 2 || duplicates != 2 {
		t.Fatalf("forwarded %d names, %d failed, %d duplicates; want 60, 2, 2", len(got), failed, duplicates)
	}
	if strings.Contains(logs, "gone1") {
		t.Errorf("unresolvable names are debug messages: %q", logs)
	}
}

func TestResolvePool_CancelStops(t *testing.T) {
	in, out := make(chan DNHost), make(chan DNHost)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		for i := 0; ; i++ {
			select {
			case in <- DNHost{Hostname: fmt.Sprintf("host%d", i)}:
			case <-ctx.Done():
				return
			}
		}
	}()
	time.AfterFunc(150*time.Millisecond, cancel)
	done := make(chan struct{})
	go func() {
		resolvePool(ctx, slowDNS, in, out, 4) // nobody reads out
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("resolvePool must return when ctx is done")
	}
}

func TestComputerFilter(t *testing.T) {
	since := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		disabled bool
		since    time.Time
		want     string
	}{
		{false, time.Time{}, "(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"},
		{true, time.Time{}, "(objectCategory=computer)"},
		{false, since, "(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(lastLogonTimestamp>=134116992000000000))"},
		{true, since, "(&(objectCategory=computer)(lastLogonTimestamp>=134116992000000000))"},
	} {
		if got := computerFilter(tc.disabled, tc.since); got != tc.want {
			t.Errorf("computerFilter(%v, %v) = %s, want %s", tc.disabled, tc.since, got, tc.want)
		}
	}
}

func TestParseActiveWithin(t *testing.T) {
	for in, want := range map[string]time.Duration{
		"90d": 90 * 24 * time.Hour,
		"12w": 12 * 7 * 24 * time.Hour,
		"36h": 36 * time.Hour,
		"45m": 45 * time.Minute,
	} {
		if got, err := ParseActiveWithin(in); err != nil || got != want {
			t.Errorf("ParseActiveWithin(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "90", "d", "0d", "-5d", "90y", "1.5d"} {
		if _, err := ParseActiveWithin(bad); err == nil {
			t.Errorf("ParseActiveWithin(%q) accepted", bad)
		}
	}
}

func TestToFileTime(t *testing.T) {
	// 100 ns intervals since 1601-01-01 UTC
	if got := toFileTime(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)); got != 134116992000000000 {
		t.Fatalf("toFileTime(2026-01-01 UTC) = %d", got)
	}
	if got := toFileTime(time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC)); got != 0 {
		t.Fatalf("toFileTime(1601-01-01) = %d", got)
	}
}

// utf16le encodes s as Active Directory stores msDFS-TargetListv2.
func utf16le(s string) []byte {
	b := []byte{0xff, 0xfe}
	for _, r := range s {
		b = append(b, byte(r), byte(r>>8))
	}
	return b
}

func TestParseDFSTargetList(t *testing.T) {
	blob := utf16le(`<?xml version="1.0" encoding="utf-16"?>` +
		`<targets><target state="online" priority="0">\\FS01.corp.local\Data</target>` +
		`<target state="offline">\\fs02\Archive$</target></targets>`)
	got, err := parseDFSTargetList(blob)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ",") != "FS01.corp.local,fs02" {
		t.Fatalf("servers = %v", got)
	}
	if _, err := parseDFSTargetList([]byte("garbage")); err == nil {
		t.Fatal("a blob that is not a target list must be refused")
	}
}

func TestParseRemoteServerName(t *testing.T) {
	for in, want := range map[string]string{
		`*\\srv01\share`:            "srv01",
		`\\srv02.corp.local\share$`: "srv02.corp.local",
		`\\srv03`:                   "srv03",
	} {
		if got, ok := parseRemoteServerName(in); !ok || got != want {
			t.Errorf("parseRemoteServerName(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
	for _, bad := range []string{"", "srv04", `\\`, `*\\`} {
		if got, ok := parseRemoteServerName(bad); ok {
			t.Errorf("parseRemoteServerName(%q) = %q, want no server", bad, got)
		}
	}
}

func TestMergeDFSServers(t *testing.T) {
	computers := []DNHost{{Hostname: "FS01.corp.local", OS: "Windows Server 2022"}, {Hostname: "ws01.corp.local"}}
	hunted := map[string]bool{"corp.local": true}
	// a DFS link may point anywhere: a partner, a child domain that is not
	// hunted, a cloud file share. Those are out of scope and would get an
	// NTLM logon with the client's credentials.
	servers := []string{"fs01.CORP.local", "nas01", "nas01", "san.corp.local", "files.partner.com", "srv.child.corp.local", "acct.file.core.windows.net"}
	got, foreign := mergeDFSServers(computers, servers, "corp.local", hunted)
	var names []string
	for _, h := range got {
		names = append(names, h.Hostname)
	}
	if strings.Join(names, ",") != "FS01.corp.local,ws01.corp.local,nas01.corp.local,san.corp.local" {
		t.Fatalf("targets = %v", names)
	}
	if strings.Join(foreign, ",") != "files.partner.com,srv.child.corp.local,acct.file.core.windows.net" {
		t.Fatalf("servers outside the hunted domains = %v", foreign)
	}
	if got[0].OS != "Windows Server 2022" {
		t.Fatal("a DFS server that is also a computer keeps the computer's facts")
	}

	// with --forest the child domain is hunted too
	_, foreign = mergeDFSServers(nil, []string{"srv.child.corp.local"}, "corp.local", map[string]bool{"corp.local": true, "child.corp.local": true})
	if len(foreign) != 0 {
		t.Fatalf("a server of a hunted domain is in scope: %v", foreign)
	}
}

// fakeDirectory answers computer searches for the base DNs it holds and
// refers every other base elsewhere, as a DC does for another domain.
type fakeDirectory struct {
	domains map[string][]*ldap.Entry
	filters []string
}

func (f *fakeDirectory) SearchComputers(baseDN, filter string) (*ldap.SearchResult, error) {
	f.filters = append(f.filters, filter)
	entries, ok := f.domains[baseDN]
	if !ok {
		return nil, &ldap.Error{ResultCode: ldap.LDAPResultReferral, Err: errors.New("referral")}
	}
	return &ldap.SearchResult{Entries: entries}, nil
}

func (f *fakeDirectory) SearchDFSServers(string) ([]string, error) { return nil, nil }

func computerEntry(name, os string) *ldap.Entry {
	return ldap.NewEntry("CN="+name, map[string][]string{"dNSHostName": {name}, "operatingSystem": {os}})
}

// domainComputer is a computer entry as a directory holds it: its DN lies in
// the domain its DNS name names.
func domainComputer(fqdn, os string) *ldap.Entry {
	short, domain, _ := strings.Cut(fqdn, ".")
	dn := "CN=" + strings.ToUpper(short) + ",CN=Computers," + GetBaseDN(domain)
	return ldap.NewEntry(dn, map[string][]string{"dNSHostName": {fqdn}, "operatingSystem": {os}})
}

func hostList(hosts []DNHost) string {
	var names []string
	for _, h := range hosts {
		names = append(names, h.Hostname+"="+h.OS)
	}
	return strings.Join(names, ",")
}

var goadForest = []DomainPartition{
	{Name: "north.sevenkingdoms.local", BaseDN: "DC=north,DC=sevenkingdoms,DC=local"},
	{Name: "sevenkingdoms.local", BaseDN: "DC=sevenkingdoms,DC=local"},
}

// GOAD: through the Global Catalog, computers of other domains came without
// their OS, and --active-within dropped them (the GC cannot evaluate
// lastLogonTimestamp for them). Each domain is now asked on its own DC.
func TestListDomainComputers_AsksEachDomainsDC(t *testing.T) {
	own := &fakeDirectory{domains: map[string][]*ldap.Entry{
		"DC=north,DC=sevenkingdoms,DC=local": {computerEntry("winterfell.north.sevenkingdoms.local", "Windows Server 2019"), computerEntry("castelblack.north.sevenkingdoms.local", "Windows Server 2019")},
	}}
	root := &fakeDirectory{domains: map[string][]*ldap.Entry{
		// a subtree search of the root may also list a child domain's computer
		"DC=sevenkingdoms,DC=local": {computerEntry("kingslanding.sevenkingdoms.local", "Windows Server 2019"), computerEntry("WINTERFELL.north.sevenkingdoms.local", "")},
	}}
	src := domainSources{
		own: own,
		chase: func(domain string) (computerDirectory, func(), error) {
			if domain != "sevenkingdoms.local" {
				t.Fatalf("chased %s", domain)
			}
			return root, func() {}, nil
		},
		gc: func() (computerDirectory, error) { t.Fatal("the Global Catalog is a last resort"); return nil, nil },
	}
	since := time.Now().Add(-90 * 24 * time.Hour)
	got := listDomainComputers(context.Background(), goadForest, false, since, src)

	var names []string
	for _, h := range got {
		names = append(names, h.Hostname+"="+h.OS)
	}
	want := "winterfell.north.sevenkingdoms.local=Windows Server 2019,castelblack.north.sevenkingdoms.local=Windows Server 2019,kingslanding.sevenkingdoms.local=Windows Server 2019"
	if strings.Join(names, ",") != want {
		t.Fatalf("computers:\n%v\nwant\n%s", names, want)
	}
	if len(root.filters) != 1 || !strings.Contains(root.filters[0], "lastLogonTimestamp>=") {
		t.Fatalf("the other domain's DC applies --active-within: %v", root.filters)
	}
}

func TestListDomainComputers_GlobalCatalogLastResort(t *testing.T) {
	own := &fakeDirectory{domains: map[string][]*ldap.Entry{"DC=north,DC=sevenkingdoms,DC=local": {domainComputer("winterfell.north.sevenkingdoms.local", "")}}}
	gc := &fakeDirectory{domains: map[string][]*ldap.Entry{"DC=sevenkingdoms,DC=local": {domainComputer("kingslanding.sevenkingdoms.local", "")}}}
	src := domainSources{
		own:   own,
		chase: func(string) (computerDirectory, func(), error) { return nil, nil, errors.New("no DC answers") },
		gc:    func() (computerDirectory, error) { return gc, nil },
	}
	var got []DNHost
	logs := captureLog(t, func() {
		got = listDomainComputers(context.Background(), goadForest, false, time.Now().Add(-time.Hour), src)
	})
	if len(got) != 2 || got[1].Hostname != "kingslanding.sevenkingdoms.local" {
		t.Fatalf("computers %v", got)
	}
	// the GC cannot evaluate the logon time of another domain's computers:
	// they are listed without the filter, and the user is told
	if len(gc.filters) != 1 || strings.Contains(gc.filters[0], "lastLogonTimestamp") {
		t.Fatalf("Global Catalog filter: %v", gc.filters)
	}
	if !strings.Contains(logs, "Global Catalog") || !strings.Contains(logs, "--active-within") {
		t.Fatalf("the fallback must be called out: %q", logs)
	}
}

// A subtree search of the Global Catalog under a domain also returns its
// child domains' computers, without their OS and without the activity
// filter. Only the domain's own computers are taken from it: a hunted child's
// come from the child's DC, and a child that is not hunted is out of scope.
func TestListDomainComputers_GlobalCatalogKeepsToTheDomain(t *testing.T) {
	rootFirst := []DomainPartition{goadForest[1], goadForest[0]}
	own := &fakeDirectory{domains: map[string][]*ldap.Entry{
		"DC=north,DC=sevenkingdoms,DC=local": {domainComputer("winterfell.north.sevenkingdoms.local", "Windows Server 2019")},
	}}
	gc := &fakeDirectory{domains: map[string][]*ldap.Entry{
		"DC=sevenkingdoms,DC=local": {
			domainComputer("kingslanding.sevenkingdoms.local", ""),
			domainComputer("winterfell.north.sevenkingdoms.local", ""),
			domainComputer("oldbox.north.sevenkingdoms.local", ""), // inactive: north's DC leaves it out
		},
	}}
	src := domainSources{
		own:   own,
		chase: func(string) (computerDirectory, func(), error) { return nil, nil, errors.New("no DC answers") },
		gc:    func() (computerDirectory, error) { return gc, nil },
	}
	for _, tc := range []struct {
		name  string
		bases []DomainPartition
		want  string
	}{
		{"the forest, root first", rootFirst, "kingslanding.sevenkingdoms.local=,winterfell.north.sevenkingdoms.local=Windows Server 2019"},
		{"the root domain only", rootFirst[:1], "kingslanding.sevenkingdoms.local="},
	} {
		var got []DNHost
		captureLog(t, func() {
			got = listDomainComputers(context.Background(), tc.bases, false, time.Now().Add(-time.Hour), src)
		})
		if hostList(got) != tc.want {
			t.Errorf("%s: computers\n%s\nwant\n%s", tc.name, hostList(got), tc.want)
		}
	}
}

// Kerberos tickets are for the user's own realm: no DC of another domain can
// be logged on to. hunt does not try (each try cost a reverse DNS lookup
// outside --proxy and a doomed logon) and reads those domains from the Global
// Catalog.
func TestListDomainComputers_KerberosAsksTheGlobalCatalog(t *testing.T) {
	own := &fakeDirectory{domains: map[string][]*ldap.Entry{"DC=north,DC=sevenkingdoms,DC=local": {domainComputer("winterfell.north.sevenkingdoms.local", "Windows Server 2019")}}}
	gc := &fakeDirectory{domains: map[string][]*ldap.Entry{"DC=sevenkingdoms,DC=local": {domainComputer("kingslanding.sevenkingdoms.local", "")}}}
	src := domainSources{own: own, gc: func() (computerDirectory, error) { return gc, nil }} // no chase
	var got []DNHost
	logs := captureLog(t, func() {
		got = listDomainComputers(context.Background(), goadForest, false, time.Time{}, src)
	})
	if want := "winterfell.north.sevenkingdoms.local=Windows Server 2019,kingslanding.sevenkingdoms.local="; hostList(got) != want {
		t.Fatalf("computers\n%s\nwant\n%s", hostList(got), want)
	}
	if !strings.Contains(logs, "Kerberos") || strings.Contains(logs, "no DC answers") {
		t.Errorf("the warning must give the reason: %q", logs)
	}
}

func TestListComputers(t *testing.T) {
	s := NewScanner(&Options{}, nil, time.Now(), 1)
	computers := []DNHost{
		{Hostname: "host1.corp.local", OS: "Windows Server 2022 Datacenter 10.0 (20348)"},
		{Hostname: "gone.corp.local"},
		{Hostname: "host2.corp.local", OS: "Windows 11\n[+] 6.6.6.6: forged"},
	}
	var out string
	logs := captureLog(t, func() {
		if err := s.ListComputers(context.Background(), computers, slowDNS); err != nil {
			t.Error(err)
		}
	})
	out = logs
	for _, want := range []string{
		"host1.corp.local                          10.0.0.1         Windows Server 2022 Datacenter 10.0 (20348)",
		`host2.corp.local                          10.0.0.2         Windows 11\x0a[+] 6.6.6.6: forged`,
		"1 domain computer(s) did not resolve",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

func TestHuntTargets_CountsDroppedNames(t *testing.T) {
	s := NewScanner(&Options{}, nil, time.Now(), 1)
	names := []DNHost{{Hostname: "host1.corp.local"}, {Hostname: "gone.corp.local"}, {Hostname: "host1.corp.local"}, {Hostname: "host2.corp.local"}}
	out := make(chan DNHost, len(names))
	logs := captureLog(t, func() {
		if err := s.HuntTargets(names, slowDNS)(context.Background(), out); err != nil {
			t.Error(err)
		}
	})
	close(out)
	if n := len(out); n != 2 {
		t.Fatalf("forwarded %d hosts, want 2", n)
	}
	// dropped names are done for the progress line
	if done := s.Stats.Done.Load(); done != 2 {
		t.Fatalf("done = %d, want 2 (one unresolvable, one duplicate)", done)
	}
	if !strings.Contains(logs, "1 domain computer(s) did not resolve") {
		t.Fatalf("unresolvable computers are counted for the user: %q", logs)
	}
}
