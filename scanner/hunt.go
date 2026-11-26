package scanner

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf16"

	"github.com/go-ldap/ldap/v3"
	"github.com/vflame6/sharefinder/logger"
)

// huntResolvers is how many domain computer names are resolved at once.
const huntResolvers = 32

// disabledAccount matches computer accounts with ACCOUNTDISABLE (0x2) set in
// userAccountControl, through the LDAP_MATCHING_RULE_BIT_AND rule.
const disabledAccount = "(userAccountControl:1.2.840.113556.1.4.803:=2)"

// computerFilter is the LDAP filter of the computers hunt scans: enabled
// accounts unless includeDisabled, and with activeSince set, those that
// logged on since then (lastLogonTimestamp replicates up to 14 days late).
func computerFilter(includeDisabled bool, activeSince time.Time) string {
	var parts []string
	if !includeDisabled {
		parts = append(parts, "(!"+disabledAccount+")")
	}
	if !activeSince.IsZero() {
		parts = append(parts, fmt.Sprintf("(lastLogonTimestamp>=%d)", toFileTime(activeSince)))
	}
	if len(parts) == 0 {
		return "(objectCategory=computer)"
	}
	return "(&(objectCategory=computer)" + strings.Join(parts, "") + ")"
}

var activeWithinRe = regexp.MustCompile(`^([0-9]+)([dwhm])$`)

// ParseActiveWithin reads --active-within: a count of days, weeks, hours or
// minutes, such as 90d, 12w, 36h or 45m.
func ParseActiveWithin(s string) (time.Duration, error) {
	m := activeWithinRe.FindStringSubmatch(s)
	if m == nil {
		return 0, fmt.Errorf("--active-within %q: use a number of days, weeks, hours or minutes, such as 90d", s)
	}
	n, err := strconv.Atoi(m[1])
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("--active-within %q must be more than 0", s)
	}
	unit := map[string]time.Duration{"d": 24 * time.Hour, "w": 7 * 24 * time.Hour, "h": time.Hour, "m": time.Minute}[m[2]]
	return time.Duration(n) * unit, nil
}

// toFileTime converts t to a Windows FILETIME: 100 ns intervals since
// 1601-01-01 UTC, the format of lastLogonTimestamp.
func toFileTime(t time.Time) int64 {
	const epochDelta = 11644473600 // seconds from 1601-01-01 to 1970-01-01
	return (t.Unix()+epochDelta)*10_000_000 + int64(t.Nanosecond()/100)
}

// uncServer returns the server of \\server\share, or of \\server.
func uncServer(path string) (string, bool) {
	rest, ok := strings.CutPrefix(path, `\\`)
	if !ok {
		return "", false
	}
	server, _, _ := strings.Cut(rest, `\`)
	return server, server != ""
}

// parseRemoteServerName reads a remoteServerName value of a legacy fTDfs
// object: *\\server\share or \\server\share.
func parseRemoteServerName(v string) (string, bool) {
	return uncServer(strings.TrimPrefix(v, "*"))
}

// parseDFSTargetList reads the servers of an msDFS-TargetListv2 value: UTF-16LE
// XML with one <target> per \\server\share.
func parseDFSTargetList(blob []byte) ([]string, error) {
	if len(blob)%2 != 0 {
		return nil, errors.New("msDFS-TargetListv2 is not UTF-16")
	}
	units := make([]uint16, 0, len(blob)/2)
	for i := 0; i < len(blob); i += 2 {
		units = append(units, uint16(blob[i])|uint16(blob[i+1])<<8)
	}
	text := strings.TrimPrefix(string(utf16.Decode(units)), "\ufeff")

	var list struct {
		Targets []string `xml:"target"`
	}
	dec := xml.NewDecoder(strings.NewReader(text))
	// the text is already decoded; the declaration still says utf-16
	dec.CharsetReader = func(_ string, input io.Reader) (io.Reader, error) { return input, nil }
	if err := dec.Decode(&list); err != nil {
		return nil, fmt.Errorf("msDFS-TargetListv2: %w", err)
	}
	var servers []string
	for _, target := range list.Targets {
		if server, ok := uncServer(strings.TrimSpace(target)); ok {
			servers = append(servers, server)
		}
	}
	return servers, nil
}

// mergeDFSServers adds to computers the DFS servers of the hunted domains
// that are not among them yet. A short server name gets the domain's suffix,
// so the domain's DNS can resolve it. A DFS link may point anywhere (a
// partner, a child domain that is not hunted, a cloud file share): servers
// outside the hunted domains are returned as foreign and not scanned, since
// they would be out of scope and get an NTLM logon with the client's
// credentials.
func mergeDFSServers(computers []DNHost, servers []string, domain string, hunted map[string]bool) (merged []DNHost, foreign []string) {
	seen := make(map[string]bool, len(computers))
	for _, c := range computers {
		seen[strings.ToLower(c.Hostname)] = true
	}
	for _, server := range servers {
		if !strings.Contains(server, ".") && domain != "" {
			server += "." + domain
		}
		key := strings.ToLower(server)
		if seen[key] {
			continue
		}
		seen[key] = true
		if _, serverDomain, _ := strings.Cut(key, "."); !hunted[serverDomain] {
			foreign = append(foreign, server)
			continue
		}
		computers = append(computers, DNHost{Hostname: server})
	}
	return computers, foreign
}

// HuntTargets returns a Producer that resolves domain computer names with
// resolve, huntResolvers at a time, and sends each host on as soon as it
// resolves, so the discovery sweep starts with the first answers instead of
// waiting for the whole domain.
func (s *Scanner) HuntTargets(names []DNHost, resolve func(context.Context, string) (net.IP, error)) Producer {
	return func(ctx context.Context, out chan<- DNHost) error {
		in := make(chan DNHost)
		go func() {
			defer close(in)
			for _, name := range names {
				select {
				case in <- name:
				case <-ctx.Done():
					return
				}
			}
		}()
		failed, duplicates := resolvePool(ctx, resolve, in, out, huntResolvers)
		// names that are not scanned are done for the progress line
		s.Stats.Done.Add(int64(failed + duplicates))
		if failed > 0 {
			logger.Warnf("%d domain computer(s) did not resolve (--debug lists them)", failed)
		}
		return nil
	}
}

// computerDirectory is what hunt asks a domain controller, or the Global
// Catalog, for.
type computerDirectory interface {
	SearchComputers(baseDN, filter string) (*ldap.SearchResult, error)
	SearchDFSServers(baseDN string) ([]string, error)
}

// domainSources says where the computers of a domain can be listed: own is
// the DC hunt bound to; chase connects to a DC of another domain (and returns
// how to close it), and is nil with Kerberos, whose tickets are for the DCs
// of the user's own realm only; gc opens the Global Catalog, the last resort.
type domainSources struct {
	own   computerDirectory
	chase func(domain string) (computerDirectory, func(), error)
	gc    func() (computerDirectory, error)
}

// listDomainComputers lists the computers of every domain in bases (and the
// DFS servers of those domains), each from a DC of its own domain: the
// Global Catalog holds neither the operating system nor the last logon time
// of another domain's computers, so through it the OS would be missing and
// --active-within would drop them. The GC is used only when no DC of a domain
// answers, without the activity filter and with a warning. Names are
// deduplicated: a subtree search of a parent domain may list a child's.
func listDomainComputers(ctx context.Context, bases []DomainPartition, includeDisabled bool, activeSince time.Time, src domainSources) []DNHost {
	filter := computerFilter(includeDisabled, activeSince)
	hunted := make(map[string]bool, len(bases))
	for _, base := range bases {
		hunted[strings.ToLower(base.Name)] = true
	}
	// the Global Catalog is opened once, and only if a domain needs it
	var gc computerDirectory
	openGC := func() (computerDirectory, error) {
		if gc == nil {
			if src.gc == nil {
				return nil, errors.New("no Global Catalog")
			}
			dir, err := src.gc()
			if err != nil {
				return nil, err
			}
			gc = dir
		}
		return gc, nil
	}

	var names []DNHost
	seen := make(map[string]bool)
	for _, base := range bases {
		if ctx.Err() != nil {
			return names
		}
		logger.Warnf("Enumerating domain %s", printable(base.Name))
		sr, dir, done, err := searchDomain(base, filter, includeDisabled, activeSince, src, openGC)
		if err != nil {
			done()
			logger.Warnf("Skipping domain %s: %v", printable(base.Name), err)
			continue
		}
		for _, entry := range sr.Entries {
			hostname := entry.GetAttributeValue("dNSHostName")
			if key := strings.ToLower(hostname); hostname != "" && !seen[key] {
				seen[key] = true
				osName := strings.TrimSpace(entry.GetAttributeValue("operatingSystem") + " " + entry.GetAttributeValue("operatingSystemVersion"))
				names = append(names, DNHost{Hostname: hostname, OS: osName})
			}
		}
		// file servers behind DFS links: those of the hunted domains are
		// added, the others are named and left out of scope
		servers, dfsErr := dir.SearchDFSServers(base.BaseDN)
		done()
		if dfsErr != nil {
			logger.Debugf("No DFS targets from domain %s: %v", printable(base.Name), dfsErr)
			continue
		}
		if len(servers) > 0 {
			before := len(names)
			var foreign []string
			names, foreign = mergeDFSServers(names, servers, base.Name, hunted)
			for _, h := range names[before:] {
				seen[strings.ToLower(h.Hostname)] = true
			}
			if added := len(names) - before; added > 0 {
				logger.Warnf("Domain %s: %d more server(s) from DFS links", printable(base.Name), added)
			}
			if len(foreign) > 0 {
				logger.Warnf("Domain %s: not scanning DFS link servers outside the hunted domain(s): %s (scan them with auth if they are in scope)",
					printable(base.Name), printable(strings.Join(foreign, ", ")))
			}
		}
	}
	return names
}

// searchDomain lists the computers of one domain from the DC hunt bound to,
// else from a DC of that domain, else from the Global Catalog. done releases
// the connection it opened; it is never nil.
func searchDomain(base DomainPartition, filter string, includeDisabled bool, activeSince time.Time, src domainSources, openGC func() (computerDirectory, error)) (sr *ldap.SearchResult, dir computerDirectory, done func(), err error) {
	done = func() {}
	sr, err = src.own.SearchComputers(base.BaseDN, filter)
	if err == nil || !isLDAPReferral(err) {
		return sr, src.own, done, err
	}
	// another domain: ask one of its own DCs
	why := "Kerberos logs on only to the DCs of the user's domain"
	if src.chase != nil {
		logger.Debugf("Domain %s is not held by this DC: connecting to one of its DCs", printable(base.Name))
		alt, closeAlt, chaseErr := src.chase(base.Name)
		if chaseErr == nil {
			sr, err = alt.SearchComputers(base.BaseDN, filter)
			return sr, alt, closeAlt, err
		}
		why = fmt.Sprintf("no DC answers (%v)", chaseErr)
	}
	gc, gcErr := openGC()
	if gcErr != nil {
		return nil, nil, done, fmt.Errorf("%s and the Global Catalog is unavailable (%v)", why, gcErr)
	}
	warning := "Domain %s: %s; listing its computers through the Global Catalog, without their operating system"
	if !activeSince.IsZero() {
		warning += " and without --active-within, which the Global Catalog cannot evaluate for another domain"
	}
	logger.Warnf(warning, printable(base.Name), why)
	sr, err = gc.SearchComputers(base.BaseDN, computerFilter(includeDisabled, time.Time{}))
	if err != nil {
		return nil, nil, done, err
	}
	// a subtree search of the GC also returns the computers of the child
	// domains: a hunted child lists its own, from its DC, and a child that
	// is not hunted is out of scope
	own := &ldap.SearchResult{}
	for _, entry := range sr.Entries {
		if inDomain(entry.DN, base.BaseDN) {
			own.Entries = append(own.Entries, entry)
		}
	}
	return own, gc, done, nil
}

// inDomain reports whether the entry named dn belongs to the domain whose
// naming context is baseDN itself, not to a child domain below it: the
// domain of an entry is the run of DC= components that ends its DN.
func inDomain(dn, baseDN string) bool {
	entry, err := ldap.ParseDN(dn)
	if err != nil {
		return false
	}
	base, err := ldap.ParseDN(baseDN)
	if err != nil {
		return false
	}
	i := len(entry.RDNs)
	for i > 0 && len(entry.RDNs[i-1].Attributes) == 1 && strings.EqualFold(entry.RDNs[i-1].Attributes[0].Type, "DC") {
		i--
	}
	return (&ldap.DN{RDNs: entry.RDNs[i:]}).EqualFold(base)
}

// ListComputers prints the name, address and operating system of each
// domain computer as its name resolves (--ldap-only): no host is contacted.
func (s *Scanner) ListComputers(ctx context.Context, computers []DNHost, resolve func(context.Context, string) (net.IP, error)) error {
	out := make(chan DNHost)
	errc := make(chan error, 1)
	go func() {
		errc <- s.HuntTargets(computers, resolve)(ctx, out)
		close(out)
	}()
	for h := range out {
		logger.Info(fmt.Sprintf("%-40s  %-15s  %s", printable(h.Hostname), h.IP, printable(h.OS)))
	}
	return <-errc
}

// resolvePool resolves the hostnames from in with workers lookups at a time
// and sends the hosts with their address to out. A name that does not
// resolve is dropped with a debug message, a name|address pair seen before
// is dropped as a duplicate. It returns when in is drained or ctx is done.
func resolvePool(ctx context.Context, resolve func(context.Context, string) (net.IP, error), in <-chan DNHost, out chan<- DNHost, workers int) (failed, duplicates int) {
	var mu sync.Mutex
	seen := make(map[string]bool)
	var nFailed, nDuplicates atomic.Int64

	var wg sync.WaitGroup
	for range max(workers, 1) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				var host DNHost
				var ok bool
				select {
				case <-ctx.Done():
					return
				case host, ok = <-in:
					if !ok {
						return
					}
				}
				ip, err := resolve(ctx, host.Hostname)
				if err != nil {
					if ctx.Err() == nil {
						nFailed.Add(1)
						logger.Debugf("Cannot resolve %s: %v", printable(host.Hostname), err)
					}
					continue
				}
				key := strings.ToLower(host.Hostname) + "|" + ip.String()
				mu.Lock()
				duplicate := seen[key]
				seen[key] = true
				mu.Unlock()
				if duplicate {
					nDuplicates.Add(1)
					continue
				}
				host.IP = ip
				select {
				case out <- host:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	wg.Wait()
	return int(nFailed.Load()), int(nDuplicates.Load())
}
