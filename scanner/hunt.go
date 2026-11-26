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
