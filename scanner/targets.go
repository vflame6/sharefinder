package scanner

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
)

const (
	minIPv4Prefix   = 8       // a /8 is the largest IPv4 block accepted
	minIPv6Prefix   = 112     // a /112 is the largest IPv6 block accepted
	maxRangeAddrs   = 1 << 24 // largest a.b.c.d-e.f.g.h range accepted
	maxHostnameSize = 253     // RFC 1123
	maxLabelSize    = 63      // RFC 1123
	targetSeparator = ", \t"  // separators between entries on one line
	commentPrefix   = "#"     // everything after it on a line is ignored
	ipv6ExpandLimit = 1 << (128 - minIPv6Prefix)
)

// TargetSet is a deduplicated set of scan targets: IPv4 addresses kept as
// merged ranges, IPv6 addresses and hostnames kept in input order.
type TargetSet struct {
	v4      []v4Range
	v6      []netip.Addr
	v6Set   map[netip.Addr]struct{}
	names   []string
	nameSet map[string]struct{}
}

type v4Range struct{ lo, hi uint32 }

func newTargetSet() *TargetSet {
	return &TargetSet{v6Set: map[netip.Addr]struct{}{}, nameSet: map[string]struct{}{}}
}

// ParseTargetSpec parses scan targets. spec is the path of an existing file
// with entries on each line, or entries separated by commas or spaces. An
// entry is an IPv4/IPv6 address, a CIDR, a range (10.0.0.1-9 or
// 10.0.0.1-10.0.0.9) or a hostname. CIDRs up to /30 skip their network and
// broadcast addresses. The whole spec is validated before it is returned.
func ParseTargetSpec(spec string) (*TargetSet, error) {
	return parseSpec(spec, false)
}

// ParseExcludeSpec parses targets to leave out, with the same grammar as
// ParseTargetSpec, except that a CIDR covers every address of the block.
func ParseExcludeSpec(spec string) (*TargetSet, error) {
	return parseSpec(spec, true)
}

func parseSpec(spec string, wholeBlocks bool) (*TargetSet, error) {
	lines, err := specLines(spec)
	if err != nil {
		return nil, err
	}
	set := newTargetSet()
	for _, line := range lines {
		if i := strings.Index(line, commentPrefix); i >= 0 {
			line = line[:i]
		}
		for _, entry := range strings.FieldsFunc(line, func(r rune) bool { return strings.ContainsRune(targetSeparator, r) }) {
			if err := set.addEntry(entry, wholeBlocks); err != nil {
				return nil, err
			}
		}
	}
	if set.Len() == 0 {
		return nil, fmt.Errorf("no targets in %q", spec)
	}
	set.normalize()
	return set, nil
}

// specLines returns the lines of spec when it names an existing regular file,
// or spec itself as the only line. A spec that looks like a file name but does
// not exist is an error rather than a hostname: a mistyped exclusion file must
// not silently exclude nothing.
func specLines(spec string) ([]string, error) {
	info, err := os.Stat(spec)
	switch {
	case err == nil && info.IsDir():
		return nil, fmt.Errorf("%s is a directory, not a target file", spec)
	case err != nil || !info.Mode().IsRegular():
		// Not a file: a list longer than a file name may be, or with
		// characters Windows rejects in paths, ends up here too.
		if looksLikeFile(spec) {
			return nil, fmt.Errorf("target file %s does not exist", spec)
		}
		return []string{spec}, nil
	}
	file, err := os.Open(spec)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

// fileExtensions are suffixes that name target files, not hosts: none of them
// is a DNS top-level domain.
var fileExtensions = []string{".txt", ".lst", ".list", ".csv", ".conf", ".cfg", ".ips", ".hosts", ".targets", ".in"}

// looksLikeFile reports whether a single-entry spec is meant as a file path:
// it has a path prefix or a backslash, or ends in a target-file extension.
func looksLikeFile(spec string) bool {
	if strings.ContainsAny(spec, targetSeparator) {
		return false
	}
	for _, prefix := range []string{"/", "./", "../", "~/"} {
		if strings.HasPrefix(spec, prefix) {
			return true
		}
	}
	if strings.Contains(spec, `\`) {
		return true
	}
	lower := strings.ToLower(spec)
	for _, ext := range fileExtensions {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

func (t *TargetSet) addEntry(entry string, wholeBlocks bool) error {
	switch {
	case strings.Contains(entry, "/"):
		return t.addCIDR(entry, wholeBlocks)
	case isIPLiteral(entry):
		addr, err := netip.ParseAddr(entry)
		if err != nil {
			return fmt.Errorf("invalid IP address: %s", entry)
		}
		t.addAddr(addr.Unmap())
		return nil
	case strings.Contains(entry, "-"):
		if before, _, _ := strings.Cut(entry, "-"); isIPLiteral(before) {
			return t.addRange(entry)
		}
	}
	return t.addName(entry)
}

// isIPLiteral reports whether s parses as an IP address.
func isIPLiteral(s string) bool {
	_, err := netip.ParseAddr(s)
	return err == nil
}

func (t *TargetSet) addAddr(addr netip.Addr) {
	if addr.Is4() {
		v := v4ToUint(addr)
		t.v4 = append(t.v4, v4Range{v, v})
		return
	}
	if _, ok := t.v6Set[addr]; !ok {
		t.v6Set[addr] = struct{}{}
		t.v6 = append(t.v6, addr)
	}
}

func (t *TargetSet) addCIDR(entry string, wholeBlocks bool) error {
	prefix, err := netip.ParsePrefix(entry)
	if err != nil {
		return fmt.Errorf("invalid CIDR: %s", entry)
	}
	prefix = prefix.Masked()
	if prefix.Addr().Is4() {
		if prefix.Bits() < minIPv4Prefix {
			return fmt.Errorf("CIDR %s is too large: the largest accepted IPv4 block is /%d", entry, minIPv4Prefix)
		}
		lo := v4ToUint(prefix.Addr())
		hi := lo | (1<<(32-prefix.Bits()) - 1)
		// Network and broadcast addresses only exist up to /30.
		if !wholeBlocks && prefix.Bits() <= 30 {
			lo++
			hi--
		}
		t.v4 = append(t.v4, v4Range{lo, hi})
		return nil
	}
	if prefix.Bits() < minIPv6Prefix {
		return fmt.Errorf("CIDR %s is too large: the largest accepted IPv6 block is /%d", entry, minIPv6Prefix)
	}
	addr := prefix.Addr()
	for i := 0; i < ipv6ExpandLimit && prefix.Contains(addr); i++ {
		t.addAddr(addr)
		addr = addr.Next()
	}
	return nil
}

func (t *TargetSet) addRange(entry string) error {
	startText, endText, _ := strings.Cut(entry, "-")
	start, err := netip.ParseAddr(startText)
	if err != nil || !start.Unmap().Is4() {
		return fmt.Errorf("invalid range start in %s: ranges are IPv4 only", entry)
	}
	start = start.Unmap()

	var end netip.Addr
	if octet, err := strconv.Atoi(endText); err == nil {
		// 10.0.0.1-9: the end replaces the last octet
		if octet < 0 || octet > 255 {
			return fmt.Errorf("invalid range end in %s", entry)
		}
		b := start.As4()
		b[3] = byte(octet)
		end = netip.AddrFrom4(b)
	} else {
		end, err = netip.ParseAddr(endText)
		if err != nil || !end.Unmap().Is4() {
			return fmt.Errorf("invalid range end in %s", entry)
		}
		end = end.Unmap()
	}

	lo, hi := v4ToUint(start), v4ToUint(end)
	if hi < lo {
		return fmt.Errorf("invalid range %s: the end is before the start", entry)
	}
	if uint64(hi-lo)+1 > maxRangeAddrs {
		return fmt.Errorf("range %s is too large: at most %d addresses", entry, maxRangeAddrs)
	}
	t.v4 = append(t.v4, v4Range{lo, hi})
	return nil
}

func (t *TargetSet) addName(entry string) error {
	name := strings.ToLower(strings.TrimSuffix(entry, "."))
	if !validHostname(name) {
		return fmt.Errorf("invalid target %q: not an IP address, CIDR, range or hostname", entry)
	}
	if _, ok := t.nameSet[name]; !ok {
		t.nameSet[name] = struct{}{}
		t.names = append(t.names, name)
	}
	return nil
}

// validHostname accepts RFC 1123 hostnames, plus underscores, which Windows
// names often contain. All-numeric names are rejected: they are mistyped IPs.
func validHostname(name string) bool {
	if name == "" || len(name) > maxHostnameSize {
		return false
	}
	allNumeric := true
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > maxLabelSize || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			switch {
			case r >= 'a' && r <= 'z', r == '-', r == '_':
				allNumeric = false
			case r >= '0' && r <= '9':
			default:
				return false
			}
		}
	}
	return !allNumeric
}

// normalize sorts and merges the IPv4 ranges.
func (t *TargetSet) normalize() {
	sort.Slice(t.v4, func(i, j int) bool { return t.v4[i].lo < t.v4[j].lo })
	merged := t.v4[:0]
	for _, r := range t.v4 {
		if r.lo > r.hi {
			continue
		}
		if n := len(merged); n > 0 && uint64(r.lo) <= uint64(merged[n-1].hi)+1 {
			if r.hi > merged[n-1].hi {
				merged[n-1].hi = r.hi
			}
			continue
		}
		merged = append(merged, r)
	}
	t.v4 = merged
}

// Subtract removes every address and name of ex from t.
func (t *TargetSet) Subtract(ex *TargetSet) {
	if ex == nil {
		return
	}
	var out []v4Range
	for _, r := range t.v4 {
		pieces := []v4Range{r}
		for _, e := range ex.v4 {
			var next []v4Range
			for _, p := range pieces {
				next = append(next, cut(p, e)...)
			}
			pieces = next
		}
		out = append(out, pieces...)
	}
	t.v4 = out

	v6 := t.v6[:0]
	for _, a := range t.v6 {
		if _, excluded := ex.v6Set[a]; excluded {
			delete(t.v6Set, a)
			continue
		}
		v6 = append(v6, a)
	}
	t.v6 = v6

	names := t.names[:0]
	for _, n := range t.names {
		if _, excluded := ex.nameSet[n]; excluded {
			delete(t.nameSet, n)
			continue
		}
		names = append(names, n)
	}
	t.names = names
}

// cut returns the parts of r outside e.
func cut(r, e v4Range) []v4Range {
	if e.hi < r.lo || e.lo > r.hi {
		return []v4Range{r}
	}
	var out []v4Range
	if e.lo > r.lo {
		out = append(out, v4Range{r.lo, e.lo - 1})
	}
	if e.hi < r.hi {
		out = append(out, v4Range{e.hi + 1, r.hi})
	}
	return out
}

// Len returns the number of targets.
func (t *TargetSet) Len() int {
	n := len(t.v6) + len(t.names)
	for _, r := range t.v4 {
		n += int(r.hi-r.lo) + 1
	}
	return n
}

// Each calls fn for every target until fn returns false: IPv4 addresses in
// ascending order, then IPv6 addresses, then hostnames, in input order.
func (t *TargetSet) Each(fn func(DNHost) bool) {
	for _, r := range t.v4 {
		for v := uint64(r.lo); v <= uint64(r.hi); v++ {
			ip := make(net.IP, 4)
			binary.BigEndian.PutUint32(ip, uint32(v))
			if !fn(DNHost{IP: ip}) {
				return
			}
		}
	}
	for _, a := range t.v6 {
		if !fn(DNHost{IP: net.IP(a.AsSlice())}) {
			return
		}
	}
	for _, n := range t.names {
		if !fn(DNHost{Hostname: n}) {
			return
		}
	}
}

// ContainsIP reports whether ip is in the set.
func (t *TargetSet) ContainsIP(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	addr = addr.Unmap()
	if addr.Is4() {
		v := v4ToUint(addr)
		i := sort.Search(len(t.v4), func(i int) bool { return t.v4[i].hi >= v })
		return i < len(t.v4) && t.v4[i].lo <= v
	}
	_, ok = t.v6Set[addr]
	return ok
}

// ContainsName reports whether the set holds the hostname, ignoring case.
func (t *TargetSet) ContainsName(name string) bool {
	_, ok := t.nameSet[strings.ToLower(strings.TrimSuffix(name, "."))]
	return ok
}

// MatchesName reports whether name is excluded by the set: an exact,
// case-insensitive match, or a short name (no dot) in the set equal to the
// first label of name, so excluding fs01 also excludes fs01.corp.local.
func (t *TargetSet) MatchesName(name string) bool {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if _, ok := t.nameSet[name]; ok {
		return true
	}
	if first, _, found := strings.Cut(name, "."); found {
		if _, ok := t.nameSet[first]; ok {
			return true
		}
	}
	return false
}

// SystemLookup resolves a name with the system resolver.
func SystemLookup(ctx context.Context, name string) ([]net.IP, error) {
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, name)
	if err != nil {
		return nil, err
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		ips = append(ips, a.IP)
	}
	return ips, nil
}

// ResolveNames adds every address of the set's hostnames to the set, so an
// excluded name also excludes targets given as its IP address. It returns the
// names that could not be resolved; those stay excluded by name only.
func (t *TargetSet) ResolveNames(ctx context.Context, lookup func(context.Context, string) ([]net.IP, error)) []string {
	var unresolved []string
	for _, name := range t.names {
		ips, err := lookup(ctx, name)
		if err != nil || len(ips) == 0 {
			unresolved = append(unresolved, name)
			continue
		}
		for _, ip := range ips {
			if addr, ok := netip.AddrFromSlice(ip); ok {
				t.addAddr(addr.Unmap())
			}
		}
	}
	t.normalize()
	return unresolved
}

// Counts returns how many addresses and hostnames the set holds.
func (t *TargetSet) Counts() (addrs, names int) {
	return t.Len() - len(t.names), len(t.names)
}

// TargetsProducer returns a Producer that sends every target of the set.
func TargetsProducer(t *TargetSet) Producer {
	return func(ctx context.Context, out chan<- DNHost) error {
		var err error
		t.Each(func(h DNHost) bool {
			select {
			case <-ctx.Done():
				err = context.Cause(ctx)
				return false
			case out <- h:
				return true
			}
		})
		return err
	}
}

func v4ToUint(addr netip.Addr) uint32 {
	b := addr.As4()
	return binary.BigEndian.Uint32(b[:])
}

// Address returns the IP to connect to, or the hostname when the host has not
// been resolved locally (for example behind a SOCKS proxy).
func (h DNHost) Address() string {
	if h.IP != nil {
		return h.IP.String()
	}
	return h.Hostname
}

// resolveTarget resolves a hostname target (unless a proxy resolves it),
// applies --exclude-hosts to the resolved address and skips addresses that
// were already scanned. ok is false when the target must be skipped.
func (s *Scanner) resolveTarget(ctx context.Context, h DNHost) (DNHost, bool, error) {
	ex := s.Options.ExcludeHosts
	if h.Hostname != "" && ex != nil && ex.MatchesName(h.Hostname) {
		return h, false, nil
	}
	if h.IP == nil && h.Hostname != "" && !s.Options.Dialer.Proxied() {
		addrs, err := net.DefaultResolver.LookupIPAddr(ctx, h.Hostname)
		if err != nil {
			return h, false, fmt.Errorf("cannot resolve %s: %w", h.Hostname, err)
		}
		h.IP = preferIPv4(addrs)
		if h.IP == nil {
			return h, false, fmt.Errorf("cannot resolve %s: no addresses", h.Hostname)
		}
	}
	if h.IP != nil && ex != nil && ex.ContainsIP(h.IP) {
		return h, false, nil
	}
	if _, seen := s.scanned.LoadOrStore(strings.ToLower(h.Address()), struct{}{}); seen {
		return h, false, nil
	}
	return h, true, nil
}

func preferIPv4(addrs []net.IPAddr) net.IP {
	for _, a := range addrs {
		if v4 := a.IP.To4(); v4 != nil {
			return v4
		}
	}
	if len(addrs) > 0 {
		return addrs[0].IP
	}
	return nil
}
