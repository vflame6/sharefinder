package scanner

import (
	"crypto/rand"
	"encoding/binary"
	"net/netip"
	"strings"
	"time"

	"github.com/jfjallid/go-smb/dcerpc/mssrvs"
)

// JSONL record types. Every line of --output-json is one self-contained
// record; host, share and file records carry scan_id, identity, host and a
// UNC path, so an interrupted scan still yields a usable file.
const (
	RecordScan  = "scan"
	RecordHost  = "host"
	RecordShare = "share"
	RecordFile  = "file"
	RecordEnd   = "end"
)

// ScanRecord opens a scan: what ran, when, as whom.
type ScanRecord struct {
	Type     string    `json:"type"`
	ScanID   string    `json:"scan_id"`
	Time     time.Time `json:"time"`
	Version  string    `json:"version,omitempty"`
	Command  string    `json:"command,omitempty"`
	Identity string    `json:"identity"`
}

// HostRecord describes a host that accepted the scan's identity.
type HostRecord struct {
	Type     string    `json:"type"`
	ScanID   string    `json:"scan_id"`
	Time     time.Time `json:"time"`
	Identity string    `json:"identity"`
	Host     string    `json:"host"`
	Hostname string    `json:"hostname,omitempty"`
	Domain   string    `json:"domain,omitempty"`
	UNC      string    `json:"unc"`
	OS       string    `json:"os,omitempty"`
	Signing  bool      `json:"signing"`
	Dialect  string    `json:"dialect,omitempty"`
	Session  string    `json:"session,omitempty"`
	Admin    *bool     `json:"admin,omitempty"`
	Shares   []string  `json:"shares"`
	Error    string    `json:"error,omitempty"`
}

// ShareRecord is written when a share is finished: checked, and listed when
// --list is set. A share without a record was not finished.
type ShareRecord struct {
	Type        string    `json:"type"`
	ScanID      string    `json:"scan_id"`
	Time        time.Time `json:"time"`
	Identity    string    `json:"identity"`
	Host        string    `json:"host"`
	Hostname    string    `json:"hostname,omitempty"`
	Share       string    `json:"share"`
	UNC         string    `json:"unc"`
	Read        bool      `json:"read"`
	Write       bool      `json:"write"`
	WriteAccess []string  `json:"write_access,omitempty"`
	Remark      string    `json:"remark,omitempty"`
	ShareType   string    `json:"share_type,omitempty"`
	Listed      bool      `json:"listed,omitempty"`
	Files       int64     `json:"files,omitempty"`
	Dirs        int64     `json:"dirs,omitempty"`
	Truncated   bool      `json:"truncated,omitempty"`
	Partial     bool      `json:"partial,omitempty"`
	Error       string    `json:"error,omitempty"`
}

// FileRecord is one listed file, directory or link.
type FileRecord struct {
	Type     string    `json:"type"`
	ScanID   string    `json:"scan_id"`
	Identity string    `json:"identity"`
	Host     string    `json:"host"`
	Share    string    `json:"share"`
	UNC      string    `json:"unc"`
	Kind     string    `json:"kind"`
	Size     uint64    `json:"size"`
	Modified time.Time `json:"modified"`
	Tags     []string  `json:"tags,omitempty"`
}

// EndRecord closes a scan with its counts.
type EndRecord struct {
	Type          string    `json:"type"`
	ScanID        string    `json:"scan_id"`
	Time          time.Time `json:"time"`
	Identity      string    `json:"identity"`
	Targets       int       `json:"targets"`
	Reachable     int       `json:"reachable"`
	Authenticated int       `json:"authenticated"`
	Failed        int       `json:"failed"`
	Interrupted   bool      `json:"interrupted,omitempty"`
	Error         string    `json:"error,omitempty"` // why the scan stopped early
}

const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// NewScanID returns a ULID: 48 bits of milliseconds and 80 random bits in 26
// Crockford base32 characters, so ids sort by start time.
func NewScanID() string {
	var b [16]byte
	binary.BigEndian.PutUint64(b[:8], uint64(time.Now().UnixMilli())<<16)
	_, _ = rand.Read(b[6:])
	hi, lo := binary.BigEndian.Uint64(b[:8]), binary.BigEndian.Uint64(b[8:])
	out := make([]byte, 26)
	// 128 bits = 26 characters of 5 bits, the first one carrying 3 bits
	for i := 25; i >= 0; i-- {
		out[i] = crockford[lo&31]
		lo = lo>>5 | hi<<59
		hi >>= 5
	}
	return string(out)
}

// UNC builds //host/part/part with forward slashes; backslashes inside parts
// become slashes and IPv6 hosts are bracketed.
func UNC(host string, parts ...string) string {
	if addr, err := netip.ParseAddr(host); err == nil && addr.Is6() && !addr.Is4In6() {
		host = "[" + host + "]"
	}
	var b strings.Builder
	b.WriteString("//")
	b.WriteString(host)
	for _, part := range parts {
		part = strings.Trim(strings.ReplaceAll(part, `\`, "/"), "/")
		if part == "" {
			continue
		}
		b.WriteString("/")
		b.WriteString(part)
	}
	return b.String()
}

// uncHost is the host part of a UNC path: the FQDN when known, so content
// scanners can resolve it, else the IP address.
func uncHost(h *Host) string {
	if h.FQDN != "" {
		return h.FQDN
	}
	return h.IP
}

// shareTypeName names a share type from NetShareEnumAll.
func shareTypeName(typeID uint32) string {
	switch typeID {
	case mssrvs.StypePrintq:
		return "printer"
	case mssrvs.StypeDevice:
		return "device"
	case mssrvs.StypeIPC:
		return "ipc"
	default:
		return "disk"
	}
}

// Identity names who the scan logs on as: null, guest, DOMAIN\user or user.
func (o *Options) Identity() string {
	switch o.Mode {
	case AuthNull:
		return "null"
	case AuthGuest:
		return "guest"
	}
	if o.Domain != "" && !o.LocalAuth {
		return o.Domain + `\` + o.Username
	}
	return o.Username
}
