package scanner

import (
	"io"
	"sync"

	"github.com/jfjallid/go-smb/smb"
)

// dialectLabel names a negotiated SMB2 dialect: 2.0.2, 2.1, 3.0, 3.0.2 or
// 3.1.1, or "" when unknown.
func dialectLabel(d uint16) string {
	switch d {
	case smb.DialectSmb_2_0_2, smb.DialectSmb_2_1, smb.DialectSmb_3_0, smb.DialectSmb_3_0_2, smb.DialectSmb_3_1_1:
		return smb.DialectString(d)
	}
	return ""
}

// RelaySink lists the hosts that do not require SMB signing, one address per
// line, as NTLM relay tools take their targets (--output-relay-list). It is
// fed by the negotiation (Options.OnNegotiated), so a host is listed whatever
// the logon gives: before any credentials work, relay targets matter most.
type RelaySink struct {
	mu   sync.Mutex
	w    io.Writer
	seen map[string]bool
	err  error // the first write error, returned by Close
}

// NewRelaySink starts a relay target list on w.
func NewRelaySink(w io.Writer) *RelaySink {
	return &RelaySink{w: w, seen: make(map[string]bool)}
}

// Negotiated lists host unless it requires signing.
func (r *RelaySink) Negotiated(host string, signingRequired bool) {
	if signingRequired {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.seen[host] {
		return
	}
	r.seen[host] = true
	if _, err := io.WriteString(r.w, host+"\n"); err != nil && r.err == nil {
		r.err = err
	}
}

func (r *RelaySink) HostEnumerated(*Host) {}

func (r *RelaySink) DirListed(*Host, *Share, Directory, int) {}
func (r *RelaySink) ShareFinished(*Host, *Share)             {}
func (r *RelaySink) HostFinished(*Host)                      {}

func (r *RelaySink) Close(EndRecord) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.err
}
