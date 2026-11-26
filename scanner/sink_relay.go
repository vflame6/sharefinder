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

// relaySink lists the hosts that do not require SMB signing, one address per
// line, as NTLM relay tools take their targets (--output-relay-list).
type relaySink struct {
	mu   sync.Mutex
	w    io.Writer
	seen map[string]bool
	err  error // the first write error, returned by Close
}

// NewRelaySink starts a relay target list on w.
func NewRelaySink(w io.Writer) Sink {
	return &relaySink{w: w, seen: make(map[string]bool)}
}

func (r *relaySink) HostEnumerated(h *Host) {
	if h.Signing {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.seen[h.IP] {
		return
	}
	r.seen[h.IP] = true
	if _, err := io.WriteString(r.w, h.IP+"\n"); err != nil && r.err == nil {
		r.err = err
	}
}

func (r *relaySink) DirListed(*Host, *Share, Directory, int) {}
func (r *relaySink) ShareFinished(*Host, *Share)             {}
func (r *relaySink) HostFinished(*Host)                      {}

func (r *relaySink) Close(EndRecord) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.err
}
