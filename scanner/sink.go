package scanner

import (
	"errors"
	"fmt"
	"strings"
	"unicode"

	"github.com/jfjallid/go-smb/smb"
	"github.com/vflame6/sharefinder/utils"
)

// Sink receives scan results as they are produced, so that no host's tree has
// to be held in memory. Implementations are safe for concurrent use: workers
// call them for different hosts at the same time, and events of one host
// arrive in order.
type Sink interface {
	// HostEnumerated: the host's facts and its permission-checked shares.
	HostEnumerated(h *Host)
	// DirListed: one listed directory of share; depth 0 is the share root,
	// whose Directory has an empty Name.
	DirListed(h *Host, share *Share, dir Directory, depth int)
	// ShareFinished: share is checked and, with --list, listed. Its
	// FileCount, DirCount, Truncated, Partial and ListError are final.
	ShareFinished(h *Host, share *Share)
	// HostFinished: every share of h is finished.
	HostFinished(h *Host)
	// Close ends the output after the scan.
	Close(end EndRecord) error
}

// MultiSink sends every event to each of its sinks.
type MultiSink []Sink

func (m MultiSink) HostEnumerated(h *Host) {
	for _, s := range m {
		s.HostEnumerated(h)
	}
}

func (m MultiSink) DirListed(h *Host, share *Share, dir Directory, depth int) {
	for _, s := range m {
		s.DirListed(h, share, dir, depth)
	}
}

func (m MultiSink) ShareFinished(h *Host, share *Share) {
	for _, s := range m {
		s.ShareFinished(h, share)
	}
}

func (m MultiSink) HostFinished(h *Host) {
	for _, s := range m {
		s.HostFinished(h)
	}
}

func (m MultiSink) Close(end EndRecord) error {
	var errs []error
	for _, s := range m {
		errs = append(errs, s.Close(end))
	}
	return errors.Join(errs...)
}

// listingEmitter converts walker output into DirListed events for share.
func listingEmitter(sink Sink, h *Host, share *Share) func(dir smb.SharedFile, depth int, entries []smb.SharedFile) {
	return func(dir smb.SharedFile, depth int, entries []smb.SharedFile) {
		listed := Directory{Files: listingFiles(entries)}
		if depth > 0 {
			listed = *NewDirectory(dir.FullPath, dir.Size, utils.ConvertToUnixTimestamp(dir.LastWriteTime), listed.Files)
		}
		sink.DirListed(h, share, listed, depth)
	}
}

// printable escapes control characters in server-supplied text, so a file
// name or remark cannot break lines or send terminal escape sequences.
func printable(s string) string {
	if strings.IndexFunc(s, unicode.IsControl) < 0 {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		if unicode.IsControl(r) {
			fmt.Fprintf(&b, `\x%02x`, r)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
