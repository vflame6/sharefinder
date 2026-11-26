package scanner

import (
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/vflame6/sharefinder/logger"
)

// textSink prints results to the console and, with -o, to a text file: the
// host line and share table when a host is enumerated, then one block per
// listed directory as it is listed.
type textSink struct {
	mu   sync.Mutex
	file io.Writer // nil without -o
}

// NewTextSink prints results on stdout and also writes them to file when it
// is not nil.
func NewTextSink(file io.Writer) Sink {
	return &textSink{file: file}
}

func (t *textSink) emit(block string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	logger.Info(block)
	if t.file != nil {
		if !strings.HasSuffix(block, "\n") {
			block += "\n"
		}
		if _, err := io.WriteString(t.file, block); err != nil {
			logger.Error(fmt.Errorf("writing text output: %w", err))
		}
	}
}

func (t *textSink) HostEnumerated(h *Host) {
	block := SprintHostLine(*h)
	if len(h.Shares) > 0 {
		block += SprintHost(*h, nil)
	}
	t.emit(block)
}

func (t *textSink) DirListed(h *Host, share *Share, dir Directory, depth int) {
	var b strings.Builder
	if depth == 0 {
		fmt.Fprintf(&b, "Listing share %s\\%s\n", h.IP, printable(share.ShareName))
	} else {
		fmt.Fprintf(&b, "Listing directory %s\\%s\\%s\n", h.IP, printable(share.ShareName), printable(dir.Name))
	}
	writeListingHeader(&b)
	writeFiles(&b, dir.Files)
	b.WriteString("\n")
	t.emit(b.String())
}

func (t *textSink) ShareFinished(*Host, *Share) {}
func (t *textSink) HostFinished(*Host)          {}
func (t *textSink) Close(EndRecord) error       { return nil }
