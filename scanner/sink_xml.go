package scanner

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
)

// xmlSink writes the legacy XML format without holding listings in memory.
// Each share's <directory> and root <file> elements are spooled to temporary
// files while it is listed; when the host is finished its <host> element is
// assembled from them in one write, byte-for-byte as the old writer did.
type xmlSink struct {
	mu       sync.Mutex
	w        io.Writer
	spoolDir string
	hosts    map[*Host]map[*Share]*xmlSpool
	order    []*Host
	err      error
}

type xmlSpool struct {
	dirs, files *os.File // <directory> elements, then the root's <file> elements
}

// NewXMLSink writes <host> elements and, on Close, the footer to w, which
// already holds the XML header. Spool files go to spoolDir ("" = temp dir).
func NewXMLSink(w io.Writer, spoolDir string) Sink {
	return &xmlSink{w: w, spoolDir: spoolDir, hosts: make(map[*Host]map[*Share]*xmlSpool)}
}

func (x *xmlSink) fail(err error) {
	if err != nil && x.err == nil {
		x.err = err
	}
}

func (x *xmlSink) HostEnumerated(h *Host) {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.hosts[h] = make(map[*Share]*xmlSpool)
	x.order = append(x.order, h)
}

func (x *xmlSink) DirListed(h *Host, share *Share, dir Directory, depth int) {
	x.mu.Lock()
	defer x.mu.Unlock()
	shares, ok := x.hosts[h]
	if !ok {
		return
	}
	spool := shares[share]
	if spool == nil {
		spool = &xmlSpool{}
		shares[share] = spool
	}
	target := &spool.files
	if depth > 0 {
		target = &spool.dirs
	}
	if *target == nil {
		f, err := os.CreateTemp(x.spoolDir, "sharefinder-*.xml")
		if err != nil {
			x.fail(err)
			return
		}
		*target = f
	}
	enc := xml.NewEncoder(*target)
	if depth > 0 {
		x.fail(enc.EncodeElement(dir, xml.StartElement{Name: xml.Name{Local: "directory"}}))
	} else {
		for _, f := range dir.Files {
			x.fail(enc.EncodeElement(f, xml.StartElement{Name: xml.Name{Local: "file"}}))
		}
	}
	x.fail(enc.Flush())
}

func (x *xmlSink) ShareFinished(*Host, *Share) {}

func (x *xmlSink) HostFinished(h *Host) {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.writeHost(h)
}

// writeHost writes h's element and drops its spools. Callers hold x.mu.
func (x *xmlSink) writeHost(h *Host) {
	spools, ok := x.hosts[h]
	if !ok {
		return
	}
	delete(x.hosts, h)
	defer func() {
		for _, spool := range spools {
			for _, f := range []*os.File{spool.dirs, spool.files} {
				if f != nil {
					_ = f.Close()
					_ = os.Remove(f.Name())
				}
			}
		}
	}()

	facts := *h
	facts.Shares = nil
	hostStart, err := startTag(facts, "host")
	if err != nil {
		x.fail(err)
		return
	}
	var b bytes.Buffer
	b.WriteString(hostStart)
	for i := range h.Shares {
		share := &h.Shares[i]
		attrs := *share
		attrs.Directories, attrs.Files = nil, nil
		shareStart, err := startTag(attrs, "share")
		if err != nil {
			x.fail(err)
			return
		}
		b.WriteString(shareStart)
		if spool := spools[share]; spool != nil {
			for _, f := range []*os.File{spool.dirs, spool.files} {
				if f == nil {
					continue
				}
				if _, err := f.Seek(0, io.SeekStart); err != nil {
					x.fail(err)
					continue
				}
				_, err := io.Copy(&b, f)
				x.fail(err)
			}
		}
		b.WriteString("</share>")
	}
	b.WriteString("</host>\n")
	_, err = x.w.Write(b.Bytes())
	x.fail(err)
}

// startTag returns the start tag xml.Marshal writes for v as element name.
func startTag(v any, name string) (string, error) {
	var buf bytes.Buffer
	enc := xml.NewEncoder(&buf)
	if err := enc.EncodeElement(v, xml.StartElement{Name: xml.Name{Local: name}}); err != nil {
		return "", err
	}
	if err := enc.Flush(); err != nil {
		return "", err
	}
	element := buf.String()
	end := "</" + name + ">"
	if !strings.HasSuffix(element, end) {
		return "", errors.New("unexpected XML encoding of " + name)
	}
	return strings.TrimSuffix(element, end), nil
}

// Close writes the hosts still open, such as hosts cut short by Ctrl+C, and
// the footer.
func (x *xmlSink) Close(end EndRecord) error {
	x.mu.Lock()
	defer x.mu.Unlock()
	for _, h := range x.order {
		x.writeHost(h)
	}
	x.order = nil
	x.fail(NewOutputWriter().WriteXMLFooter(end.Time, x.w))
	return x.err
}
