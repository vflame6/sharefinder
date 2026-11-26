package scanner

import (
	"bytes"
	"encoding/xml"
	"path/filepath"
	"time"
)

type Timestamp struct {
	Time          time.Time `xml:"time,attr"`
	FormattedTime string    `xml:"formatted_time,attr"`
}

// SharefinderRun contains all data for a single scan
type SharefinderRun struct {
	Version            string    `xml:"version,attr"`
	Command            string    `xml:"command,attr"`
	TimeStart          time.Time `xml:"time_start,attr"`
	FormattedTimeStart string    `xml:"formatted_time_start,attr"`
	Hosts              []Host    `xml:"hosts>host"`
	TimeEnd            Timestamp `xml:"time_end"`
}

type Host struct {
	XMLName  xml.Name  `xml:"host"`
	Time     time.Time `xml:"time,attr"`
	IP       string    `xml:"ip,attr"`
	Version  string    `xml:"version,attr"`
	Hostname string    `xml:"hostname,attr"`
	Domain   string    `xml:"domain,attr"`
	Signing  bool      `xml:"signing,attr"`
	Dialect  string    `xml:"dialect,attr,omitempty"` // negotiated SMB dialect, such as 3.1.1
	Session  string    `xml:"session,attr,omitempty"`
	Admin    *bool     `xml:"admin,attr,omitempty"`
	// FQDN is the DNS name the host was scanned by, when the target was a
	// name (given by the user or found by hunt). UNC paths use it, else the
	// IP: the name a server reports for itself may point to another host.
	FQDN   string  `xml:"fqdn,attr,omitempty"`
	Shares []Share `xml:"share"`

	// Declared names every share the server listed that the scan covers,
	// checked or not; Error says why the shares could not be listed.
	Declared []string `xml:"-"`
	Error    string   `xml:"-"`
}

type Share struct {
	ShareName       string `xml:"share_name,attr"`
	Description     string `xml:"description,attr"`
	ReadPermission  bool   `xml:"read_permission,attr"`
	WritePermission bool   `xml:"write_permission,attr"`
	Truncated       bool   `xml:"truncated,attr,omitempty"`
	WriteAccess     string `xml:"write_access,attr,omitempty"`
	// Partial marks a share whose listing was cut short by Ctrl+C.
	Partial bool `xml:"partial,attr,omitempty"`
	// Directories and Files are filled when an XML file is read back; a scan
	// streams listings to the outputs instead of keeping them here.
	Directories []Directory `xml:"directory"`
	Files       []File      `xml:"file"`

	TypeID    uint32 `xml:"-"`
	ShareType string `xml:"-"` // disk, printer, device or ipc
	Listed    bool   `xml:"-"` // a listing was attempted
	FileCount int64  `xml:"-"`
	DirCount  int64  `xml:"-"`
	ListError string `xml:"-"`
}

type Directory struct {
	Parent       string    `xml:"parent,attr"`
	Name         string    `xml:"name,attr"`
	Size         uint64    `xml:"size,attr"`
	LastModified time.Time `xml:"last_modified,attr"`
	Files        []File    `xml:"file"`
}

type File struct {
	Parent       string    `xml:"parent,attr"`
	Type         string    `xml:"type,attr"`
	Name         string    `xml:"name,attr"`
	Size         uint64    `xml:"size,attr"`
	LastModified time.Time `xml:"last_modified,attr"`
}

// escapeXML escapes special XML characters in a string
func escapeXML(input string) string {
	var buffer bytes.Buffer
	_ = xml.EscapeText(&buffer, []byte(input))
	return buffer.String()
}

// ParseSharefinderRun takes a byte array of nmap xml data and unmarshalls it into SharefinderRun struct.
func ParseSharefinderRun(content []byte) (*SharefinderRun, error) {
	r := &SharefinderRun{}
	err := xml.Unmarshal(content, r)
	return r, err
}

func NewFile(filetype, filename, parent string, size uint64, lastModified time.Time) *File {
	return &File{
		Type:         filetype,
		Name:         filename,
		Parent:       parent,
		Size:         size,
		LastModified: lastModified,
	}
}

func NewDirectory(filename string, size uint64, lastModified time.Time, files []File) *Directory {
	parent := filepath.Dir(filename)
	if parent == "." {
		parent = ""
	}
	return &Directory{
		Parent:       parent,
		Name:         filename,
		Size:         size,
		LastModified: lastModified,
		Files:        files,
	}
}
