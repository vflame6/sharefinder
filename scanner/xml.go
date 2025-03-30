package scanner

import (
	"bytes"
	"encoding/xml"
	"time"
)

type Timestamp struct {
	Time time.Time `xml:"time,attr"`
}

// SharefinderRun contains all data for a single scan
type SharefinderRun struct {
	Command   string    `xml:"command,attr"`
	TimeStart time.Time `xml:"time_start,attr"`
	Hosts     []Host    `xml:"hosts"`
	TimeEnd   Timestamp `xml:"time_end"`
}

type Host struct {
	Time     time.Time `xml:"time,attr"`
	IP       string    `xml:"ip,attr"`
	Version  string    `xml:"version,attr"`
	Hostname string    `xml:"hostname,attr"`
	Domain   string    `xml:"domain,attr"`
	Signing  bool      `xml:"signing,attr"`
	Shares   []Share   `xml:"share"`
}

type Share struct {
	Name            string      `xml:"name,attr"`
	Description     string      `xml:"description,attr"`
	ReadPermission  bool        `xml:"read_permission,attr"`
	WritePermission bool        `xml:"write_permission,attr"`
	Directories     []Directory `xml:"directory"`
	Files           []File      `xml:"file"`
}

type Directory struct {
	Parent       string      `xml:"parent,attr"`
	Type         string      `xml:"type,attr"`
	Name         string      `xml:"name,attr"`
	Size         uint64      `xml:"size,attr"`
	LastModified time.Time   `xml:"last_modified,attr"`
	Directories  []Directory `xml:"directory"`
	Files        []File      `xml:"file"`
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

// ParseSharefinderRun takes a byte array of nmap xml data and unmarshals it into an
// SharefinderRun struct.
func ParseSharefinderRun(content []byte) (*SharefinderRun, error) {
	r := &SharefinderRun{}
	err := xml.Unmarshal(content, r)
	return r, err
}

func NewFile(filetype, filename string, size uint64, lastModified time.Time) *File {
	return &File{
		Type:         filetype,
		Name:         filename,
		Size:         size,
		LastModified: lastModified,
	}
}

func NewDirectory(filetype, filename string, size uint64, lastModified time.Time, directories []Directory, files []File) *Directory {
	return &Directory{
		Type:         filetype,
		Name:         filename,
		Size:         size,
		LastModified: lastModified,
		Directories:  directories,
		Files:        files,
	}
}
