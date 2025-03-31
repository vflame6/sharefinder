package scanner

import (
	"net"
	"os"
	"time"
)

type Options struct {
	SmbPort          int
	Output           bool
	OutputHTML       bool
	OutputFile       string
	Writer           *OutputWriter
	File             *os.File
	FileXML          *os.File
	Timeout          time.Duration
	Exclude          []string
	Target           chan string
	Username         string
	Password         string
	Domain           string
	List             bool
	Recurse          bool
	LocalAuth        bool
	DomainController net.IP
}

func NewOptions(smbPort int, output, outputHTML bool, outputFile string, writer *OutputWriter, file, fileXML *os.File, timeout time.Duration, exclude []string, target chan string, username, password, domain string, localAuth, list, recurse bool, domainController net.IP) *Options {
	return &Options{
		SmbPort:          smbPort,
		Output:           output,
		OutputHTML:       outputHTML,
		OutputFile:       outputFile,
		Writer:           writer,
		File:             file,
		FileXML:          fileXML,
		Timeout:          timeout,
		Exclude:          exclude,
		Target:           target,
		Username:         username,
		Password:         password,
		Domain:           domain,
		LocalAuth:        localAuth,
		List:             list,
		Recurse:          recurse,
		DomainController: domainController,
	}
}
