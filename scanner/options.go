package scanner

import (
	"golang.org/x/net/proxy"
	"net"
	"os"
	"time"
)

// Options is a struct to store scanner's configuration
type Options struct {
	SmbPort          int // --smb-port
	Output           bool
	OutputFileName   string // --output
	OutputHTML       bool   // --html
	Writer           *OutputWriter
	FileTXT          *os.File
	FileXML          *os.File
	Timeout          time.Duration // --timeout
	Exclude          []string      // --exclude
	Target           chan string
	Username         string // part of --username
	Domain           string // part of --username
	Password         string // --password
	Hashes           []byte // --hashes
	List             bool   // --list
	Recurse          bool   // --recurse
	LocalAuth        bool   // --local-auth
	DomainController net.IP
	CustomResolver   net.IP       // --resolver
	ProxyDialer      proxy.Dialer // --proxy
}

// NewOptions is a function to generate new Options object
func NewOptions(smbPort int, output, outputHTML bool, outputFile string, writer *OutputWriter, file, fileXML *os.File, timeout time.Duration, exclude []string, target chan string, username, password string, hashes []byte, domain string, localAuth, list, recurse bool, domainController net.IP, proxyDialer proxy.Dialer) *Options {
	return &Options{
		SmbPort:          smbPort,
		Output:           output,
		OutputHTML:       outputHTML,
		OutputFileName:   outputFile,
		Writer:           writer,
		FileTXT:          file,
		FileXML:          fileXML,
		Timeout:          timeout,
		Exclude:          exclude,
		Target:           target,
		Username:         username,
		Password:         password,
		Hashes:           hashes,
		Domain:           domain,
		LocalAuth:        localAuth,
		List:             list,
		Recurse:          recurse,
		DomainController: domainController,
		ProxyDialer:      proxyDialer,
	}
}
