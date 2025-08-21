package scanner

import (
	"golang.org/x/net/proxy"
	"net"
	"os"
	"time"
)

// Options is a struct to store scanner's configuration
type Options struct {
	SmbPort          int    // --smb-port
	OutputFileName   string // --output-*
	OutputHTML       bool   // --html
	Writer           *OutputWriter
	FileTXT          *os.File
	FileXML          *os.File
	Timeout          time.Duration // --timeout
	Exclude          []string      // --exclude
	Target           chan DNHost
	Username         string // part of --username
	Domain           string // part of --username
	Password         string // --password
	Hashes           []byte // --hashes
	Kerberos         bool
	List             bool // --list
	Recurse          bool // --recurse
	LocalAuth        bool // --local-auth
	DomainController net.IP
	DCHostname       string
	CustomResolver   net.IP       // --resolver
	ProxyDialer      proxy.Dialer // --proxy
}

// NewOptions is a function to generate new Options object
func NewOptions(smbPort int, outputHTML bool, outputFile string, writer *OutputWriter, file, fileXML *os.File, timeout time.Duration, exclude []string, username, password string, hashes []byte, kerberos bool, domain string, localAuth, list, recurse bool, domainController net.IP, dcHostname string, proxyDialer proxy.Dialer) *Options {
	return &Options{
		SmbPort:          smbPort,
		OutputHTML:       outputHTML,
		OutputFileName:   outputFile,
		Writer:           writer,
		FileTXT:          file,
		FileXML:          fileXML,
		Timeout:          timeout,
		Exclude:          exclude,
		Target:           make(chan DNHost, 256),
		Username:         username,
		Password:         password,
		Hashes:           hashes,
		Kerberos:         kerberos,
		Domain:           domain,
		LocalAuth:        localAuth,
		List:             list,
		Recurse:          recurse,
		DomainController: domainController,
		DCHostname:       dcHostname,
		ProxyDialer:      proxyDialer,
	}
}
