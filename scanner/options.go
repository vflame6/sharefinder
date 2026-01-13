package scanner

import (
	"golang.org/x/net/proxy"
	"net"
	"os"
	"time"
)

// Options is a struct to store scanner's configuration
type Options struct {
	CustomResolver     net.IP // --resolver
	DCHostname         string
	Domain             string // part of --username
	DomainController   net.IP
	Exclude            []string // --exclude
	FileTXT            *os.File
	FileXML            *os.File
	Hash               string // --hashes
	HashBytes          []byte // --hashes
	Kerberos           bool
	List               bool // --list
	LocalAuth          bool // --local-auth
	OutputRawFileName  string
	OutputXMLFileName  string
	OutputHTML         bool // --html
	OutputHTMLFileName string
	Password           string       // --password
	ProxyDialer        proxy.Dialer // --proxy
	Recurse            bool         // --recurse
	SmbPort            int          // --smb-port
	Target             chan DNHost
	Timeout            time.Duration // --timeout
	Username           string        // part of --username
	Writer             *OutputWriter
}
