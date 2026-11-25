package scanner

import (
	"net"
	"os"
	"time"
)

// Options is a struct to store scanner's configuration
type Options struct {
	CustomResolver     net.IP // --resolver
	DCHostname         string
	Dialer             *Dialer // --proxy, --timeout, --io-timeout
	Domain             string  // part of --username
	DomainController   net.IP
	Exclude            []string // --exclude
	FileTXT            *os.File
	FileXML            *os.File
	Forest             bool          // --forest (hunt only)
	Hash               string        // --hashes
	HashBytes          []byte        // --hashes
	IOTimeout          time.Duration // --io-timeout
	Kerberos           bool
	List               bool // --list
	LocalAuth          bool // --local-auth
	NullSession        bool
	OutputRawFileName  string
	OutputXMLFileName  string
	OutputHTML         bool // --html
	OutputHTMLFileName string
	Password           string        // --password
	Recurse            bool          // --recurse
	SmbPort            int           // --smb-port
	Timeout            time.Duration // --timeout
	Username           string        // part of --username
	Writer             *OutputWriter
}
