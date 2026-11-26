package scanner

import (
	"net"
	"os"
	"time"
)

// Options is a struct to store scanner's configuration
type Options struct {
	AESKey             []byte     // --aes-key: Kerberos AES key of the user
	AllowPlaintextLDAP bool       // --allow-plaintext-ldap (hunt)
	AuthGuard          *AuthGuard // --max-auth-failures
	CustomResolver     net.IP     // --resolver
	DCHostname         string
	Dialer             *Dialer     // --proxy, --timeout, --io-timeout
	Domain             string      // part of --username
	Depth              int         // --depth
	Discovery          SweepConfig // --discovery, --discovery-threads, --connect-timeout
	DomainController   net.IP
	Exclude            []string   // --exclude
	ExcludeHosts       *TargetSet // --exclude-hosts
	FileTXT            *os.File
	FileCSV            *os.File // --output-csv
	FileJSON           *os.File // --output-json
	FileUNC            *os.File // --output-unc
	FileRelay          *os.File // --output-relay-list
	FileXML            *os.File
	FollowLinks        bool          // --follow-links
	Forest             bool          // --forest (hunt only)
	Hash               string        // --hashes
	HashBytes          []byte        // --hashes
	IOTimeout          time.Duration // --io-timeout
	Kerberos           bool
	List               bool // --list
	MaxFiles           int  // --max-files
	MaxConnsPerHost    int  // --max-conns-per-host: connections that list one host's shares
	LocalAuth          bool // --local-auth
	Mode               AuthMode
	NullSession        bool
	OutputRawFileName  string
	OutputXMLFileName  string
	OutputJSONFileName string
	OutputHTML         bool // --html
	OutputHTMLFileName string
	Password           string         // --password
	Progress           bool           // draw a progress line: stderr is a terminal, no --quiet or --debug
	Recurse            bool           // --recurse
	Resume             *ResumeState   // --resume: what the interrupted scan finished
	SmbPort            int            // --smb-port
	Timeout            time.Duration  // --timeout
	Username           string         // part of --username
	WriteCheck         WriteCheckMode // --write-check
	Sink               Sink           // where results go; built by StartOutputs
	Writer             *OutputWriter
}
