package cmd

import "time"

// Config carries the global command-line options shared by every scan command.
type Config struct {
	Version     string
	CommandLine []string
	TimeStart   time.Time

	OutputRaw   string // -o/--output
	OutputXML   string // --output-xml
	OutputJSON  string // --output-json
	OutputCSV   string // --output-csv
	OutputUNC   string // --output-unc
	OutputRelay string // --output-relay-list
	OutputAll   string // --output-all
	OutputHTML  string // --output-html
	Force       bool   // --force: overwrite existing output files
	Resume      string // --resume: the JSONL file of an interrupted scan

	Threads   int           // --threads
	Timeout   time.Duration // --timeout: connect timeout
	IOTimeout time.Duration // --io-timeout: idle bound on every read and write
	SmbPort   int           // --smb-port
	Proxy     string        // --proxy

	// discovery sweep
	DisableDiscovery bool          // --disable-discovery
	DiscoveryThreads int           // --discovery-threads
	ConnectTimeout   time.Duration // --connect-timeout

	MaxAuthFailures int    // --max-auth-failures
	WriteCheck      string // --write-check

	Exclude            string // --exclude
	ExcludeHosts       string // --exclude-hosts
	List               bool   // --list
	Recurse            bool   // --recurse
	Depth              int    // --depth
	DisableFollowLinks bool   // --disable-follow-links: do not descend into symlinks and junctions
	MaxFiles           int    // --max-files
	MaxConnsPerHost    int    // --max-conns-per-host
}
