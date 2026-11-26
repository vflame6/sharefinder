package cmd

import "time"

// Config carries the global command-line options shared by every scan command.
type Config struct {
	Version     string
	CommandLine []string
	TimeStart   time.Time

	OutputRaw  string // -o/--output
	OutputXML  string // --output-xml
	OutputAll  string // --output-all
	OutputHTML bool   // --html
	Force      bool   // --force: overwrite existing output files

	Threads   int           // --threads
	Timeout   time.Duration // --timeout: connect timeout
	IOTimeout time.Duration // --io-timeout: idle bound on every read and write
	SmbPort   int           // --smb-port
	Proxy     string        // --proxy

	MaxAuthFailures int    // --max-auth-failures
	WriteCheck      string // --write-check

	Exclude      string // --exclude
	ExcludeHosts string // --exclude-hosts
	List         bool   // --list
	Recurse      bool   // --recurse
	Depth        int    // --depth
	FollowLinks  bool   // --follow-links
	MaxFiles     int    // --max-files
}
