package main

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/alecthomas/kingpin/v2"
	"github.com/vflame6/sharefinder/cmd"
	"github.com/vflame6/sharefinder/logger"
	"golang.org/x/term"
)

// set when the user gives the flag: --proxy changes their defaults
var discoveryThreadsSet, connectTimeoutSet bool

// set when -p is given, even empty: it then wins over SHAREFINDER_PASSWORD
// and the prompt
var authPasswordSet, huntPasswordSet bool

// program options
var (
	// program description
	app = kingpin.New("sharefinder", "sharefinder is a network share discovery tool that enumerates shares, permissions and files in networks and domains.")

	// global flags

	// log output flags
	debugFlag = app.Flag("debug", "Enable debug mode, print debug messages").Bool()
	quietFlag = app.Flag("quiet", "Enable quiet mode, print only results").Bool()

	// file output flags
	outputRawFlag   = app.Flag("output", "Filename to write output in raw format").Short('o').Default("").String()
	outputXMLFlag   = app.Flag("output-xml", "Filename to write XML formatted output").Default("").String()
	outputJSONFlag  = app.Flag("output-json", "Filename to write JSONL output: one record per line, written as results arrive").Default("").String()
	outputCSVFlag   = app.Flag("output-csv", "Filename to write CSV output: one row per share").Default("").String()
	outputUNCFlag   = app.Flag("output-unc", "Filename to write the readable shares as //host/share lines, for content scanners").Default("").String()
	outputRelayFlag = app.Flag("output-relay-list", "Filename to write the hosts that do not require SMB signing, one address per line, for NTLM relay tools").Default("").String()
	outputAllFlag   = app.Flag("output-all", "Filename to write output in all formats").Default("").String()
	outputHTMLFlag  = app.Flag("html", "Write an HTML report named after --output-json or --output-xml").Default("false").Bool()
	forceFlag       = app.Flag("force", "Overwrite existing output files").Bool()
	resumeFlag      = app.Flag("resume", "Continue the interrupted scan in this --output-json file: finished hosts and shares are skipped").PlaceHolder("SCAN.jsonl").String()

	// connection flags
	threadsFlag          = app.Flag("threads", "Number of threads").Default("10").Int()
	timeoutFlag          = app.Flag("timeout", "Seconds to wait for connection").Default("5s").Duration()
	ioTimeoutFlag        = app.Flag("io-timeout", "Abort an SMB or LDAP operation when the server sends nothing for this long").Default("30s").Duration()
	smbPortFlag          = app.Flag("smb-port", "Target port of SMB service").Default("445").Int()
	proxyFlag            = app.Flag("proxy", "SOCKS-proxy address to use for connection in format IP:PORT").Default("").String()
	discoveryFlag        = app.Flag("discovery", "Probe the SMB port of every target first and enumerate only the hosts that answer").Default("true").Bool()
	discoveryThreadsFlag = app.Flag("discovery-threads", "Number of concurrent port probes (50 by default with --proxy)").Default("500").IsSetByUser(&discoveryThreadsSet).Int()
	connectTimeoutFlag   = app.Flag("connect-timeout", "Time to wait for the SMB port to answer a probe (--timeout by default with --proxy)").Default("1s").IsSetByUser(&connectTimeoutSet).Duration()
	maxAuthFailuresFlag  = app.Flag("max-auth-failures", "Stop the scan after this many rejected logons; 0 disables the guard").Default("1").Int()

	// SMB interaction flags
	excludeFlag         = app.Flag("exclude", "Exclude list").Short('e').Default("IPC$,NETLOGON,ADMIN$,print$,C$").String()
	excludeHostsFlag    = app.Flag("exclude-hosts", "Skip these targets: IPs, CIDRs, ranges, hostnames (comma-separated) or a file").Default("").String()
	listFlag            = app.Flag("list", "List readable shares").Default("false").Bool()
	recurseFlag         = app.Flag("recurse", "List readable shares recursively").Default("false").Bool()
	depthFlag           = app.Flag("depth", "Maximum directory depth below the share root for --recurse (0 lists the root only)").Default("5").Int()
	followLinksFlag     = app.Flag("follow-links", "Descend into directory symlinks and junctions during --recurse").Bool()
	maxFilesFlag        = app.Flag("max-files", "Stop listing a share after this many entries (0 = no limit)").Default("0").Int()
	maxConnsPerHostFlag = app.Flag("max-conns-per-host", "Connections that list the shares of one host in parallel, while --threads allows").Default("2").Int()
	writeCheckFlag      = app.Flag("write-check", "How to test write access: mask (open the share root with write rights, creates nothing), file (create and delete a temporary file) or off").Default("file").Enum("mask", "file", "off")

	// null command
	// find null sessions shares and permissions
	nullCommand   = app.Command("null", "null session module")
	nullTargetArg = nullCommand.Arg("target", "Target, IP range of filename").Required().String()

	// guest command
	// find guest authentication shares and permissions
	guestCommand      = app.Command("guest", "guest module")
	guestTargetArg    = guestCommand.Arg("target", "Target, IP range or filename").Required().String()
	guestUsernameFlag = guestCommand.Flag("username", "Username to authenticate as Guest").String()

	// auth command
	// find authenticated shares and permissions
	authCommand        = app.Command("auth", "authenticated module")
	authTargetArg      = authCommand.Arg("target", "Target, IP range or filename").Required().String()
	authUsernameFlag   = authCommand.Flag("username", "Username in format DOMAIN\\username for domain auth, and just username for local auth").Short('u').Required().String()
	authPasswordFlag   = authCommand.Flag("password", "User's password; without it, SHAREFINDER_PASSWORD or a prompt").Short('p').IsSetByUser(&authPasswordSet).String()
	authHashFlag       = authCommand.Flag("hashes", "NTLM hash of password to authenticate").Short('H').String()
	authAESKeyFlag     = authCommand.Flag("aes-key", "Kerberos AES128 or AES256 key of the user, in hex (with -k)").String()
	authLocalAuthFlag  = authCommand.Flag("local-auth", "Enable local authentication, the username is passed without domain").Bool()
	authKerberosFlag   = authCommand.Flag("kerberos", "Use Kerberos authentication").Short('k').Bool()
	authDcHostnameFlag = authCommand.Flag("dc-hostname", "Hostname of domain controller for Kerberos authentication").String()
	authDcIPFlag       = authCommand.Flag("dc-ip", "IP of KDC when using Kerberos authentication").IP()

	// hunt command
	// hunt for targets from AD and find shares and permissions
	huntCommand        = app.Command("hunt", "hunting module")
	huntDcArg          = huntCommand.Arg("dc", "Domain Controller IP").Required().IP()
	huntUsernameFlag   = huntCommand.Flag("username", "Domain username in format DOMAIN\\username").Short('u').Required().String()
	huntPasswordFlag   = huntCommand.Flag("password", "Domain user's password; without it, SHAREFINDER_PASSWORD or a prompt").Short('p').IsSetByUser(&huntPasswordSet).String()
	huntHashFlag       = huntCommand.Flag("hashes", "NTLM hash of password to authenticate").Short('H').String()
	huntAESKeyFlag     = huntCommand.Flag("aes-key", "Kerberos AES128 or AES256 key of the user, in hex (with -k)").String()
	huntResolverFlag   = huntCommand.Flag("resolver", "Custom DNS resolver IP address").Short('r').IP()
	huntForestFlag     = huntCommand.Flag("forest", "Search all available domains in the current forest").Default("false").Bool()
	huntKerberosFlag   = huntCommand.Flag("kerberos", "Use Kerberos authentication").Short('k').Bool()
	huntDcHostnameFlag = huntCommand.Flag("dc-hostname", "Hostname of domain controller for Kerberos authentication").String()
	huntAllowPlainFlag = huntCommand.Flag("allow-plaintext-ldap", "Allow a simple bind, which sends the password, over LDAP without TLS when LDAPS and StartTLS fail").Bool()

	// report command
	// render the HTML report of a JSONL file
	reportCommand  = app.Command("report", "Write the HTML report of an --output-json file, named after it or after -o")
	reportInputArg = reportCommand.Arg("jsonl", "JSONL file written by --output-json").Required().ExistingFile()

	// diff command
	// compare two JSONL scans
	diffCommand = app.Command("diff", "Print the shares that are new, removed or have other permissions in the later of two --output-json files")
	diffOldArg  = diffCommand.Arg("old", "Earlier JSONL scan").Required().ExistingFile()
	diffNewArg  = diffCommand.Arg("new", "Later JSONL scan").Required().ExistingFile()
)

func main() {
	// kingpin settings
	app.Version(cmd.VERSION)
	app.Author(cmd.AUTHOR)
	app.HelpFlag.Short('h')
	app.UsageTemplate(kingpin.CompactUsageTemplate)

	// parse options
	command := kingpin.MustParse(app.Parse(os.Args[1:]))

	// print program banner
	if !*quietFlag {
		cmd.PrintBanner(os.Stderr)
	}

	// set up a logger
	err := logger.SetLoggerOptions(*debugFlag, *quietFlag)
	if err != nil {
		logger.Fatal(err)
	}

	// report and diff read finished scan files: no scanner is set up
	if command == reportCommand.FullCommand() {
		if *outputXMLFlag != "" || *outputJSONFlag != "" || *outputCSVFlag != "" || *outputUNCFlag != "" || *outputRelayFlag != "" || *outputAllFlag != "" || *outputHTMLFlag {
			logger.Fatal(errors.New("report writes only the HTML report: name it with -o"))
		}
		if err := cmd.ExecuteReport(*reportInputArg, *outputRawFlag, *forceFlag); err != nil {
			logger.Fatal(err)
		}
		return
	}
	if command == diffCommand.FullCommand() {
		if *outputRawFlag != "" || *outputXMLFlag != "" || *outputJSONFlag != "" || *outputCSVFlag != "" || *outputUNCFlag != "" || *outputRelayFlag != "" || *outputAllFlag != "" || *outputHTMLFlag {
			logger.Fatal(errors.New("diff prints to stdout: output flags do not apply"))
		}
		if err := cmd.ExecuteDiff(*diffOldArg, *diffNewArg); err != nil {
			logger.Fatal(err)
		}
		return
	}

	// set up a scanner
	scanner, err := cmd.CreateScanner(cmd.Config{
		Version:             cmd.VERSION,
		CommandLine:         os.Args[1:],
		TimeStart:           time.Now(),
		OutputRaw:           *outputRawFlag,
		OutputXML:           *outputXMLFlag,
		OutputJSON:          *outputJSONFlag,
		OutputCSV:           *outputCSVFlag,
		OutputUNC:           *outputUNCFlag,
		OutputRelay:         *outputRelayFlag,
		OutputAll:           *outputAllFlag,
		OutputHTML:          *outputHTMLFlag,
		Force:               *forceFlag,
		Resume:              *resumeFlag,
		Threads:             *threadsFlag,
		Timeout:             *timeoutFlag,
		IOTimeout:           *ioTimeoutFlag,
		SmbPort:             *smbPortFlag,
		Proxy:               *proxyFlag,
		Discovery:           *discoveryFlag,
		DiscoveryThreads:    *discoveryThreadsFlag,
		DiscoveryThreadsSet: discoveryThreadsSet,
		ConnectTimeout:      *connectTimeoutFlag,
		ConnectTimeoutSet:   connectTimeoutSet,
		MaxAuthFailures:     *maxAuthFailuresFlag,
		WriteCheck:          *writeCheckFlag,
		Exclude:             *excludeFlag,
		ExcludeHosts:        *excludeHostsFlag,
		List:                *listFlag,
		Recurse:             *recurseFlag,
		Depth:               *depthFlag,
		FollowLinks:         *followLinksFlag,
		MaxFiles:            *maxFilesFlag,
		MaxConnsPerHost:     *maxConnsPerHostFlag,
	})
	if err != nil {
		logger.Fatal(err)
	}
	// a progress line on an interactive stderr; --debug output is too busy
	// for it, and go-smb's own debug messages bypass the logger
	scanner.Options.Progress = !*quietFlag && !*debugFlag && term.IsTerminal(int(os.Stderr.Fd()))

	// Ctrl+C or SIGTERM cancels ctx: every open connection is closed, workers
	// stop, and the outputs are terminated below. After the first signal the
	// default handler is restored, so a second Ctrl+C exits immediately.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	var finished atomic.Bool
	go func() {
		<-ctx.Done()
		if finished.Load() {
			return
		}
		stop()
		logger.Warn("Interrupt received: stopping and writing partial results (press Ctrl+C again to exit immediately)")
	}()
	// Unblock any phase (LDAP, DNS, SMB) that is waiting on the network.
	context.AfterFunc(ctx, scanner.Options.Dialer.CloseAll)

	// execute specified command
	if command == nullCommand.FullCommand() {
		err = cmd.ExecuteNull(ctx, scanner, *nullTargetArg)
	}
	if command == guestCommand.FullCommand() {
		err = cmd.ExecuteGuest(ctx, scanner, *guestTargetArg, *guestUsernameFlag)
	}
	if command == authCommand.FullCommand() {
		password, perr := cmd.Password(*authUsernameFlag, *authPasswordFlag, authPasswordSet, *authHashFlag, *authAESKeyFlag, *authKerberosFlag)
		if perr != nil {
			logger.Fatal(perr)
		}
		err = cmd.ExecuteAuth(ctx, scanner, *authTargetArg, *authUsernameFlag, password, *authHashFlag, *authAESKeyFlag, *authLocalAuthFlag, *authKerberosFlag, *authDcHostnameFlag, *authDcIPFlag)
	}
	if command == huntCommand.FullCommand() {
		password, perr := cmd.Password(*huntUsernameFlag, *huntPasswordFlag, huntPasswordSet, *huntHashFlag, *huntAESKeyFlag, *huntKerberosFlag)
		if perr != nil {
			logger.Fatal(perr)
		}
		err = cmd.ExecuteHunt(ctx, scanner, *huntUsernameFlag, password, *huntHashFlag, *huntAESKeyFlag, *huntDcArg, *huntResolverFlag, *huntForestFlag, *huntKerberosFlag, *huntDcHostnameFlag, *huntAllowPlainFlag)
	}
	interrupted := ctx.Err() != nil
	finished.Store(true)
	stop()

	// terminate and close every output file, also after an interrupt
	scanner.CloseOutputter()
	if err == nil || scanner.Stats.Targets.Load() > 0 {
		logger.Warn(scanner.Stats.SummaryLine())
	}

	if interrupted {
		os.Exit(130)
	}
	if err != nil {
		logger.Fatal(err)
	}
}
