package main

import (
	"context"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/alecthomas/kingpin/v2"
	"github.com/vflame6/sharefinder/cmd"
	"github.com/vflame6/sharefinder/logger"
)

// program options
var (
	// program description
	app = kingpin.New("sharefinder", "sharefinder is a network share discovery tool that enumerates shares, permissions and files in networks and domains.")

	// global flags

	// log output flags
	debugFlag = app.Flag("debug", "Enable debug mode, print debug messages").Bool()
	quietFlag = app.Flag("quiet", "Enable quiet mode, print only results").Bool()

	// file output flags
	outputRawFlag  = app.Flag("output", "Filename to write output in raw format").Short('o').Default("").String()
	outputXMLFlag  = app.Flag("output-xml", "Filename to write XML formatted output").Default("").String()
	outputAllFlag  = app.Flag("output-all", "Filename to write output in all formats").Default("").String()
	outputHTMLFlag = app.Flag("html", "Generate HTML report (requires XML output)").Default("false").Bool()

	// connection flags
	threadsFlag         = app.Flag("threads", "Number of threads").Default("10").Int()
	timeoutFlag         = app.Flag("timeout", "Seconds to wait for connection").Default("5s").Duration()
	ioTimeoutFlag       = app.Flag("io-timeout", "Abort an SMB or LDAP operation when the server sends nothing for this long").Default("30s").Duration()
	smbPortFlag         = app.Flag("smb-port", "Target port of SMB service").Default("445").Int()
	proxyFlag           = app.Flag("proxy", "SOCKS-proxy address to use for connection in format IP:PORT").Default("").String()
	maxAuthFailuresFlag = app.Flag("max-auth-failures", "Stop the scan after this many rejected logons; 0 disables the guard").Default("1").Int()

	// SMB interaction flags
	excludeFlag      = app.Flag("exclude", "Exclude list").Short('e').Default("IPC$,NETLOGON,ADMIN$,print$,C$").String()
	excludeHostsFlag = app.Flag("exclude-hosts", "Skip these targets: IPs, CIDRs, ranges, hostnames (comma-separated) or a file").Default("").String()
	listFlag         = app.Flag("list", "List readable shares").Default("false").Bool()
	recurseFlag      = app.Flag("recurse", "List readable shares recursively").Default("false").Bool()
	depthFlag        = app.Flag("depth", "Maximum directory depth below the share root for --recurse (0 lists the root only)").Default("5").Int()
	followLinksFlag  = app.Flag("follow-links", "Descend into directory symlinks and junctions during --recurse").Bool()
	maxFilesFlag     = app.Flag("max-files", "Stop listing a share after this many entries (0 = no limit)").Default("0").Int()
	writeCheckFlag   = app.Flag("write-check", "How to test write access: mask (open the share root with write rights, creates nothing), file (create and delete a temporary file) or off").Default("file").Enum("mask", "file", "off")

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
	authPasswordFlag   = authCommand.Flag("password", "User's password").Short('p').String()
	authHashFlag       = authCommand.Flag("hashes", "NTLM hash of password to authenticate").Short('H').String()
	authLocalAuthFlag  = authCommand.Flag("local-auth", "Enable local authentication, the username is passed without domain").Bool()
	authKerberosFlag   = authCommand.Flag("kerberos", "Use Kerberos authentication").Short('k').Bool()
	authDcHostnameFlag = authCommand.Flag("dc-hostname", "Hostname of domain controller for Kerberos authentication").String()
	authDcIPFlag       = authCommand.Flag("dc-ip", "IP of KDC when using Kerberos authentication").IP()

	// hunt command
	// hunt for targets from AD and find shares and permissions
	huntCommand        = app.Command("hunt", "hunting module")
	huntDcArg          = huntCommand.Arg("dc", "Domain Controller IP").Required().IP()
	huntUsernameFlag   = huntCommand.Flag("username", "Domain username in format DOMAIN\\username").Short('u').Required().String()
	huntPasswordFlag   = huntCommand.Flag("password", "Domain user's password").Short('p').String()
	huntHashFlag       = huntCommand.Flag("hashes", "NTLM hash of password to authenticate").Short('H').String()
	huntResolverFlag   = huntCommand.Flag("resolver", "Custom DNS resolver IP address").Short('r').IP()
	huntForestFlag     = huntCommand.Flag("forest", "Search all available domains in the current forest").Default("false").Bool()
	huntKerberosFlag   = huntCommand.Flag("kerberos", "Use Kerberos authentication").Short('k').Bool()
	huntDcHostnameFlag = huntCommand.Flag("dc-hostname", "Hostname of domain controller for Kerberos authentication").String()
	huntAllowPlainFlag = huntCommand.Flag("allow-plaintext-ldap", "Allow a simple bind, which sends the password, over LDAP without TLS when LDAPS and StartTLS fail").Bool()
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

	// set up a scanner
	scanner, err := cmd.CreateScanner(cmd.Config{
		Version:         cmd.VERSION,
		CommandLine:     os.Args[1:],
		TimeStart:       time.Now(),
		OutputRaw:       *outputRawFlag,
		OutputXML:       *outputXMLFlag,
		OutputAll:       *outputAllFlag,
		OutputHTML:      *outputHTMLFlag,
		Threads:         *threadsFlag,
		Timeout:         *timeoutFlag,
		IOTimeout:       *ioTimeoutFlag,
		SmbPort:         *smbPortFlag,
		Proxy:           *proxyFlag,
		MaxAuthFailures: *maxAuthFailuresFlag,
		WriteCheck:      *writeCheckFlag,
		Exclude:         *excludeFlag,
		ExcludeHosts:    *excludeHostsFlag,
		List:            *listFlag,
		Recurse:         *recurseFlag,
		Depth:           *depthFlag,
		FollowLinks:     *followLinksFlag,
		MaxFiles:        *maxFilesFlag,
	})
	if err != nil {
		logger.Fatal(err)
	}

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
		err = cmd.ExecuteAuth(ctx, scanner, *authTargetArg, *authUsernameFlag, *authPasswordFlag, *authHashFlag, *authLocalAuthFlag, *authKerberosFlag, *authDcHostnameFlag, *authDcIPFlag)
	}
	if command == huntCommand.FullCommand() {
		err = cmd.ExecuteHunt(ctx, scanner, *huntUsernameFlag, *huntPasswordFlag, *huntHashFlag, *huntDcArg, *huntResolverFlag, *huntForestFlag, *huntKerberosFlag, *huntDcHostnameFlag, *huntAllowPlainFlag)
	}
	interrupted := ctx.Err() != nil
	finished.Store(true)
	stop()

	// terminate and close every output file, also after an interrupt
	scanner.CloseOutputter()

	if interrupted {
		os.Exit(130)
	}
	if err != nil {
		logger.Fatal(err)
	}
}
