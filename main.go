package main

import (
	"github.com/alecthomas/kingpin/v2"
	"github.com/vflame6/sharefinder/cmd"
	"github.com/vflame6/sharefinder/logger"
	"os"
	"time"
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
	threadsFlag = app.Flag("threads", "Number of threads").Default("10").Int()
	timeoutFlag = app.Flag("timeout", "Seconds to wait for connection").Default("5s").Duration()
	smbPortFlag = app.Flag("smb-port", "Target port of SMB service").Default("445").Int()
	proxyFlag   = app.Flag("proxy", "SOCKS-proxy address to use for connection in format IP:PORT").Default("").String()

	// SMB interaction flags
	excludeFlag = app.Flag("exclude", "Exclude list").Short('e').Default("IPC$,NETLOGON,ADMIN$,print$,C$").String()
	listFlag    = app.Flag("list", "List readable shares").Default("false").Bool()
	recurseFlag = app.Flag("recurse", "List readable shares recursively").Default("false").Bool()

	// null command
	// find null sessions shares and permissions
	nullCommand   = app.Command("null", "null session module")
	nullTargetArg = nullCommand.Arg("target", "Target, IP range of filename").Required().String()

	// anon command
	// find anonymous (guest) shares and permissions
	anonCommand      = app.Command("anon", "anonymous module")
	anonTargetArg    = anonCommand.Arg("target", "Target, IP range or filename").Required().String()
	anonUsernameFlag = anonCommand.Flag("username", "Username to authenticate").String()

	// auth command
	// find authenticated shares and permissions
	authCommand       = app.Command("auth", "authenticated module")
	authTargetArg     = authCommand.Arg("target", "Target, IP range or filename").Required().String()
	authUsernameFlag  = authCommand.Flag("username", "Username in format DOMAIN\\username for domain auth, and just username for local auth").Short('u').Required().String()
	authPasswordFlag  = authCommand.Flag("password", "User's password").Short('p').String()
	authHashFlag      = authCommand.Flag("hashes", "NTLM hash of password to authenticate").Short('H').String()
	authLocalAuthFlag = authCommand.Flag("local-auth", "Enable local authentication, the username is passed without domain").Bool()

	// hunt command
	// hunt for targets from AD and find shares and permissions
	huntCommand        = app.Command("hunt", "hunting module")
	huntDcArg          = huntCommand.Arg("dc", "Domain Controller IP").Required().IP()
	huntUsernameFlag   = huntCommand.Flag("username", "Domain username in format DOMAIN\\username").Short('u').Required().String()
	huntPasswordFlag   = huntCommand.Flag("password", "Domain user's password").Short('p').String()
	huntHashFlag       = huntCommand.Flag("hashes", "NTLM hash of password to authenticate").Short('H').String()
	huntResolverFlag   = huntCommand.Flag("resolver", "Custom DNS resolver IP address").Short('r').IP()
	huntKerberosFlag   = huntCommand.Flag("kerberos", "Use Kerberos authentication").Short('k').Bool()
	huntDcHostnameFlag = huntCommand.Flag("dc-hostname", "Hostname of domain controller for Kerberos authentication").String()
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
		cmd.PrintBanner()
	}

	// set up a logger
	err := logger.SetLoggerOptions(*debugFlag, *quietFlag)
	if err != nil {
		logger.Fatal(err)
	}

	// set up a scanner
	scanner, err := cmd.CreateScanner(
		cmd.VERSION,
		os.Args[1:],
		time.Now(),
		*outputRawFlag,
		*outputXMLFlag,
		*outputAllFlag,
		*outputHTMLFlag,
		*threadsFlag,
		*timeoutFlag,
		*excludeFlag,
		*listFlag,
		*recurseFlag,
		*smbPortFlag,
		*proxyFlag,
	)
	if err != nil {
		logger.Fatal(err)
	}

	// execute specified command
	if command == nullCommand.FullCommand() {
		err = cmd.ExecuteNull(scanner, *nullTargetArg)
	}
	if command == anonCommand.FullCommand() {
		err = cmd.ExecuteAnon(scanner, *anonTargetArg, *anonUsernameFlag)
	}
	if command == authCommand.FullCommand() {
		err = cmd.ExecuteAuth(scanner, *authTargetArg, *authUsernameFlag, *authPasswordFlag, *authHashFlag, *authLocalAuthFlag)
	}
	if command == huntCommand.FullCommand() {
		err = cmd.ExecuteHunt(scanner, *huntUsernameFlag, *huntPasswordFlag, *huntHashFlag, *huntDcArg, *huntResolverFlag, *huntKerberosFlag, *huntDcHostnameFlag)
	}
	if err != nil {
		logger.Fatal(err)
	}
}
