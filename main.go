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

	// output flags
	debugFlag = app.Flag("debug", "enable debug mode, print debug messages (default false)").Bool()
	quietFlag = app.Flag("quiet", "enable quiet mode, don't print any messages (default false)").Bool()

	// file output flags
	outputFlag     = app.Flag("output", "file to write output to (raw and xml)").Short('o').Default("").String()
	outputHTMLFlag = app.Flag("html", "output HTML (default false)").Default("false").Bool()

	// connection flags
	threadsFlag = app.Flag("threads", "number of threads (default 1)").Default("1").Int()
	timeoutFlag = app.Flag("timeout", "seconds to wait for connection (default 5s)").Default("5s").Duration()
	smbPortFlag = app.Flag("smb-port", "target port of SMB service (default 445)").Default("445").Int()
	proxyFlag   = app.Flag("proxy", "SOCKS-proxy address to use for connection in format IP:PORT").String()

	// SMB interaction flags
	excludeFlag = app.Flag("exclude", "share names to exclude (default IPC$,NETLOGON,ADMIN$,print$,C$)").Short('e').Default("IPC$,NETLOGON,ADMIN$,print$,C$").String()
	listFlag    = app.Flag("list", "list readable shares (default false)").Default("false").Bool()
	recurseFlag = app.Flag("recurse", "list readable shares recursively (default false)").Default("false").Bool()

	// anon command
	// find anonymous (guest) shares and permissions
	anonCommand    = app.Command("anon", "anonymous module")
	anonTargetFlag = anonCommand.Arg("target", "target, IP range or filename").Required().String()

	// TODO: implement null session check - https://sensepost.com/blog/2024/guest-vs-null-session-on-windows/

	// auth command
	// find authenticated shares and permissions
	authCommand       = app.Command("auth", "authenticated module")
	authTargetFlag    = authCommand.Arg("target", "target, IP range or filename").Required().String()
	authUsernameFlag  = authCommand.Flag("username", "username in format DOMAIN\\username for domain auth, and just username for local auth").Short('u').Required().String()
	authPasswordFlag  = authCommand.Flag("password", "user password").Short('p').Required().String()
	authLocalAuthFlag = authCommand.Flag("local-auth", "enable local authentication, the username is passed without domain").Bool()

	// TODO: add support for NTLM hash instead of password
	// TODO: add kerberos support (-k and --no-pass)

	// hunt command
	// hunt for targets from AD and find shares and permissions
	huntCommand      = app.Command("hunt", "hunting module")
	huntDcFlag       = huntCommand.Arg("dc", "domain controller IP").Required().IP()
	huntUsernameFlag = huntCommand.Flag("username", "domain username in format DOMAIN\\username").Short('u').Required().String()
	huntPasswordFlag = huntCommand.Flag("password", "domain user password").Short('p').Required().String()
	huntResolverFlag = huntCommand.Flag("resolver", "custom DNS resolver IP address (default DC IP)").Short('r').IP()

	// TODO: add kerberos support (-k and --no-pass)
	// TODO: add support for NTLM hash instead of password
	// TODO: implement search forest option
)

func main() {
	// version is linked to actual tag
	VERSION := "1.2.0"

	// kingpin settings
	app.Version(VERSION)
	app.Author("vflame6")
	app.HelpFlag.Short('h')
	app.UsageTemplate(kingpin.CompactUsageTemplate)

	// parse options
	command := kingpin.MustParse(app.Parse(os.Args[1:]))

	// print program banner
	cmd.PrintBanner()

	// set up a logger
	err := logger.SetLoggerOptions(*debugFlag, *quietFlag)
	if err != nil {
		logger.Fatal(err)
	}

	// set up a scanner
	scanner, err := cmd.CreateScanner(
		VERSION,
		os.Args[1:],
		time.Now(),
		*outputFlag,
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
	if command == anonCommand.FullCommand() {
		err = cmd.ExecuteAnon(scanner, *anonTargetFlag)
	}
	if command == authCommand.FullCommand() {
		err = cmd.ExecuteAuth(scanner, *authTargetFlag, *authUsernameFlag, *authPasswordFlag, *authLocalAuthFlag)
	}
	if command == huntCommand.FullCommand() {
		err = cmd.ExecuteHunt(scanner, *huntUsernameFlag, *huntPasswordFlag, *huntDcFlag, *huntResolverFlag)
	}
	if err != nil {
		logger.Fatal(err)
	}
}
