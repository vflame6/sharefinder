package main

import (
	"github.com/alecthomas/kingpin/v2"
	"github.com/vflame6/sharefinder/cmd"
	"os"
	"time"
)

var (
	app = kingpin.New("sharefinder", "sharefinder is a network share discovery tool that enumerates shares, permissions and files in networks and domains.")

	// global flags
	outputFlag     = app.Flag("output", "file to write output to (raw and xml)").Short('o').Default("").String()
	outputHTMLFlag = app.Flag("html", "output HTML (default false)").Default("false").Bool()
	threadsFlag    = app.Flag("threads", "number of threads (default 1)").Default("1").Int()
	timeoutFlag    = app.Flag("timeout", "seconds to wait for connection (default 5s)").Default("5s").Duration()
	excludeFlag    = app.Flag("exclude", "share names to exclude (default IPC$,ADMIN$,print$)").Short('e').Default("IPC$,ADMIN$,print$").String()
	listFlag       = app.Flag("list", "list readable shares (default false)").Default("false").Bool()
	recurseFlag    = app.Flag("recurse", "list readable shares recursively (default false)").Default("false").Bool()
	// TODO: implement search for interesting files through shares
	// TODO: implement file search through shares (--filter)
	//filterFlag  = app.Flag("filter", "pattern to filter through files while listing (default none)").Default("").String()
	// TODO: implement proxy support (--proxy)
	smbPortFlag = app.Flag("smb-port", "target port of SMB service (default 445)").Default("445").Int()
	// TODO: add --victim flag to scan targets for SMB vulnerabilities

	// find anonymous (guest) shares and permissions
	anonCommand    = app.Command("anon", "anonymous module")
	anonTargetFlag = anonCommand.Arg("target", "target, IP range or filename").Required().String()
	// TODO: implement null session check - https://sensepost.com/blog/2024/guest-vs-null-session-on-windows/

	// find authenticated shares and permissions
	authCommand       = app.Command("auth", "authenticated module")
	authUsernameFlag  = authCommand.Flag("username", "username in format DOMAIN\\username, except for local auth").Short('u').Required().String()
	authPasswordFlag  = authCommand.Flag("password", "user password").Short('p').Required().String()
	authLocalAuthFlag = authCommand.Flag("local-auth", "enable local authentication, the username is passed without domain").Bool()
	authTargetFlag    = authCommand.Arg("target", "target, IP range or filename").Required().String()
	// TODO: add support for NTLM hash instead of password
	// TODO: add kerberos support (-k and --no-pass)

	//hunt for targets from AD and find shares and permissions, also check for AD vulnerabilities
	huntCommand      = app.Command("hunt", "hunting module")
	huntUsernameFlag = huntCommand.Flag("username", "domain username in format DOMAIN\\username").Short('u').Required().String()
	huntPasswordFlag = huntCommand.Flag("password", "domain user password").Short('p').Required().String()
	huntDcFlag       = huntCommand.Arg("dc", "domain controller IP").Required().IP()
	huntResolverFlag = huntCommand.Flag("resolver", "custom DNS resolver IP address (default DC IP)").Short('r').IP()
	// TODO: add kerberos support (-k and --no-pass)
	// TODO: add support for NTLM hash instead of password
	// TODO: implement search forest option
)

func main() {
	VERSION := "1.1.4"

	app.Version(VERSION)
	app.Author("vflame6")
	app.HelpFlag.Short('h')
	app.UsageTemplate(kingpin.CompactUsageTemplate)

	command := kingpin.MustParse(app.Parse(os.Args[1:]))
	cmd.PrintBanner()

	scanner := cmd.CreateScanner(
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
	)

	if command == anonCommand.FullCommand() {
		cmd.ExecuteAnon(scanner, *anonTargetFlag)
	}
	if command == authCommand.FullCommand() {
		cmd.ExecuteAuth(scanner, *authTargetFlag, *authUsernameFlag, *authPasswordFlag, *authLocalAuthFlag)
	}
	if command == huntCommand.FullCommand() {
		cmd.ExecuteHunt(scanner, *huntUsernameFlag, *huntPasswordFlag, *huntDcFlag, *huntResolverFlag)
	}
}
