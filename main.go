package main

import (
	"github.com/alecthomas/kingpin/v2"
	"github.com/vflame6/sharefinder/cmd"
	"os"
)

var (
	app = kingpin.New("sharefinder", "Sharefinder is a network share discovery tool that enumerates shares, permissions, files and vulnerabilities in networks and domains.")

	// global flags
	outputFlag = app.Flag("output", "file to write output to").Short('o').Default("").String()
	// TODO: implement HTML output
	threadsFlag = app.Flag("threads", "number of threads (default 1)").Default("1").Int()
	timeoutFlag = app.Flag("timeout", "seconds to wait for connection (default 5s)").Default("5s").Duration()
	excludeFlag = app.Flag("exclude", "share names to exclude (default IPC$)").Short('e').Default("IPC$").String()
	listFlag    = app.Flag("list", "attempt to list shares (default false)").Default("false").Bool()
	// TODO: implement recursive list through shares (--recurse)
	// TODO: implement file search through shares (--search)
	//searchFlag  = app.Flag("search", "pattern to search through files").Short('s').String()
	// TODO: implement proxy support (--proxy)

	// find anonymous (guest) shares and permissions
	anonCommand    = app.Command("anon", "anonymous module")
	anonTargetFlag = anonCommand.Arg("target", "target, IP range or filename").Required().String()
	// TODO: implement null session check

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
	// TODO: add kerberos support (-k and --no-pass)
	// TODO: add support for NTLM hash instead of password
	// TODO: implement search forest option
)

func main() {
	app.Version("1.0.0")
	app.HelpFlag.Short('h')
	app.UsageTemplate(kingpin.CompactUsageTemplate)

	command := kingpin.MustParse(app.Parse(os.Args[1:]))
	cmd.PrintBanner()

	scanner := cmd.CreateScanner(*outputFlag, *threadsFlag, *timeoutFlag, *excludeFlag, *listFlag)

	if command == anonCommand.FullCommand() {
		cmd.ExecuteAnon(scanner, *anonTargetFlag)
	}
	if command == authCommand.FullCommand() {
		cmd.ExecuteAuth(scanner, *authTargetFlag, *authUsernameFlag, *authPasswordFlag, *authLocalAuthFlag)
	}
	if command == huntCommand.FullCommand() {
		cmd.ExecuteHunt(scanner, *huntUsernameFlag, *huntPasswordFlag, *huntDcFlag)
	}
}
