package main

import (
	"github.com/alecthomas/kingpin/v2"
	"github.com/vflame6/sharefinder/cmd"
	"os"
)

var (
	app         = kingpin.New("sharefinder", "Sharefinder is a network share discovery tool that enumerates shares, permissions, files and vulnerabilities in networks and domains.")
	outputFlag  = app.Flag("output", "file to write output to").Short('o').Default("").String()
	threadsFlag = app.Flag("threads", "number of threads (default 10)").Default("1").Int()
	timeoutFlag = app.Flag("timeout", "seconds to wait for connection (default 5)").Default("5s").Duration()
	excludeFlag = app.Flag("exclude", "share names to exclude (default ADMIN$,IPC$").Short('e').Default("ADMIN$,IPC$").String()
	listFlag    = app.Flag("list", "attempt to list shares (default false)").Default("false").Bool()
	searchFlag  = app.Flag("search", "pattern to search through files").Short('s').String()

	// find anonymous shares and permissions
	//anonCommand    = app.Command("anon", "")
	//anonTargetFlag = anonCommand.Arg("target", "").Required().String()

	// find authenticated shares and permissions, also can search for file
	authCommand       = app.Command("auth", "")
	authTargetFlag    = authCommand.Arg("target", "").Required().String()
	authUsernameFlag  = authCommand.Flag("username", "username in format DOMAIN\\username, except for local auth").Short('u').Required().String()
	authPasswordFlag  = authCommand.Flag("password", "").Short('p').Required().String()
	authLocalAuthFlag = authCommand.Flag("local-auth", "enable local authentication, the username is passed without domain").Bool()

	// hunt for targets from AD and find shares and permissions, also check for AD vulnerabilities
	//huntCommand      = app.Command("hunt", "")
	//huntUsernameFlag = huntCommand.Flag("username", "").Short('u').Required().String()
	//huntPasswordFlag = huntCommand.Flag("password", "").Short('p').Required().String()
	//huntDcFlag       = huntCommand.Flag("dc", "").Required().IP()
)

func main() {
	app.Version("0.0.1")
	app.HelpFlag.Short('h')
	app.UsageTemplate(kingpin.CompactUsageTemplate)

	command := kingpin.MustParse(app.Parse(os.Args[1:]))
	cmd.PrintBanner()

	//case anonCommand.FullCommand():
	//	cmd.PrintBanner()
	//	cmd.ExecuteAnon()
	if command == authCommand.FullCommand() {
		cmd.ExecuteAuth(*outputFlag, *threadsFlag, *timeoutFlag, *excludeFlag, *authTargetFlag, *authUsernameFlag, *authPasswordFlag, *authLocalAuthFlag, *listFlag, *searchFlag)
	}
	//case huntCommand.FullCommand():
	//	cmd.PrintBanner()
	//	cmd.ExecuteHunt()
}
