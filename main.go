package main

import (
	"github.com/alecthomas/kingpin/v2"
	"github.com/vflame6/sharefinder/cmd"
	"os"
)

var (
	app         = kingpin.New("sharefinder", "Sharefinder is a network share discovery tool that enumerates shares, permissions, files and vulnerabilities in networks and domains.")
	outputFlag  = app.Flag("output", "file to write output to").Short('o').Default("").String()
	threadsFlag = app.Flag("threads", "number of threads (default 10)").Default("10").Int()
	timeoutFlag = app.Flag("timeout", "seconds to wait for connection (default: 5)").Default("5s").Duration()
	excludeFlag = app.Flag("exclude", "share names to exclude (default: ADMIN$,IPC$").Short('e').Default("ADMIN$,IPC$").String()

	// audit everything
	//allCommand      = app.Command("all", "")
	//allTargetFlag   = allCommand.Flag("target", "").Short('t').Required().String()
	//allUsernameFlag = allCommand.Flag("username", "").Short('u').Required().String()
	//allPasswordFlag = allCommand.Flag("password", "").Short('p').Required().String()
	//allDomainFlag   = allCommand.Flag("domain", "").Short('d').Required().String()
	//allDcFlag       = allCommand.Flag("dc", "").Required().IP()

	// find anonymous shares and permissions
	//anonCommand    = app.Command("anon", "")
	//anonTargetFlag = anonCommand.Arg("target", "").Required().String()

	// find authenticated shares and permissions, also can search for file
	authCommand       = app.Command("auth", "")
	authTargetFlag    = authCommand.Arg("target", "").Required().String()
	authUsernameFlag  = authCommand.Flag("username", "username in format DOMAIN\\username, except for local auth").Short('u').Required().String()
	authPasswordFlag  = authCommand.Flag("password", "").Short('p').Required().String()
	authLocalAuthFlag = authCommand.Flag("local-auth", "enable local authentication, the username is passed without domain").Bool()
	authListFlag      = authCommand.Flag("list", "list shares recursively (default: No)").Default("false").Bool()
	authSearchFlag    = authCommand.Flag("search", "").Short('s').String()

	// hunt for targets from AD and find shares and permissions, also check for AD vulnerabilities
	//huntCommand      = app.Command("hunt", "")
	//huntUsernameFlag = huntCommand.Flag("username", "").Short('u').Required().String()
	//huntPasswordFlag = huntCommand.Flag("password", "").Short('p').Required().String()
	//huntDcFlag       = huntCommand.Flag("dc", "").Required().IP()

	// search for vulnerabilities and coerce attacks
	//vulnCommand       = app.Command("vuln", "")
	//vulnTargetFlag    = vulnCommand.Arg("target", "").Required().String()
	//vulnUsernameFlag  = vulnCommand.Flag("username", "").Short('u').String()
	//vulnPasswordFlag  = vulnCommand.Flag("password", "").Short('p').String()
	//vulnLocalAuthFlag = vulnCommand.Flag("local-auth", "").Bool()
)

func main() {
	kingpin.Version("0.0.1")
	kingpin.CommandLine.HelpFlag.Short('h')
	app.UsageTemplate(kingpin.CompactUsageTemplate)

	switch kingpin.MustParse(app.Parse(os.Args[1:])) {
	//case allCommand.FullCommand():
	//	cmd.ExecuteAll()
	//case anonCommand.FullCommand():
	//	cmd.ExecuteAnon(outputFlag, threadsFlag, timeoutFlag, anonTargetFlag, anonListFlag)
	case authCommand.FullCommand():
		cmd.ExecuteAuth(*outputFlag, *threadsFlag, *timeoutFlag, *excludeFlag, *authTargetFlag, *authUsernameFlag, *authPasswordFlag, *authLocalAuthFlag, *authListFlag, *authSearchFlag)
		//case huntCommand.FullCommand():
		//	cmd.ExecuteHunt()
		//case vulnCommand.FullCommand():
		//	cmd.ExecuteVuln()
	}
}
