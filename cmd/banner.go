package cmd

import (
	"fmt"
	"runtime/debug"
)

// AUTHOR of the program
const AUTHOR = "Maksim Radaev (@vflame6)"

// VERSION should be linked to actual tag
var VERSION = "dev"

// BANNER format string
const BANNER = "\n         __                    _____           __         \n   _____/ /_  ____ _________  / __(_)___  ____/ /__  _____\n  / ___/ __ \\/ __ `/ ___/ _ \\/ /_/ / __ \\/ __  / _ \\/ ___/\n (__  ) / / / /_/ / /  /  __/ __/ / / / / /_/ /  __/ /    \n/____/_/ /_/\\__,_/_/   \\___/_/ /_/_/ /_/\\__,_/\\___/_/ %s    \n                                                          \nMade by %s\n\n"

func init() {
	if VERSION == "dev" {
		if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
			VERSION = info.Main.Version
		}
	}
}

// PrintBanner is a function to print program banner
func PrintBanner() {
	fmt.Printf(BANNER, VERSION, AUTHOR)
}
