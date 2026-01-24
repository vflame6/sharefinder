package cmd

import "fmt"

// AUTHOR of the program
const AUTHOR = "Maksim Radaev (@vflame6)"

// VERSION should be linked to actual tag
const VERSION = "v1.3.1"

// BANNER format string
const BANNER = "\n         __                    _____           __         \n   _____/ /_  ____ _________  / __(_)___  ____/ /__  _____\n  / ___/ __ \\/ __ `/ ___/ _ \\/ /_/ / __ \\/ __  / _ \\/ ___/\n (__  ) / / / /_/ / /  /  __/ __/ / / / / /_/ /  __/ /    \n/____/_/ /_/\\__,_/_/   \\___/_/ /_/_/ /_/\\__,_/\\___/_/ %s    \n                                                          \nMade by %s\n\n"

// PrintBanner is a function to print program banner
func PrintBanner() {
	fmt.Printf(BANNER, VERSION, AUTHOR)
}
