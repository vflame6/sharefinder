package cmd

import "fmt"

// Banner string
var Banner = "\n         __                    _____           __         \n   _____/ /_  ____ _________  / __(_)___  ____/ /__  _____\n  / ___/ __ \\/ __ `/ ___/ _ \\/ /_/ / __ \\/ __  / _ \\/ ___/\n (__  ) / / / /_/ / /  /  __/ __/ / / / / /_/ /  __/ /    \n/____/_/ /_/\\__,_/_/   \\___/_/ /_/_/ /_/\\__,_/\\___/_/     \n                                                          "

// PrintBanner is a function to print program banner
func PrintBanner() {
	fmt.Println(Banner)
}
