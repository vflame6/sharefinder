package cmd

import (
	"github.com/vflame6/sharefinder/scanner"
	"log"
	"net"
	"time"
)

func ExecuteAll() {

}

func ExecuteAnon(output *string, threads *int, timeout *time.Duration, target *string, list *bool) {
	options := scanner.NewOptions(
		*target,
		"",
		"",
		"",
		"",
		false,
		*list,
		net.IPv4zero,
	)
	s := scanner.NewScanner(options, *output, *threads, *timeout)
	err := s.RunAnonEnumeration()
	if err != nil {
		log.Fatal(err)
	}
}

func ExecuteAuth() {

}

func ExecuteHunt() {

}

func ExecuteVuln() {

}
