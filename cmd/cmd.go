package cmd

import (
	"github.com/vflame6/sharefinder/logger"
	"github.com/vflame6/sharefinder/scanner"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

func CreateScanner(output string, threads int, timeout time.Duration, exclude string, list bool) *scanner.Scanner {
	excludeList := strings.Split(exclude, ",")

	options := scanner.NewOptions(
		output,
		timeout,
		excludeList,
		make(chan string, 256),
		"",
		"",
		"",
		false,
		list,
		net.IPv4zero,
	)
	s := scanner.NewScanner(options, threads)

	return s
}

//func ExecuteAnon(output *string, threads *int, timeout *time.Duration, target *string) {
//	//options := scanner.NewOptions(
//	//	*target,
//	//	"",
//	//	"",
//	//	"",
//	//	"",
//	//	false,
//	//	net.IPv4zero,
//	//)
//	//s := scanner.NewScanner(options, *output, *threads, *timeout)
//	//err := s.RunAnonEnumeration()
//	//if err != nil {
//	//	logger.Fatal(err)
//	//}
//}

func ExecuteAuth(s *scanner.Scanner, target, username, password string, localauth bool) {
	logger.Info("Executing auth module")
	var targetDomain string
	var targetUsername string
	if localauth {
		targetDomain = ""
		targetUsername = username
	} else {
		trySplit := strings.Split(username, "\\")
		targetDomain = trySplit[0]
		targetUsername = trySplit[1]
	}

	s.Options.Username = targetUsername
	s.Options.Password = password
	s.Options.Domain = targetDomain
	s.Options.LocalAuth = localauth

	var wg sync.WaitGroup
	s.RunAuthEnumeration(&wg)
	err := s.ParseTargets(target)
	if err != nil {
		log.Fatal(err)
	}
	wg.Wait()
}

//func ExecuteHunt() {
//
//}
//
