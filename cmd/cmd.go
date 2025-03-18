package cmd

import (
	"github.com/vflame6/sharefinder/scanner"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

//func ExecuteAll() {
//
//}

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
//	//	log.Fatal(err)
//	//}
//}

func ExecuteAuth(output string, threads int, timeout time.Duration, exclude string, target, username, password string, localauth, list bool, search string) {
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
	excludeList := strings.Split(exclude, ",")

	options := scanner.NewOptions(
		excludeList,
		make(chan string, 256),
		targetUsername,
		password,
		targetDomain,
		search,
		localauth,
		list,
		net.IPv4zero,
	)
	s := scanner.NewScanner(options, output, threads, timeout)
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
//func ExecuteVuln() {
//
//}
