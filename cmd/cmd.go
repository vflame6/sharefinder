package cmd

import (
	"fmt"
	"github.com/vflame6/sharefinder/logger"
	"github.com/vflame6/sharefinder/scanner"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

func CreateScanner(output string, threads int, timeout time.Duration, exclude string, list bool) *scanner.Scanner {
	outputOption := false
	var outputWriter *scanner.OutputWriter
	var file *os.File
	var err error
	if output != "" {
		outputOption = true
		outputWriter = scanner.NewOutputWriter(false)
		file, err = outputWriter.CreateFile(output, false)
		if err != nil {
			log.Fatal(err)
		}
	}

	excludeList := strings.Split(exclude, ",")

	options := scanner.NewOptions(
		outputOption,
		outputWriter,
		file,
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

func ExecuteAnon(s *scanner.Scanner, target string) {
	logger.Info("Executing anon module")
	anonUsername := "anonymous_" + scanner.RandSeq(8)
	logger.Info(fmt.Sprintf("Using username for anonymous access: %s", anonUsername))

	s.Options.Username = anonUsername

	var wg sync.WaitGroup
	s.RunAuthEnumeration(&wg)
	err := s.ParseTargets(target)
	if err != nil {
		log.Fatal(err)
	}
	wg.Wait()

	if s.Options.Output {
		s.Options.File.Close()
	}
}

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

	if s.Options.Output {
		s.Options.File.Close()
	}
}

//func ExecuteHunt() {
//
//}
//
