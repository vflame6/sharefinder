package cmd

import (
	"errors"
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

func CreateScanner(version string, commandLine []string, timeStart time.Time, output string, outputHTML bool, threads int, timeout time.Duration, exclude string, list, recurse bool, smbPort int) *scanner.Scanner {
	outputOption := false
	var outputWriter *scanner.OutputWriter
	var file *os.File
	var fileXML *os.File
	var err error
	if output != "" {
		outputOption = true
		outputWriter = scanner.NewOutputWriter()
		file, err = outputWriter.CreateFile(output, false)
		if err != nil {
			log.Fatal(err)
		}
		fileXML, err = outputWriter.CreateFile(output+".xml", false)
		if err != nil {
			log.Fatal(err)
		}
		err = outputWriter.WriteXMLHeader(version, commandLine, timeStart, fileXML)
		if err != nil {
			log.Fatal(err)
		}
	}
	if outputHTML && output == "" {
		log.Fatal(errors.New("cannot use --html without --output"))
	}
	if recurse && !list {
		log.Fatal(errors.New("cannot use --recurse without --list"))
	}

	excludeList := strings.Split(exclude, ",")

	options := scanner.NewOptions(
		smbPort,
		outputOption,
		outputHTML,
		output,
		outputWriter,
		file,
		fileXML,
		timeout,
		excludeList,
		make(chan string, 256),
		"",
		"",
		"",
		false,
		list,
		recurse,
		net.IPv4zero,
	)
	s := scanner.NewScanner(options, commandLine, timeStart, threads)

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

	s.TimeEnd = time.Now()

	if s.Options.Output {
		s.CloseOutputter()
	}
}

func ExecuteAuth(s *scanner.Scanner, target, username, password string, localAuth bool) {
	logger.Info("Executing auth module")
	var targetDomain string
	var targetUsername string
	if localAuth {
		targetDomain = ""
		targetUsername = username
	} else {
		trySplit := strings.Split(username, "\\")
		if len(trySplit) != 2 {
			log.Fatal(errors.New("invalid username. Try DOMAIN\\username"))
		}
		targetDomain = trySplit[0]
		targetUsername = trySplit[1]
	}

	s.Options.Username = targetUsername
	s.Options.Password = password
	s.Options.Domain = targetDomain
	s.Options.LocalAuth = localAuth

	var wg sync.WaitGroup
	s.RunAuthEnumeration(&wg)
	err := s.ParseTargets(target)
	if err != nil {
		log.Fatal(err)
	}
	wg.Wait()

	s.TimeEnd = time.Now()

	if s.Options.Output {
		s.CloseOutputter()
	}
}

func ExecuteHunt(s *scanner.Scanner, username, password string, dc net.IP) {
	logger.Info("Executing hunt module")
	var targetDomain string
	var targetUsername string
	trySplit := strings.Split(username, "\\")
	if len(trySplit) != 2 {
		log.Fatal(errors.New("Invalid username. Try DOMAIN\\username"))
	}
	targetDomain = strings.ToLower(trySplit[0])
	targetUsername = strings.ToLower(trySplit[1])

	s.Options.Username = targetUsername
	s.Options.Password = password
	s.Options.Domain = targetDomain
	s.Options.LocalAuth = false
	s.Options.DomainController = dc

	var wg sync.WaitGroup

	logger.Infof("Starting %s domain enumeration", s.Options.Domain)

	// enumerate possible targets via domain controller
	possibleTargets, err := s.RunEnumerateDomainComputers()
	if err != nil {
		log.Fatal(err)
	}
	logger.Infof("Found %d possible targets", len(possibleTargets))

	// scan every possible target for opened SMB port
	targets := s.RunHuntDomainTargets(&wg, possibleTargets)
	logger.Info(fmt.Sprintf("Found %d targets to enumerate", len(targets)))

	// check for shares and permissions on identified targets
	s.RunAuthEnumeration(&wg)
	err = s.ParseTargetsInMemory(targets)
	if err != nil {
		log.Fatal(err)
	}
	wg.Wait()

	s.TimeEnd = time.Now()

	if s.Options.Output {
		s.CloseOutputter()
	}
}
