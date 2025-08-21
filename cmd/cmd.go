package cmd

import (
	"errors"
	"github.com/vflame6/sharefinder/logger"
	"github.com/vflame6/sharefinder/scanner"
	"golang.org/x/net/proxy"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

func CreateScanner(version string, commandLine []string, timeStart time.Time, outputFileName string, outputHTML bool, threads int, timeout time.Duration, exclude string, list, recurse bool, smbPort int, proxyStr string) (*scanner.Scanner, error) {
	var outputWriter *scanner.OutputWriter
	var file *os.File
	var fileXML *os.File
	var err error
	var proxyDialer proxy.Dialer

	outputOption := false

	// HTML output is available only if basic output is specified
	// it is done like that because HTML file is generated based on generated XML
	// maybe I will rewrite that logic in the future, maybe
	if outputHTML && outputFileName == "" {
		return nil, errors.New("cannot use --html without --output")
	}

	// recursive output is available only if the list option is specified
	// it is done like that just to make the execution clear and avoid user mistakes
	if recurse && !list {
		return nil, errors.New("cannot use --recurse without --list")
	}

	// non-empty outputFileName means the output option is specified
	if outputFileName != "" {
		outputOption = true

		// trim suffix of output filename if it matches with txt/xml/html
		outputFileName = scanner.TrimFilenameSuffix(outputFileName)
		logger.Debugf("Output option is specified. Output file name: %s", outputFileName)

		// create raw text output file
		outputWriter = scanner.NewOutputWriter()
		file, err = outputWriter.CreateFile(outputFileName+".txt", false)
		if err != nil {
			return nil, err
		}

		// create XML output file and write an XML header line to it
		fileXML, err = outputWriter.CreateFile(outputFileName+".xml", false)
		if err != nil {
			return nil, err
		}
		err = outputWriter.WriteXMLHeader(version, commandLine, timeStart, fileXML)
		if err != nil {
			return nil, err
		}
	}

	// excludeList is created from string of words divided by ","
	excludeList := strings.Split(exclude, ",")

	// parse proxyStr string in a format IP:PORT
	if proxyStr != "" {
		proxyURL, err := url.Parse("socks5://" + proxyStr)
		if err != nil {
			return nil, errors.New("invalid proxy setting, try IP:PORT")
		}
		proxyDialer, err = proxy.SOCKS5("tcp", proxyURL.Host, nil, proxy.Direct)
		if err != nil {
			return nil, errors.New("invalid proxy setting, try IP:PORT")
		}
	} else {
		proxyDialer = nil
	}

	// scanner options are created without credentials just to specify global flags
	// the credentials will be specified on execution of authenticated modules
	options := scanner.NewOptions(
		smbPort,
		outputOption,
		outputHTML,
		outputFileName,
		outputWriter,
		file,
		fileXML,
		timeout,
		excludeList,
		make(chan string, 256),
		"",
		"",
		[]byte{},
		"",
		false,
		list,
		recurse,
		net.IPv4zero,
		proxyDialer,
	)

	// create and return a scanner object
	s := scanner.NewScanner(options, commandLine, timeStart, threads)
	return s, nil
}

func ExecuteAnon(s *scanner.Scanner, target string) error {
	logger.Warn("Executing anon module")

	// generate a random username for anonymous access check
	s.Options.Username = "anonymous_" + scanner.RandSeq(8)
	logger.Warnf("Using username for anonymous access: %s", s.Options.Username)

	var wg sync.WaitGroup
	s.RunAuthEnumeration(&wg)
	err := s.ParseTargets(target)
	if err != nil {
		return err
	}
	wg.Wait()

	// finish the execution
	s.TimeEnd = time.Now()
	logger.Warnf("Finished executing anon module at %s", s.TimeEnd)
	s.CloseOutputter()
	return nil
}

func ExecuteAuth(s *scanner.Scanner, target, username, password, hash string, localAuth bool) error {
	var targetDomain string
	var targetUsername string

	logger.Warn("Executing auth module")

	// check if both password and hash are provided
	if password != "" && hash != "" {
		return errors.New("--password can't be used with --hashes")
	}

	// check for local authentication option to parse username correctly
	if localAuth {
		targetDomain = ""
		targetUsername = username
	} else {
		trySplit := strings.Split(username, "\\")
		if len(trySplit) != 2 {
			return errors.New("invalid username. Try DOMAIN\\username")
		}
		targetDomain = trySplit[0]
		targetUsername = trySplit[1]
	}

	s.Options.Username = targetUsername
	s.Options.Password = password
	s.Options.Hashes = []byte(hash)
	s.Options.Domain = targetDomain
	s.Options.LocalAuth = localAuth

	var wg sync.WaitGroup

	// run the enumeration threads
	s.RunAuthEnumeration(&wg)
	// parse targets and send them to targets channel
	err := s.ParseTargets(target)
	if err != nil {
		return err
	}
	wg.Wait()

	// finish the execution
	s.TimeEnd = time.Now()
	logger.Warnf("Finished executing auth module at %s", s.TimeEnd)
	s.CloseOutputter()
	return nil
}

func ExecuteHunt(s *scanner.Scanner, username, password, hash string, dc, resolver net.IP) error {
	var targetDomain string
	var targetUsername string

	logger.Warn("Executing hunt module")

	// check if both password and hash are provided
	if password != "" && hash != "" {
		return errors.New("--password can't be used with --hashes")
	}

	// try to parse username in format DOMAIN\username
	trySplit := strings.Split(username, "\\")
	if len(trySplit) != 2 {
		return errors.New("invalid username. Try DOMAIN\\username")
	}
	targetDomain = strings.ToLower(trySplit[0])
	targetUsername = strings.ToLower(trySplit[1])

	s.Options.Username = targetUsername
	s.Options.Password = password
	s.Options.Hashes = []byte(hash)
	s.Options.Domain = targetDomain
	s.Options.LocalAuth = false
	s.Options.DomainController = dc
	s.Options.CustomResolver = resolver

	var wg sync.WaitGroup

	logger.Warnf("Starting %s domain enumeration", s.Options.Domain)

	// enumerate possible targets via domain controller
	possibleTargets, err := s.RunEnumerateDomainComputers()
	if err != nil {
		return err
	}

	logger.Warnf("Found %d domain computers", len(possibleTargets))
	logger.Warn("Starting SMB shares enumeration")

	// check for shares and permissions on identified targets
	s.RunAuthEnumeration(&wg)
	// send identified targets for processing channel
	s.ParseTargetsInMemory(possibleTargets)
	wg.Wait()

	// finish the execution
	s.TimeEnd = time.Now()
	logger.Warnf("Finished executing hunt module at %s", s.TimeEnd)
	s.CloseOutputter()
	return nil
}
