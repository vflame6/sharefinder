package cmd

import (
	"encoding/hex"
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

func CreateScanner(version string, commandLine []string, timeStart time.Time, outputRaw, outputXML, outputAll string, outputHTML bool, threads int, timeout time.Duration, exclude string, list, recurse bool, smbPort int, proxyStr string) (*scanner.Scanner, error) {
	var outputRawFileName string
	var outputXMLFileName string
	var outputHTMLFileName string
	var outputWriter *scanner.OutputWriter
	var file *os.File
	var fileXML *os.File
	var err error
	var proxyDialer proxy.Dialer

	// HTML output is available only if basic output is specified
	// it is done like that because HTML file is generated based on generated XML
	if outputHTML && outputXML == "" {
		return nil, errors.New("cannot use --html without --output-xml")
	}

	if (outputXML != "" || outputRaw != "" || outputHTML) && outputAll != "" {
		return nil, errors.New("cannot use --output-all with --output-raw, --output-xml or --html")
	}

	// recursive output is available only if the list option is specified
	// it is done like that just to make the execution clear and avoid user mistakes
	if recurse && !list {
		return nil, errors.New("cannot use --recurse without --list")
	}

	outputWriter = scanner.NewOutputWriter()
	if outputRaw != "" {
		// trim suffix of output filename if it matches with txt/xml/html
		outputRawFileName = outputRaw + ".txt"
		logger.Debugf("Output in Raw format option is specified. Output file name: %s", outputRawFileName)

		// create raw text output file
		file, err = outputWriter.CreateFile(outputRawFileName, false)
		if err != nil {
			return nil, err
		}
	}

	if outputXML != "" {
		// trim suffix of output filename if it matches with txt/xml/html
		outputXMLFileName = outputXML + ".xml"
		logger.Debugf("Output in XML format option is specified. Output file name: %s", outputXMLFileName)

		// create XML output file and write an XML header line to it
		fileXML, err = outputWriter.CreateFile(outputXMLFileName, false)
		if err != nil {
			return nil, err
		}
		err = outputWriter.WriteXMLHeader(version, commandLine, timeStart, fileXML)
		if err != nil {
			return nil, err
		}
	}

	if outputHTML {
		outputHTMLFileName = outputXML + ".html"
	}

	if outputAll != "" {
		logger.Debugf("Output all formats option is specified. Output file name: %s", outputAll)

		// set HTML output variable to true in case of --output-all
		outputHTML = true
		outputHTMLFileName = outputAll + ".html"

		// trim suffix of output filename if it matches with txt/xml/html
		outputRawFileName = outputAll + ".txt"

		// create raw text output file
		file, err = outputWriter.CreateFile(outputRawFileName, false)
		if err != nil {
			return nil, err
		}

		outputXMLFileName = outputAll + ".xml"
		// create XML output file and write an XML header line to it
		fileXML, err = outputWriter.CreateFile(outputXMLFileName, false)
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
	options := &scanner.Options{
		DCHostname:         "",
		Domain:             "",
		DomainController:   net.IPv4zero,
		Exclude:            excludeList,
		FileTXT:            file,
		FileXML:            fileXML,
		Hash:               "",
		HashBytes:          []byte{},
		Kerberos:           false,
		List:               list,
		LocalAuth:          false,
		NullSession:        false,
		OutputHTML:         outputHTML,
		OutputHTMLFileName: outputHTMLFileName,
		OutputRawFileName:  outputRawFileName,
		OutputXMLFileName:  outputXMLFileName,
		Password:           "",
		ProxyDialer:        proxyDialer,
		Recurse:            recurse,
		SmbPort:            smbPort,
		Target:             make(chan scanner.DNHost, 256),
		Timeout:            timeout,
		Username:           "",
		Writer:             outputWriter,
	}

	// create and return a scanner object
	s := scanner.NewScanner(options, commandLine, timeStart, threads)
	return s, nil
}

func ExecuteNull(s *scanner.Scanner, target string) error {
	logger.Warn("Executing null module")

	// configure options to use null session
	s.Options.NullSession = true

	var wg sync.WaitGroup
	s.RunSMBEnumeration(&wg)
	err := s.ParseTargets(target)
	if err != nil {
		return err
	}
	wg.Wait()

	// finish the execution
	s.TimeEnd = time.Now()
	logger.Warnf("Finished executing null module at %s", s.TimeEnd.Format("02/01/2006 15:04:05"))
	s.CloseOutputter()
	return nil
}

func ExecuteAnon(s *scanner.Scanner, target, username string) error {
	logger.Warn("Executing anon module")

	if username != "" {
		// use the username specified by the user
		s.Options.Username = username
	} else {
		// generate a random username for anonymous access check
		s.Options.Username = "anonymous_" + scanner.RandSeq(8)
	}
	logger.Warnf("Using username for anonymous access: %s", s.Options.Username)

	var wg sync.WaitGroup
	s.RunSMBEnumeration(&wg)
	err := s.ParseTargets(target)
	if err != nil {
		return err
	}
	wg.Wait()

	// finish the execution
	s.TimeEnd = time.Now()
	logger.Warnf("Finished executing anon module at %s", s.TimeEnd.Format("02/01/2006 15:04:05"))
	s.CloseOutputter()
	return nil
}

func ExecuteAuth(s *scanner.Scanner, target, username, password, hash string, localAuth bool) error {
	var targetDomain string
	var targetUsername string
	var err error

	logger.Warn("Executing auth module")

	// if both password and hashes are empty, will use blank password to authenticate
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

	// try to decode hash
	var hashBytes []byte
	if hash != "" {
		hashBytes, err = hex.DecodeString(hash)
		if err != nil {
			return err
		}
	}

	s.Options.Username = targetUsername
	s.Options.Password = password
	s.Options.Hash = hash
	s.Options.HashBytes = hashBytes
	s.Options.Domain = targetDomain
	s.Options.LocalAuth = localAuth

	var wg sync.WaitGroup

	// run the enumeration threads
	s.RunSMBEnumeration(&wg)
	// parse targets and send them to targets channel
	err = s.ParseTargets(target)
	if err != nil {
		return err
	}
	wg.Wait()

	// finish the execution
	s.TimeEnd = time.Now()
	logger.Warnf("Finished executing auth module at %s", s.TimeEnd.Format("02/01/2006 15:04:05"))
	s.CloseOutputter()
	return nil
}

func ExecuteHunt(s *scanner.Scanner, username, password, hash string, dc, resolver net.IP, kerberos bool, dcHostname string) error {
	var targetDomain string
	var targetUsername string
	var err error

	logger.Warn("Executing hunt module")

	// if both password and hashes are empty, will use blank password to authenticate
	// check if both password and hash are provided
	if password != "" && hash != "" {
		return errors.New("--password can't be used with --hashes")
	}

	// check if dcHostname is provided with kerberos authentication
	if kerberos && dcHostname == "" {
		return errors.New("--kerberos can't be used without --dc-hostname")
	}

	// try to parse username in format DOMAIN\username
	trySplit := strings.Split(username, "\\")
	if len(trySplit) != 2 {
		return errors.New("invalid username. Try DOMAIN\\username")
	}
	targetDomain = strings.ToLower(trySplit[0])
	targetUsername = strings.ToLower(trySplit[1])

	// try to decode hash
	var hashBytes []byte
	if hash != "" {
		hashBytes, err = hex.DecodeString(hash)
		if err != nil {
			return err
		}
	}

	s.Options.Username = targetUsername
	s.Options.Password = password
	s.Options.Hash = hash
	s.Options.HashBytes = hashBytes
	s.Options.Kerberos = kerberos
	s.Options.Domain = targetDomain
	s.Options.LocalAuth = false
	s.Options.DomainController = dc
	s.Options.DCHostname = dcHostname
	s.Options.CustomResolver = resolver

	var wg sync.WaitGroup

	logger.Warnf("Starting %s domain enumeration", s.Options.Domain)

	// enumerate possible targets via domain controller
	possibleTargets, err := s.RunEnumerateDomainComputers()
	if err != nil {
		return err
	}

	logger.Warnf("Found %d domain computers. Starting SMB shares enumeration...", len(possibleTargets))

	// check for shares and permissions on identified targets
	s.RunSMBEnumeration(&wg)
	// send identified targets for processing channel
	s.ParseTargetsInMemory(possibleTargets)
	wg.Wait()

	// finish the execution
	s.TimeEnd = time.Now()
	logger.Warnf("Finished executing hunt module at %s", s.TimeEnd.Format("02/01/2006 15:04:05"))
	s.CloseOutputter()
	return nil
}
