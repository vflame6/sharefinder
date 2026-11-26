package cmd

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/vflame6/sharefinder/logger"
	"github.com/vflame6/sharefinder/scanner"
	"github.com/vflame6/sharefinder/utils"
)

// CreateScanner validates the global options, opens the requested output
// files and returns a scanner without credentials; commands add those.
func CreateScanner(cfg Config) (*scanner.Scanner, error) {
	var outputRawFileName string
	var outputXMLFileName string
	var outputHTMLFileName string
	var outputJSONFileName string
	var fileJSON *os.File
	var file *os.File
	var fileXML *os.File
	var err error

	outputHTML := cfg.OutputHTML

	// HTML output is available only if basic output is specified
	// it is done like that because HTML file is generated based on generated XML
	if outputHTML && cfg.OutputXML == "" {
		return nil, errors.New("cannot use --html without --output-xml")
	}

	if (cfg.OutputXML != "" || cfg.OutputRaw != "" || cfg.OutputJSON != "" || outputHTML) && cfg.OutputAll != "" {
		return nil, errors.New("cannot use --output-all with -o, --output-xml, --output-json or --html")
	}

	// recursive output is available only if the list option is specified
	// it is done like that just to make the execution clear and avoid user mistakes
	if cfg.Recurse && !cfg.List {
		return nil, errors.New("cannot use --recurse without --list")
	}

	if cfg.Timeout <= 0 {
		return nil, errors.New("--timeout must be greater than 0")
	}
	if cfg.IOTimeout < 0 {
		return nil, errors.New("--io-timeout must be 0 (no limit) or more")
	}
	if cfg.MaxAuthFailures < 0 {
		return nil, errors.New("--max-auth-failures must be 0 (no limit) or more")
	}
	if cfg.Depth < 0 {
		return nil, errors.New("--depth must be 0 (share root only) or more")
	}
	if cfg.MaxFiles < 0 {
		return nil, errors.New("--max-files must be 0 (no limit) or more")
	}

	writeCheck, err := scanner.ParseWriteCheckMode(cfg.WriteCheck)
	if err != nil {
		return nil, err
	}

	// every SMB, LDAP and proxied DNS connection goes through this dialer: it
	// applies the connect and I/O timeouts and can close everything on Ctrl+C
	dialer, err := scanner.NewDialer(cfg.Proxy, cfg.Timeout, cfg.IOTimeout)
	if err != nil {
		return nil, err
	}

	// scope control: these targets are never scanned, also when a hostname
	// or a hunt result resolves into them
	var excludeHosts *scanner.TargetSet
	if cfg.ExcludeHosts != "" {
		excludeHosts, err = scanner.ParseExcludeSpec(cfg.ExcludeHosts)
		if err != nil {
			return nil, fmt.Errorf("--exclude-hosts: %w", err)
		}
		excludeHostsSummary(excludeHosts, dialer, cfg.Timeout)
	}

	// resolve every output file name first: a known extension is replaced,
	// not doubled, and nothing is created when any of them already exists
	switch {
	case cfg.OutputAll != "":
		outputHTML = true
		outputRawFileName = scanner.OutputPath(cfg.OutputAll, ".txt")
		outputXMLFileName = scanner.OutputPath(cfg.OutputAll, ".xml")
		outputJSONFileName = scanner.OutputPath(cfg.OutputAll, ".jsonl")
		outputHTMLFileName = scanner.OutputPath(cfg.OutputAll, ".html")
	default:
		if cfg.OutputRaw != "" {
			outputRawFileName = scanner.OutputPath(cfg.OutputRaw, ".txt")
		}
		if cfg.OutputXML != "" {
			outputXMLFileName = scanner.OutputPath(cfg.OutputXML, ".xml")
		}
		if cfg.OutputJSON != "" {
			outputJSONFileName = scanner.OutputPath(cfg.OutputJSON, ".jsonl")
		}
		if outputHTML {
			outputHTMLFileName = scanner.OutputPath(cfg.OutputXML, ".html")
		}
	}
	var outputs []string
	for _, name := range []string{outputRawFileName, outputXMLFileName, outputJSONFileName, outputHTMLFileName} {
		if name != "" {
			outputs = append(outputs, name)
		}
	}
	if err := scanner.CheckOverwrite(outputs, cfg.Force); err != nil {
		return nil, err
	}

	outputWriter := scanner.NewOutputWriter()
	if outputRawFileName != "" {
		logger.Debugf("Writing raw output to %s", outputRawFileName)
		file, err = outputWriter.CreateFile(outputRawFileName, false)
		if err != nil {
			return nil, err
		}
	}
	if outputJSONFileName != "" {
		logger.Debugf("Writing JSONL output to %s", outputJSONFileName)
		fileJSON, err = outputWriter.CreateFile(outputJSONFileName, false)
		if err != nil {
			return nil, err
		}
	}
	if outputXMLFileName != "" {
		logger.Debugf("Writing XML output to %s", outputXMLFileName)
		// create XML output file and write an XML header line to it
		fileXML, err = outputWriter.CreateFile(outputXMLFileName, false)
		if err != nil {
			return nil, err
		}
		err = outputWriter.WriteXMLHeader(cfg.Version, cfg.CommandLine, cfg.TimeStart, fileXML)
		if err != nil {
			return nil, err
		}
	}

	// excludeList is created from string of words divided by ","
	excludeList := strings.Split(cfg.Exclude, ",")

	// scanner options are created without credentials just to specify global flags
	// the credentials will be specified on execution of authenticated modules
	options := &scanner.Options{
		DCHostname:         "",
		Dialer:             dialer,
		Domain:             "",
		DomainController:   net.IPv4zero,
		Exclude:            excludeList,
		ExcludeHosts:       excludeHosts,
		AuthGuard:          scanner.NewAuthGuard(cfg.MaxAuthFailures),
		WriteCheck:         writeCheck,
		Depth:              cfg.Depth,
		FollowLinks:        cfg.FollowLinks,
		MaxFiles:           cfg.MaxFiles,
		FileTXT:            file,
		FileXML:            fileXML,
		Hash:               "",
		HashBytes:          []byte{},
		IOTimeout:          cfg.IOTimeout,
		Kerberos:           false,
		List:               cfg.List,
		LocalAuth:          false,
		NullSession:        false,
		OutputHTML:         outputHTML,
		OutputHTMLFileName: outputHTMLFileName,
		OutputRawFileName:  outputRawFileName,
		OutputXMLFileName:  outputXMLFileName,
		FileJSON:           fileJSON,
		OutputJSONFileName: outputJSONFileName,
		Password:           "",
		Recurse:            cfg.Recurse,
		SmbPort:            cfg.SmbPort,
		Timeout:            cfg.Timeout,
		Username:           "",
		Writer:             outputWriter,
	}

	// create and return a scanner object
	s := scanner.NewScanner(options, cfg.CommandLine, cfg.TimeStart, cfg.Threads)
	s.Version = cfg.Version
	return s, nil
}

// runScan enumerates the hosts produce sends and logs how the module ended.
func runScan(ctx context.Context, s *scanner.Scanner, module string, produce scanner.Producer) error {
	s.StartOutputs()
	err := s.Run(ctx, produce)
	s.Interrupted = ctx.Err() != nil
	s.TimeEnd = time.Now()
	if ctx.Err() != nil || err != nil {
		logger.Warnf("Stopped %s module at %s", module, s.TimeEnd.Format("02/01/2006 15:04:05"))
		return err
	}
	logger.Warnf("Finished executing %s module at %s", module, s.TimeEnd.Format("02/01/2006 15:04:05"))
	return err
}

// excludeHostsSummary resolves excluded hostnames, so that they also exclude
// targets given as IP addresses, and reports what is excluded.
func excludeHostsSummary(ex *scanner.TargetSet, dialer *scanner.Dialer, timeout time.Duration) {
	if dialer.Proxied() {
		if _, names := ex.Counts(); names > 0 {
			logger.Warn("--exclude-hosts: with --proxy, excluded hostnames are matched by name only; exclude their IP addresses too")
		}
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		unresolved := ex.ResolveNames(ctx, scanner.SystemLookup)
		cancel()
		for _, name := range unresolved {
			logger.Warnf("--exclude-hosts: cannot resolve %s; it is excluded by name only", name)
		}
	}
	addrs, names := ex.Counts()
	logger.Warnf("Excluding %d addresses and %d hostnames (--exclude-hosts)", addrs, names)
}

// loadTargets parses the target argument, removes --exclude-hosts and returns
// a producer for what is left.
func loadTargets(s *scanner.Scanner, target string) (scanner.Producer, error) {
	set, err := scanner.ParseTargetSpec(target)
	if err != nil {
		return nil, err
	}
	total := set.Len()
	if ex := s.Options.ExcludeHosts; ex != nil && s.Options.Dialer.Proxied() {
		_, targetNames := set.Counts()
		if exAddrs, _ := ex.Counts(); targetNames > 0 && exAddrs > 0 {
			logger.Warn("--proxy resolves hostname targets remotely, so excluded addresses cannot be checked against them; exclude those hostnames by name")
		}
	}
	set.Subtract(s.Options.ExcludeHosts)
	if set.Len() == 0 {
		return nil, errors.New("no targets left after --exclude-hosts")
	}
	if excluded := total - set.Len(); excluded > 0 {
		logger.Warnf("Loaded %d targets (%d excluded by --exclude-hosts)", set.Len(), excluded)
	} else {
		logger.Debugf("Loaded %d targets", set.Len())
	}
	return scanner.TargetsProducer(set), nil
}

func ExecuteNull(ctx context.Context, s *scanner.Scanner, target string) error {
	logger.Warn("Executing null module")

	// configure options to use null session
	s.Options.NullSession = true
	s.Options.Mode = scanner.AuthNull

	produce, err := loadTargets(s, target)
	if err != nil {
		return err
	}
	return runScan(ctx, s, "null", produce)
}

func ExecuteGuest(ctx context.Context, s *scanner.Scanner, target, username string) error {
	logger.Warn("Executing guest module")

	if username != "" {
		// use the username specified by the user
		s.Options.Username = username
	} else {
		// generate a random username for Guest access check
		s.Options.Username = "anonymous_" + utils.RandSeq(8)
	}
	logger.Warnf("Using username for Guest access: %s", s.Options.Username)
	s.Options.Mode = scanner.AuthGuest

	produce, err := loadTargets(s, target)
	if err != nil {
		return err
	}
	return runScan(ctx, s, "guest", produce)
}

func ExecuteAuth(ctx context.Context, s *scanner.Scanner, target, username, password, hash string, localAuth, kerberos bool, dcHostname string, dcIP net.IP) error {
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

	// check if dcHostname is provided with kerberos authentication
	if kerberos && dcHostname == "" {
		return errors.New("--kerberos can't be used without --dc-hostname")
	}

	s.Options.Username = targetUsername
	s.Options.Password = password
	s.Options.Hash = hash
	s.Options.HashBytes = hashBytes
	s.Options.Domain = targetDomain
	s.Options.LocalAuth = localAuth
	s.Options.Kerberos = kerberos
	s.Options.DCHostname = dcHostname
	if dcIP != nil {
		s.Options.DomainController = dcIP
	}

	produce, err := loadTargets(s, target)
	if err != nil {
		return err
	}
	return runScan(ctx, s, "auth", produce)
}

func ExecuteHunt(ctx context.Context, s *scanner.Scanner, username, password, hash string, dc, resolver net.IP, forest, kerberos bool, dcHostname string, allowPlaintextLDAP bool) error {
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
	s.Options.Forest = forest
	s.Options.AllowPlaintextLDAP = allowPlaintextLDAP

	if s.Options.Forest {
		logger.Warnf("Starting forest-wide enumeration from %s", s.Options.Domain)
	} else {
		logger.Warnf("Starting %s domain enumeration", s.Options.Domain)
	}

	// enumerate possible targets via domain controller
	possibleTargets, err := s.RunEnumerateDomainComputers(ctx)
	if err != nil {
		return err
	}

	logger.Warnf("Found %d domain computers. Starting SMB shares enumeration...", len(possibleTargets))

	return runScan(ctx, s, "hunt", scanner.TargetsFromList(possibleTargets))
}
