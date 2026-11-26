package cmd

import (
	"cmp"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
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
	var outputCSVFileName string
	var outputUNCFileName string
	var fileJSON *os.File
	var fileCSV *os.File
	var fileUNC *os.File
	var file *os.File
	var fileXML *os.File
	var err error

	outputHTML := cfg.OutputHTML

	// the HTML report is named after the JSONL or XML output
	if outputHTML && cfg.OutputJSON == "" && cfg.OutputXML == "" && cfg.Resume == "" {
		return nil, errors.New("cannot use --html without --output-json, --resume or --output-xml: the report is named after them")
	}

	if (cfg.OutputXML != "" || cfg.OutputRaw != "" || cfg.OutputJSON != "" || cfg.OutputCSV != "" || cfg.OutputUNC != "" || outputHTML) && cfg.OutputAll != "" {
		return nil, errors.New("cannot use --output-all with -o, --output-xml, --output-json, --output-csv, --output-unc or --html")
	}

	// --resume continues only the JSONL file: the text, XML, CSV and UNC files
	// of the interrupted run would be recreated with only the rest of the scan
	if cfg.Resume != "" {
		for _, out := range []struct {
			set  bool
			flag string
		}{
			{cfg.OutputRaw != "", "-o"}, {cfg.OutputXML != "", "--output-xml"}, {cfg.OutputCSV != "", "--output-csv"},
			{cfg.OutputUNC != "", "--output-unc"}, {cfg.OutputAll != "", "--output-all"},
		} {
			if out.set {
				return nil, fmt.Errorf("--resume continues only the JSONL file and cannot be combined with %s; use --html, or the report command once the scan is complete", out.flag)
			}
		}
	}

	// recursive output is available only if the list option is specified
	// it is done like that just to make the execution clear and avoid user mistakes
	if cfg.Recurse && !cfg.List {
		return nil, errors.New("cannot use --recurse without --list")
	}

	if cfg.Threads < 1 {
		return nil, errors.New("--threads must be at least 1")
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
	if cfg.MaxConnsPerHost < 1 {
		return nil, errors.New("--max-conns-per-host must be at least 1")
	}

	writeCheck, err := scanner.ParseWriteCheckMode(cfg.WriteCheck)
	if err != nil {
		return nil, err
	}

	discovery, err := discoveryConfig(cfg)
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
		outputCSVFileName = scanner.OutputPath(cfg.OutputAll, ".csv")
		outputUNCFileName = scanner.OutputPath(cfg.OutputAll, ".unc.txt")
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
		if cfg.OutputCSV != "" {
			outputCSVFileName = scanner.OutputPath(cfg.OutputCSV, ".csv")
		}
		if cfg.OutputUNC != "" {
			outputUNCFileName = scanner.OutputPath(cfg.OutputUNC, ".unc.txt")
		}
		if outputHTML {
			base := cmp.Or(cfg.OutputJSON, cfg.Resume, cfg.OutputXML)
			outputHTMLFileName = scanner.OutputPath(base, ".html")
		}
	}
	// --resume continues the JSONL file of an interrupted scan: it is the
	// JSONL output, appended to, so it is not an existing file to refuse
	if cfg.Resume != "" {
		if outputJSONFileName != "" && filepath.Clean(outputJSONFileName) != filepath.Clean(cfg.Resume) {
			return nil, fmt.Errorf("--resume continues %s, so JSONL output cannot also go to %s", cfg.Resume, outputJSONFileName)
		}
		if info, err := os.Stat(cfg.Resume); err != nil || !info.Mode().IsRegular() {
			return nil, fmt.Errorf("--resume: there is no scan file %s to resume", cfg.Resume)
		}
		outputJSONFileName = cfg.Resume
	}
	var outputs []string
	for _, name := range []string{outputRawFileName, outputXMLFileName, outputJSONFileName, outputCSVFileName, outputUNCFileName, outputHTMLFileName} {
		if name != "" && (cfg.Resume == "" || name != outputJSONFileName) {
			outputs = append(outputs, name)
		}
	}
	if err := scanner.CheckOverwrite(outputs, cfg.Force); err != nil {
		return nil, err
	}
	var resume *scanner.ResumeState
	if cfg.Resume != "" {
		if resume, err = scanner.LoadResume(cfg.Resume); err != nil {
			return nil, err
		}
		if now := resumeCommand(cfg.CommandLine); now != resumeCommand(strings.Fields(resume.Command)) {
			logger.Warnf("--resume: %s was written by a different command: sharefinder %s", cfg.Resume, resume.Command)
		}
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
		fileJSON, err = outputWriter.CreateFile(outputJSONFileName, resume != nil)
		if err != nil {
			return nil, err
		}
	}
	if outputCSVFileName != "" {
		logger.Debugf("Writing CSV output to %s", outputCSVFileName)
		fileCSV, err = outputWriter.CreateFile(outputCSVFileName, false)
		if err != nil {
			return nil, err
		}
	}
	if outputUNCFileName != "" {
		logger.Debugf("Writing the UNC list to %s", outputUNCFileName)
		fileUNC, err = outputWriter.CreateFile(outputUNCFileName, false)
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
		Discovery:          discovery,
		FollowLinks:        cfg.FollowLinks,
		MaxFiles:           cfg.MaxFiles,
		MaxConnsPerHost:    cfg.MaxConnsPerHost,
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
		FileCSV:            fileCSV,
		FileUNC:            fileUNC,
		Password:           "",
		Recurse:            cfg.Recurse,
		Resume:             resume,
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

// discoveryConfig validates the sweep flags. Through --proxy every probe is a
// SOCKS request, so unless the user chose otherwise the sweep runs 50 probes
// at once and waits as long as the SMB stage (--timeout): a short timeout over
// a slow tunnel would drop live hosts without a trace.
func discoveryConfig(cfg Config) (scanner.SweepConfig, error) {
	sweep := scanner.SweepConfig{Enabled: cfg.Discovery, Threads: cfg.DiscoveryThreads, Timeout: cfg.ConnectTimeout}
	if !sweep.Enabled {
		return sweep, nil
	}
	if cfg.Proxy != "" {
		if !cfg.DiscoveryThreadsSet {
			sweep.Threads = 50
		}
		if !cfg.ConnectTimeoutSet {
			sweep.Timeout = cfg.Timeout
		}
	}
	if sweep.Threads < 1 {
		return sweep, errors.New("--discovery-threads must be at least 1")
	}
	if sweep.Timeout <= 0 {
		return sweep, errors.New("--connect-timeout must be greater than 0")
	}
	return sweep, nil
}

// resumeIgnored lists the flags that change how a scan is shown, saved or
// paced, not what it finds; the value says whether the flag takes one.
var resumeIgnored = map[string]bool{
	"--resume": true, "-o": true, "--output": true, "--output-xml": true, "--output-json": true,
	"--output-csv": true, "--output-unc": true, "--output-all": true, "--threads": true,
	"--discovery-threads": true, "--connect-timeout": true, "--max-conns-per-host": true,
	"--quiet": false, "--debug": false, "--force": false, "--html": false, "--discovery": false,
}

// resumeCommand is a command line as --resume compares it: credentials
// masked, without the flags in resumeIgnored.
func resumeCommand(args []string) string {
	var kept []string
	for i := 0; i < len(args); i++ {
		name, _, inline := strings.Cut(args[i], "=")
		takesValue, ignored := resumeIgnored[strings.Replace(name, "--no-", "--", 1)]
		switch {
		case !ignored:
			kept = append(kept, args[i])
		case takesValue && !inline:
			i++ // skip the value too
		}
	}
	return strings.Join(scanner.MaskCredentials(kept), " ")
}

// runScan enumerates the hosts produce sends and logs how the module ended.
func runScan(ctx context.Context, s *scanner.Scanner, module string, produce scanner.Producer) error {
	s.StartOutputs()
	err := s.Run(ctx, produce)
	// stopped early by Ctrl+C or by an error such as the lockout guard: the
	// outputs say so, and resume and diff do not take the scan for complete
	switch {
	case ctx.Err() != nil:
		s.Interrupted, s.StopReason = true, "interrupted"
	case err != nil:
		s.Interrupted, s.StopReason = true, err.Error()
	}
	s.TimeEnd = time.Now()
	if n := s.Stats.Resumed.Load(); n > 0 {
		logger.Warnf("Skipped %d host(s) finished in %s", n, s.Options.OutputJSONFileName)
	}
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
	s.Stats.Total.Store(int64(set.Len()))
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

	// list the domain computers via the domain controller; their names are
	// resolved while the scan runs
	computers, dns, err := s.EnumerateDomainComputers(ctx)
	if err != nil {
		return err
	}

	logger.Warnf("Found %d domain computers. Starting SMB shares enumeration...", len(computers))
	s.Stats.Total.Store(int64(len(computers)))

	return runScan(ctx, s, "hunt", s.HuntTargets(computers, dns.LookupHost))
}
