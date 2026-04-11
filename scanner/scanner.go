package scanner

import (
	"bufio"
	"errors"
	"github.com/vflame6/sharefinder/logger"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// Scanner is a struct so store scanner's configuration and execute commands
type Scanner struct {
	Options     *Options
	CommandLine []string
	TimeStart   time.Time
	TimeEnd     time.Time
	Threads     int
	Stop        chan bool
}

type DNHost struct {
	Hostname string
	IP       net.IP
}

// NewScanner is a function to create new Scanner struct
func NewScanner(options *Options, commandLine []string, timeStart time.Time, threads int) *Scanner {
	return &Scanner{
		Options:     options,
		CommandLine: commandLine,
		TimeStart:   timeStart,
		Threads:     threads,
		Stop:        make(chan bool),
	}
}

// CloseOutputter is a function to close output files channels
func (s *Scanner) CloseOutputter() {
	if s.Options.FileTXT != nil {
		_ = s.Options.FileTXT.Close()
	}
	if s.Options.FileXML != nil {
		err := s.Options.Writer.WriteXMLFooter(s.TimeEnd, s.Options.FileXML)
		if err != nil {
			logger.Error(err)
		}
		_ = s.Options.FileXML.Close()

		if s.Options.OutputHTML {
			xmlFile, err := s.Options.Writer.ReadFile(s.Options.OutputXMLFileName)
			if err != nil {
				logger.Error(err)
			}

			err = s.OutputHTML(xmlFile)
			if err != nil {
				logger.Error(err)
			}
		}
	}
}

// ParseTargets function used to parse IP-address, IP-range or file and pass them in targets channel
func (s *Scanner) ParseTargets(target string) error {
	var targets []string

	// check if the file with specified name is NOT available
	if _, err := os.Stat(target); errors.Is(err, os.ErrNotExist) {
		// target file does not exist
		// try to parse specified string as IP/CIDR
		targets, err = ParseIPOrCIDR(target)
		if err != nil {
			return err
		}

		// pass to targets channel
		for _, t := range targets {
			dnHost := &DNHost{
				Hostname: "",
				IP:       net.ParseIP(t),
			}
			s.Options.Target <- *dnHost
		}
		// close the channel if targets are over
		close(s.Options.Target)
		return nil
	}

	// if the file is available, read it and then parse it
	file, err := os.Open(target)
	if err != nil {
		return err
	}
	defer file.Close()

	// scan the file
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		// skip empty line
		line := strings.TrimSpace(scanner.Text())
		if len(line) == 0 {
			continue
		}

		// try to parse specified string as IP/CIDR
		targets, err = ParseIPOrCIDR(line)
		if err != nil {
			return err
		}
		for _, t := range targets {
			dnHost := &DNHost{
				Hostname: "",
				IP:       net.ParseIP(t),
			}
			s.Options.Target <- *dnHost
		}
	}
	// close the channel if targets are over
	close(s.Options.Target)
	return nil
}

// ParseTargetsInMemory is used to parse a list of targets and pass them in targets list
func (s *Scanner) ParseTargetsInMemory(targets []DNHost) {
	for _, target := range targets {
		s.Options.Target <- target
	}
	close(s.Options.Target)
}

// RunSMBEnumeration is executed by auth command
func (s *Scanner) RunSMBEnumeration(wg *sync.WaitGroup) {
	for i := 0; i < s.Threads; i++ {
		wg.Add(1)
		go smbThread(s.Stop, s.Options, wg)
	}
}

// RunEnumerateDomainComputers is executed by hunt command to get a list of hosts
func (s *Scanner) RunEnumerateDomainComputers() ([]DNHost, error) {
	ldapConn, err := NewLDAPConnection(
		s.Options.DomainController,
		s.Options.Username,
		s.Options.Password,
		s.Options.Hash,
		strings.ToLower(s.Options.Domain),
		s.Options.Timeout,
		s.Options.ProxyDialer,
		s.Options.Kerberos,
		s.Options.DCHostname,
	)
	if err != nil {
		return nil, err
	}
	defer ldapConn.Close()

	var searchBases []DomainPartition
	if s.Options.Forest {
		searchBases, err = ldapConn.SearchForestDomains()
		if err != nil {
			return nil, err
		}
	} else {
		searchBases = []DomainPartition{{
			Name:   strings.ToLower(s.Options.Domain),
			BaseDN: GetBaseDN(s.Options.Domain),
		}}
	}

	if len(searchBases) == 0 {
		return nil, errors.New("no domain naming contexts found")
	}

	var results []DNHost
	seenHosts := make(map[string]struct{})
	var resolver net.IP
	if s.Options.CustomResolver != nil {
		resolver = s.Options.CustomResolver
	} else {
		resolver = s.Options.DomainController
	}

	var r *Resolver
	if s.Options.ProxyDialer != nil {
		r = NewResolver("tcp", resolver, s.Options.Timeout, s.Options.ProxyDialer)
	} else {
		r = NewResolver("udp", resolver, s.Options.Timeout, nil)
	}

	for i, searchBase := range searchBases {
		logger.Warnf("Enumerating domain %s", searchBase.Name)
		sr, err := ldapConn.SearchComputers(searchBase.BaseDN)
		if err != nil {
			logger.Warnf("Skipping domain %s: %v", searchBase.Name, err)
			continue
		}
		if len(sr.Entries) == 0 {
			continue
		}

		if i == 0 {
			testEntry := sr.Entries[0].GetAttributeValue("dNSHostName")
			if s.Options.ProxyDialer != nil {
				_, err = r.LookupHost(testEntry)
				if err != nil {
					return nil, err
				}
			} else {
				_, err = r.LookupHost(testEntry)
				if err != nil {
					r = NewResolver("tcp", resolver, s.Options.Timeout, nil)
					_, err = r.LookupHost(testEntry)
					if err != nil {
						return nil, err
					}
				}
			}
		}

		for _, entry := range sr.Entries {
			hostname := entry.GetAttributeValue("dNSHostName")
			if hostname == "" {
				continue
			}

			possibleTarget, err := r.LookupHost(hostname)
			if err != nil {
				logger.Debug(err.Error())
				continue
			}
			key := strings.ToLower(hostname) + "|" + possibleTarget.String()
			if _, ok := seenHosts[key]; ok {
				continue
			}
			seenHosts[key] = struct{}{}
			results = append(results, DNHost{Hostname: hostname, IP: possibleTarget})
		}
	}

	if len(results) == 0 {
		return nil, errors.New("no domain computers found")
	}

	return results, nil
}

// OutputHTML is used to generate HTML output from XML output
func (s *Scanner) OutputHTML(data []byte) error {
	// parse XML data
	result, err := ParseSharefinderRun(data)
	if err != nil {
		return err
	}

	// create the HTML file and write to it
	logger.Debugf("Generating HTML report. Output file: %s", s.Options.OutputHTMLFileName)
	fileHTML, err := s.Options.Writer.CreateFile(s.Options.OutputHTMLFileName, false)
	if err != nil {
		return err
	}
	err = s.Options.Writer.WriteHTML(result, fileHTML)
	if err != nil {
		return err
	}

	return nil
}

// Shutdown is a function to stop the scan by external caller
func (s *Scanner) Shutdown() {
	for i := 0; i < s.Threads; i++ {
		s.Stop <- true
	}
	close(s.Stop)
}
