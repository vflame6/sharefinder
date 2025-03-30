package scanner

import (
	"bufio"
	"errors"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

type Scanner struct {
	Options     *Options
	CommandLine []string
	TimeStart   time.Time
	TimeEnd     time.Time
	Threads     int
	Stop        chan bool
}

func NewScanner(options *Options, commandLine []string, timeStart time.Time, threads int) *Scanner {
	return &Scanner{
		Options:     options,
		CommandLine: commandLine,
		TimeStart:   timeStart,
		Threads:     threads,
		Stop:        make(chan bool),
	}
}

func (s *Scanner) CloseOutputter() {
	_ = s.Options.File.Close()

	err := s.Options.Writer.WriteXMLFooter(s.TimeEnd, s.Options.FileXML)
	if err != nil {
		log.Println("Error writing XML Footer:", err)
	}
	_ = s.Options.FileXML.Close()
}

func (s *Scanner) ParseTargets(target string) error {
	var targets []string
	if _, err := os.Stat(target); errors.Is(err, os.ErrNotExist) {
		// target file does not exist
		// try to parse as IP/CIDR
		targets, err = ParseIPOrCIDR(target)
		if err != nil {
			return err
		}
		for _, t := range targets {
			s.Options.Target <- t
		}
		close(s.Options.Target)
		return nil
	}
	file, err := os.Open(target)
	if err != nil {
		return err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		// skip empty line
		line := strings.TrimSpace(scanner.Text())
		if len(line) == 0 {
			continue
		}

		targets, err = ParseIPOrCIDR(line)
		if err != nil {
			return err
		}
		for _, t := range targets {
			s.Options.Target <- t
		}
	}
	close(s.Options.Target)
	return nil
}

func (s *Scanner) ParseTargetsInMemory(targets []net.IP) error {
	for _, target := range targets {
		s.Options.Target <- target.String()
	}
	close(s.Options.Target)
	return nil
}

func (s *Scanner) RunAuthEnumeration(wg *sync.WaitGroup) {
	for i := 0; i < s.Threads; i++ {
		wg.Add(1)
		go authThread(s.Stop, s.Options, wg)
	}
}

func (s *Scanner) RunEnumerateDomainComputers() ([]net.IP, error) {
	var results []net.IP

	ldapConn, err := NewLDAPConnection(s.Options.DomainController, s.Options.Username, s.Options.Password, s.Options.Domain)
	if err != nil {
		return nil, err
	}
	defer ldapConn.Close()

	sr, err := ldapConn.SearchComputers(GetBaseDN(s.Options.Domain))
	if err != nil {
		return nil, err
	}
	if len(sr.Entries) == 0 {
		return nil, errors.New("no domain computers found")
	}

	// test if DNS works with UDP
	testEntry := sr.Entries[0].GetAttributeValue("dNSHostName")
	r := NewUDPResolver(s.Options.DomainController, s.Options.Timeout)
	_, err = r.LookupHost(testEntry)
	if err != nil {
		// test if DNS works with TCP
		r = NewTCPResolver(s.Options.DomainController, s.Options.Timeout)
		_, err = r.LookupHost(testEntry)
		if err != nil {
			return nil, err
		}
	}

	for _, entry := range sr.Entries {
		hostname := entry.GetAttributeValue("dNSHostName")
		possibleTarget, err := r.LookupHost(hostname)
		if err != nil {
			log.Println(err)
			continue
		}
		results = append(results, possibleTarget)
	}

	return results, nil
}

func (s *Scanner) RunHuntDomainTargets(wg *sync.WaitGroup, possibleTargets []net.IP) []net.IP {
	var liveTargets []net.IP
	targets := make(chan net.IP, 256)
	results := make(chan net.IP)

	// Separate WaitGroup for scanner threads
	var scanWg sync.WaitGroup

	// Start scan threads
	for i := 0; i < s.Threads; i++ {
		scanWg.Add(1)
		go scanThread(s.Stop, &scanWg, targets, results, s.Options)
	}

	wg.Add(1)
	// Collect results
	go func() {
		for result := range results {
			liveTargets = append(liveTargets, result)
		}
		wg.Done()
	}()

	// Send targets
	for _, target := range possibleTargets {
		targets <- target
	}
	close(targets)

	// Wait for scan threads to finish, then close results
	scanWg.Wait()
	close(results)

	// Wait for results collector to finish
	wg.Wait()

	return liveTargets
}

func (s *Scanner) Shutdown() {
	for i := 0; i < s.Threads; i++ {
		s.Stop <- true
	}
	close(s.Stop)
}
