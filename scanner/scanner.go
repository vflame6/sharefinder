package scanner

import (
	"bufio"
	"errors"
	"fmt"
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
	// Regular LDAP for forest discovery: the GC's partial attribute set excludes
	// crossRef.systemFlags, so a config-NC crossRef search on 3268 returns 0 hits.
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
		false,
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

	// Prefer GC for cross-domain SearchComputers (one connection covers the forest).
	// If GC is unreachable we keep ldapConn and chase referrals per-domain below.
	queryConn := ldapConn
	if s.Options.Forest {
		gcConn, gcErr := NewLDAPConnection(
			s.Options.DomainController,
			s.Options.Username,
			s.Options.Password,
			s.Options.Hash,
			strings.ToLower(s.Options.Domain),
			s.Options.Timeout,
			s.Options.ProxyDialer,
			s.Options.Kerberos,
			s.Options.DCHostname,
			true,
		)
		if gcErr != nil {
			logger.Warnf("Global Catalog unavailable on %s, will chase per-domain referrals: %v", s.Options.DomainController, gcErr)
		} else {
			defer gcConn.Close()
			queryConn = gcConn
		}
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
		sr, err := queryConn.SearchComputers(searchBase.BaseDN)
		if err != nil && isLDAPReferral(err) {
			// Referral-chase fallback: connect directly to a DC of the referred domain.
			logger.Warnf("Domain %s referred — chasing via direct DC connection", searchBase.Name)
			altConn, dialErr := s.dialDCForDomain(searchBase.Name, &r, resolver)
			if dialErr != nil {
				logger.Warnf("Skipping domain %s: %v", searchBase.Name, dialErr)
				continue
			}
			sr, err = altConn.SearchComputers(searchBase.BaseDN)
			altConn.Close()
		}
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

// dialDCForDomain resolves domainName via DNS and opens a regular LDAP connection
// to a DC of that domain. Used when the Global Catalog is unavailable and a
// SearchComputers query against the user-specified DC returned an LDAP referral.
// AD-integrated DNS registers the domain name itself as A records for every DC,
// so a plain host lookup yields a usable target. The resolver pointer is updated
// in-place if a UDP→TCP retry succeeds, mirroring the test-entry validation below.
func (s *Scanner) dialDCForDomain(domainName string, r **Resolver, resolverIP net.IP) (*LDAPConnection, error) {
	ip, err := (*r).LookupHost(domainName)
	if err != nil && s.Options.ProxyDialer == nil {
		tcpResolver := NewResolver("tcp", resolverIP, s.Options.Timeout, nil)
		if ip2, err2 := tcpResolver.LookupHost(domainName); err2 == nil {
			ip, err = ip2, nil
			*r = tcpResolver
		}
	}
	if err != nil {
		return nil, fmt.Errorf("DNS lookup for %s: %w", domainName, err)
	}

	dcHostname := s.Options.DCHostname
	if s.Options.Kerberos {
		// Kerberos SPN must match the alt DC's hostname; reverse-resolve the IP.
		// Cross-realm Kerberos may still fail downstream — the in-memory krb5 config
		// has only the user's realm — but failing fast here gives a clearer error.
		names, rerr := net.LookupAddr(ip.String())
		if rerr != nil || len(names) == 0 {
			return nil, fmt.Errorf("kerberos referral fallback to %s requires reverse-DNS for SPN: %v", ip, rerr)
		}
		dcHostname = strings.TrimSuffix(names[0], ".")
	}

	return NewLDAPConnection(
		ip,
		s.Options.Username,
		s.Options.Password,
		s.Options.Hash,
		strings.ToLower(s.Options.Domain),
		s.Options.Timeout,
		s.Options.ProxyDialer,
		s.Options.Kerberos,
		dcHostname,
		false,
	)
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
