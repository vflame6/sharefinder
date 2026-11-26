package scanner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/vflame6/sharefinder/logger"
)

// Scanner is a struct so store scanner's configuration and execute commands
type Scanner struct {
	Options     *Options
	CommandLine []string
	TimeStart   time.Time
	TimeEnd     time.Time
	Threads     int
	Version     string // sharefinder version, for the outputs
	Interrupted bool   // the scan was stopped by Ctrl+C
	Stats       Stats  // counts for the summary line and the end record

	closeOnce sync.Once
	scanned   sync.Map // addresses already scanned, for deduplication
	slots     slots    // SMB connections in use, at most Threads; made by Run
	tempJSON  string   // JSONL file created only to render --html, removed at the end
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
	}
}

// CloseOutputter terminates and closes the output files and renders the HTML
// report. It runs once: the normal exit path and the interrupt path may both
// call it.
func (s *Scanner) CloseOutputter() {
	s.closeOnce.Do(s.closeOutputs)
}

// StartOutputs builds the sinks for the opened output files: the console
// (and -o text file), XML, JSONL, CSV and the UNC list. Call it once the
// identity is known; it does nothing when Options.Sink is already set.
func (s *Scanner) StartOutputs() {
	o := s.Options
	if o.Sink != nil {
		return
	}
	// the HTML report is rendered from JSONL: without --output-json, a
	// temporary JSONL file is written and removed once the report is done
	if o.OutputHTML && o.FileJSON == nil {
		if f, err := os.CreateTemp("", "sharefinder-*.jsonl"); err != nil {
			logger.Error(fmt.Errorf("cannot write the HTML report: %w", err))
		} else {
			o.FileJSON, o.OutputJSONFileName, s.tempJSON = f, f.Name(), f.Name()
		}
	}
	sinks := MultiSink{NewTextSink(fileOrNil(o.FileTXT))}
	if o.FileXML != nil {
		sinks = append(sinks, NewXMLSink(o.FileXML, ""))
	}
	if o.FileJSON != nil {
		sinks = append(sinks, NewJSONLSink(o.FileJSON, ScanRecord{
			ScanID:   NewScanID(),
			Time:     s.TimeStart,
			Version:  s.Version,
			Command:  strings.Join(MaskCredentials(s.CommandLine), " "),
			Identity: o.Identity(),
		}))
	}
	if o.FileCSV != nil {
		sinks = append(sinks, NewCSVSink(o.FileCSV, o.Identity()))
	}
	if o.FileUNC != nil {
		sinks = append(sinks, NewUNCSink(o.FileUNC))
	}
	o.Sink = sinks
}

// fileOrNil keeps a nil *os.File from becoming a non-nil io.Writer.
func fileOrNil(f *os.File) io.Writer {
	if f == nil {
		return nil
	}
	return f
}

func (s *Scanner) closeOutputs() {
	if s.TimeEnd.IsZero() {
		s.TimeEnd = time.Now()
	}
	// a run that never started (e.g. hunt failed in LDAP) still terminates
	// its XML and JSONL files
	s.StartOutputs()
	if err := s.Options.Sink.Close(s.endRecord()); err != nil {
		logger.Error(err)
	}
	for _, f := range []*os.File{s.Options.FileTXT, s.Options.FileXML, s.Options.FileJSON, s.Options.FileCSV, s.Options.FileUNC} {
		if f != nil {
			_ = f.Close()
		}
	}

	if s.Options.OutputHTML && s.Options.OutputJSONFileName != "" {
		if err := s.writeHTMLReport(); err != nil {
			logger.Error(fmt.Errorf("writing the HTML report: %w", err))
		}
	}
	if s.tempJSON != "" {
		_ = os.Remove(s.tempJSON)
	}
}

// writeHTMLReport renders the HTML report from the scan's JSONL output.
func (s *Scanner) writeHTMLReport() error {
	logger.Debugf("Generating HTML report. Output file: %s", s.Options.OutputHTMLFileName)
	f, err := s.Options.Writer.CreateFile(s.Options.OutputHTMLFileName, false)
	if err != nil {
		return err
	}
	if err := WriteReport(s.Options.OutputJSONFileName, f); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// TargetsFromList returns a Producer that sends hosts in order.
func TargetsFromList(hosts []DNHost) Producer {
	return func(ctx context.Context, out chan<- DNHost) error {
		for _, h := range hosts {
			select {
			case <-ctx.Done():
				return context.Cause(ctx)
			case out <- h:
			}
		}
		return nil
	}
}

// RunEnumerateDomainComputers is executed by hunt command to get a list of hosts
func (s *Scanner) RunEnumerateDomainComputers(ctx context.Context) ([]DNHost, error) {
	// Regular LDAP for forest discovery: the GC's partial attribute set excludes
	// crossRef.systemFlags, so a config-NC crossRef search on 3268 returns 0 hits.
	ldapConn, err := NewLDAPConnection(ctx, s.ldapOptions(s.Options.DomainController, s.Options.DCHostname, false))
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := ldapConn.Close(); err != nil {
			logger.Error(err)
		}
	}()

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
		gcConn, gcErr := NewLDAPConnection(ctx, s.ldapOptions(s.Options.DomainController, s.Options.DCHostname, true))
		if gcErr != nil {
			logger.Warnf("Global Catalog unavailable on %s, will chase per-domain referrals: %v", s.Options.DomainController, gcErr)
		} else {
			defer func() {
				if err := gcConn.Close(); err != nil {
					logger.Error(err)
				}
			}()
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
	if s.Options.Dialer.Proxied() {
		r = NewResolver("tcp", resolver, s.Options.Timeout, s.Options.Dialer)
	} else {
		r = NewResolver("udp", resolver, s.Options.Timeout, nil)
	}

	for i, searchBase := range searchBases {
		logger.Warnf("Enumerating domain %s", searchBase.Name)
		sr, err := queryConn.SearchComputers(searchBase.BaseDN)
		if err != nil && isLDAPReferral(err) {
			// Referral-chase fallback: connect directly to a DC of the referred domain.
			logger.Warnf("Domain %s referred — chasing via direct DC connection", searchBase.Name)
			altConn, dialErr := s.dialDCForDomain(ctx, searchBase.Name, &r, resolver)
			if dialErr != nil {
				logger.Warnf("Skipping domain %s: %v", searchBase.Name, dialErr)
				continue
			}
			sr, err = altConn.SearchComputers(searchBase.BaseDN)
			if closeErr := altConn.Close(); closeErr != nil {
				logger.Error(closeErr)
			}
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
			if s.Options.Dialer.Proxied() {
				_, err = r.LookupHost(ctx, testEntry)
				if err != nil {
					return nil, err
				}
			} else {
				_, err = r.LookupHost(ctx, testEntry)
				if err != nil {
					r = NewResolver("tcp", resolver, s.Options.Timeout, nil)
					_, err = r.LookupHost(ctx, testEntry)
					if err != nil {
						return nil, err
					}
				}
			}
		}

		for _, entry := range sr.Entries {
			if ctx.Err() != nil {
				return nil, context.Cause(ctx)
			}
			hostname := entry.GetAttributeValue("dNSHostName")
			if hostname == "" {
				continue
			}

			possibleTarget, err := r.LookupHost(ctx, hostname)
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
func (s *Scanner) dialDCForDomain(ctx context.Context, domainName string, r **Resolver, resolverIP net.IP) (*LDAPConnection, error) {
	ip, err := (*r).LookupHost(ctx, domainName)
	if err != nil && !s.Options.Dialer.Proxied() {
		tcpResolver := NewResolver("tcp", resolverIP, s.Options.Timeout, nil)
		if ip2, err2 := tcpResolver.LookupHost(ctx, domainName); err2 == nil {
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
		names, rerr := net.DefaultResolver.LookupAddr(ctx, ip.String())
		if rerr != nil || len(names) == 0 {
			return nil, fmt.Errorf("kerberos referral fallback to %s requires reverse-DNS for SPN: %v", ip, rerr)
		}
		dcHostname = strings.TrimSuffix(names[0], ".")
	}

	return NewLDAPConnection(ctx, s.ldapOptions(ip, dcHostname, false))
}

// ldapOptions describes an LDAP connection to host with the scan's credentials.
func (s *Scanner) ldapOptions(host net.IP, dcHostname string, useGC bool) LDAPOptions {
	return LDAPOptions{
		Host:           host,
		Username:       s.Options.Username,
		Password:       s.Options.Password,
		Hash:           s.Options.Hash,
		Domain:         strings.ToLower(s.Options.Domain),
		DCHostname:     dcHostname,
		Kerberos:       s.Options.Kerberos,
		UseGC:          useGC,
		AllowPlaintext: s.Options.AllowPlaintextLDAP,
		Dialer:         s.Options.Dialer,
	}
}
