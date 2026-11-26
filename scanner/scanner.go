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
	Interrupted bool   // the scan stopped early: Ctrl+C, or an error such as the lockout guard
	StopReason  string // why it stopped early, for the end record
	NoScan      bool   // nothing was scanned (hunt --ldap-only): no summary
	Stats       Stats  // counts for the summary line and the end record

	closeOnce sync.Once
	scanned   sync.Map   // addresses already scanned, for deduplication
	slots     slots      // SMB connections in use, at most Threads; made by Run
	tempJSON  string     // JSONL file created only to render --html, removed at the end
	matrixMu  sync.Mutex // one host's matrix printed at a time
}

type DNHost struct {
	Hostname string
	IP       net.IP
	OS       string // operating system from LDAP (hunt)
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
	var sinks MultiSink
	// a matrix prints its own table on the console and in the text file
	if len(o.Matrix) == 0 {
		sinks = append(sinks, NewTextSink(fileOrNil(o.FileTXT)))
	}
	if o.FileXML != nil {
		sinks = append(sinks, NewXMLSink(o.FileXML, ""))
	}
	if o.FileJSON != nil && o.Resume != nil {
		sinks = append(sinks, ResumeJSONLSink(o.FileJSON, o.Resume, o.Identity()))
	} else if o.FileJSON != nil {
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
	if o.FileRelay != nil {
		relay := NewRelaySink(o.FileRelay)
		sinks = append(sinks, relay)
		o.OnNegotiated = relay.Negotiated
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
	for _, f := range []*os.File{s.Options.FileTXT, s.Options.FileXML, s.Options.FileJSON, s.Options.FileCSV, s.Options.FileUNC, s.Options.FileRelay} {
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

// EnumerateDomainComputers lists the computers of the domain (or forest) by
// their DNS names, without addresses, and returns the resolver that answers
// for them: the domain's DNS (--resolver or the DC), over UDP, or over TCP when
// UDP does not answer or --proxy is set. HuntTargets resolves the names.
func (s *Scanner) EnumerateDomainComputers(ctx context.Context) ([]DNHost, *Resolver, error) {
	// Regular LDAP for forest discovery: the GC's partial attribute set excludes
	// crossRef.systemFlags, so a config-NC crossRef search on 3268 returns 0 hits.
	ldapConn, err := NewLDAPConnection(ctx, s.ldapOptions(s.Options.DomainController, s.Options.DCHostname, false))
	if err != nil {
		return nil, nil, err
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
			return nil, nil, err
		}
	} else {
		searchBases = []DomainPartition{{
			Name:   strings.ToLower(s.Options.Domain),
			BaseDN: GetBaseDN(s.Options.Domain),
		}}
	}

	if len(searchBases) == 0 {
		return nil, nil, errors.New("no domain naming contexts found")
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

	var names []DNHost
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

	// enabled computers unless --include-disabled, and with --active-within
	// only those that logged on recently
	var activeSince time.Time
	if s.Options.ActiveWithin > 0 {
		activeSince = time.Now().Add(-s.Options.ActiveWithin)
	}
	filter := computerFilter(s.Options.IncludeDisabled, activeSince)

	// DFS servers are scanned only within the domains being hunted
	hunted := make(map[string]bool, len(searchBases))
	for _, searchBase := range searchBases {
		hunted[strings.ToLower(searchBase.Name)] = true
	}

	for _, searchBase := range searchBases {
		logger.Warnf("Enumerating domain %s", printable(searchBase.Name))
		conn := queryConn
		sr, err := conn.SearchComputers(searchBase.BaseDN, filter)
		var altConn *LDAPConnection
		if err != nil && isLDAPReferral(err) {
			// Referral-chase fallback: connect directly to a DC of the referred domain.
			logger.Warnf("Domain %s referred — chasing via direct DC connection", printable(searchBase.Name))
			var dialErr error
			if altConn, dialErr = s.dialDCForDomain(ctx, searchBase.Name, &r, resolver); dialErr != nil {
				logger.Warnf("Skipping domain %s: %v", printable(searchBase.Name), dialErr)
				continue
			}
			conn = altConn
			sr, err = conn.SearchComputers(searchBase.BaseDN, filter)
		}
		if err != nil {
			logger.Warnf("Skipping domain %s: %v", printable(searchBase.Name), err)
		} else {
			for _, entry := range sr.Entries {
				if hostname := entry.GetAttributeValue("dNSHostName"); hostname != "" {
					osName := strings.TrimSpace(entry.GetAttributeValue("operatingSystem") + " " + entry.GetAttributeValue("operatingSystemVersion"))
					names = append(names, DNHost{Hostname: hostname, OS: osName})
				}
			}
			// file servers behind DFS links: those of the hunted domains are
			// added, the others are named and left out of scope
			if servers, dfsErr := conn.SearchDFSServers(searchBase.BaseDN); dfsErr != nil {
				logger.Debugf("No DFS targets from domain %s: %v", printable(searchBase.Name), dfsErr)
			} else if before := len(names); len(servers) > 0 {
				var foreign []string
				names, foreign = mergeDFSServers(names, servers, searchBase.Name, hunted)
				if added := len(names) - before; added > 0 {
					logger.Warnf("Domain %s: %d more server(s) from DFS links", printable(searchBase.Name), added)
				}
				if len(foreign) > 0 {
					logger.Warnf("Domain %s: not scanning DFS link servers outside the hunted domain(s): %s (scan them with auth if they are in scope)",
						printable(searchBase.Name), printable(strings.Join(foreign, ", ")))
				}
			}
		}
		if altConn != nil {
			if closeErr := altConn.Close(); closeErr != nil {
				logger.Error(closeErr)
			}
		}
	}
	if ctx.Err() != nil {
		return nil, nil, context.Cause(ctx)
	}
	if len(names) == 0 {
		return nil, nil, errors.New("no domain computers found")
	}

	// choose the transport once, on the first name: UDP unless it does not
	// answer, TCP through --proxy
	if _, err := r.LookupHost(ctx, names[0].Hostname); err != nil {
		if s.Options.Dialer.Proxied() {
			return nil, nil, err
		}
		r = NewResolver("tcp", resolver, s.Options.Timeout, nil)
		if _, err := r.LookupHost(ctx, names[0].Hostname); err != nil {
			return nil, nil, err
		}
	}
	return names, r, nil
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
		AESKey:         s.Options.AESKey,
	}
}
