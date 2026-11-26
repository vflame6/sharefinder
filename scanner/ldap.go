package scanner

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"github.com/go-ldap/ldap/v3/gssapi"
	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/vflame6/sharefinder/logger"
	"math"
	"net"
	"os"
	"strings"
	"time"
)

// isLDAPReferral reports whether err is an LDAP referral response (result code 10),
// which AD returns for searches against a non-local domain partition over 389/636.
func isLDAPReferral(err error) bool {
	var le *ldap.Error
	if errors.As(err, &le) {
		return le.ResultCode == ldap.LDAPResultReferral
	}
	return false
}

type LDAPConnection struct {
	connection *ldap.Conn
	gssClient  *gssapi.Client
}

type DomainPartition struct {
	Name   string
	BaseDN string
}

func GetBaseDN(domain string) string {
	result := "dc="
	dns := strings.Split(domain, ".")
	result += strings.Join(dns, ",dc=")
	return result
}

// LDAPOptions describes one LDAP connection to a domain controller.
type LDAPOptions struct {
	Host       net.IP
	Username   string
	Password   string
	Hash       string
	Domain     string
	DCHostname string
	Kerberos   bool
	UseGC      bool // Global Catalog ports 3269/3268 instead of 636/389
	// AllowPlaintext permits a simple bind, which sends the password, over
	// LDAP without TLS when LDAPS and StartTLS both fail.
	AllowPlaintext bool
	Dialer         *Dialer
	// AESKey is the Kerberos AES key of the user (--aes-key)
	AESKey []byte
}

// ldapTransport is how the LDAP connection is protected.
type ldapTransport int

const (
	transportLDAPS ldapTransport = iota
	transportStartTLS
	transportPlain
)

// bindMethod is how sharefinder authenticates to LDAP.
type bindMethod int

const (
	bindGSSAPI bindMethod = iota + 1
	bindNTLMHash
	bindNTLMPassword
	bindSimple
)

// chooseBind picks the bind for the credentials and transport. Kerberos never
// falls back to another method. Over plain LDAP a password goes into an NTLM
// bind, which does not send it; a simple bind, which sends it in clear text,
// is used there only when AllowPlaintext is set.
func chooseBind(o LDAPOptions, t ldapTransport) (bindMethod, error) {
	switch {
	case o.Kerberos:
		return bindGSSAPI, nil
	case o.Hash != "":
		return bindNTLMHash, nil
	case t == transportPlain && !o.AllowPlaintext:
		return bindNTLMPassword, nil
	default:
		return bindSimple, nil
	}
}

// ldapBinder is the part of *ldap.Conn that binds.
type ldapBinder interface {
	GSSAPIBind(client ldap.GSSAPIClient, servicePrincipal, authzid string) error
	NTLMBindWithHash(domain, username, hash string) error
	NTLMBind(domain, username, password string) error
	Bind(username, password string) error
}

// bindLDAP performs exactly the bind chooseBind selects.
func bindLDAP(b ldapBinder, o LDAPOptions, t ldapTransport, gss ldap.GSSAPIClient) error {
	method, err := chooseBind(o, t)
	if err != nil {
		return err
	}
	switch method {
	case bindGSSAPI:
		// SPN must be host-based ldap/<fqdn>
		spn := "ldap/" + strings.ToLower(o.DCHostname)
		if err := b.GSSAPIBind(gss, spn, ""); err != nil {
			return fmt.Errorf("kerberos LDAP bind failed: %w", err)
		}
	case bindNTLMHash:
		if err := b.NTLMBindWithHash(o.Domain, o.Username, o.Hash); err != nil {
			return fmt.Errorf("NTLM bind failed: %w", err)
		}
	case bindNTLMPassword:
		if err := b.NTLMBind(o.Domain, o.Username, o.Password); err != nil {
			return fmt.Errorf("NTLM bind failed: %w", err)
		}
	default:
		// simple bind with UPN (user@domain)
		if err := b.Bind(o.Username+"@"+o.Domain, o.Password); err != nil {
			return fmt.Errorf("simple bind failed: %w", err)
		}
	}
	return nil
}

// NewLDAPConnection connects to the domain controller over LDAPS, else LDAP
// with StartTLS, else plain LDAP, and binds with the credentials in o.
func NewLDAPConnection(ctx context.Context, o LDAPOptions) (*LDAPConnection, error) {
	l, transport, err := dialLDAP(ctx, o)
	if err != nil {
		return nil, err
	}
	conn := &LDAPConnection{connection: l}

	var gss ldap.GSSAPIClient
	if o.Kerberos {
		gc, err := newGSSAPIClient(o)
		if err != nil {
			_ = l.Close()
			return nil, err
		}
		conn.gssClient = gc
		gss = gc
	}
	if err := bindLDAP(l, o, transport, gss); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

// dialLDAP opens the best protected LDAP connection the server offers. It
// does not open a plain connection that could not be used to bind.
func dialLDAP(ctx context.Context, o LDAPOptions) (*ldap.Conn, ldapTransport, error) {
	// GC ports (3268/3269) avoid LDAP referrals for cross-domain searches; required by --forest.
	ldapsAddr, ldapAddr := net.JoinHostPort(o.Host.String(), "636"), net.JoinHostPort(o.Host.String(), "389")
	if o.UseGC {
		ldapsAddr, ldapAddr = net.JoinHostPort(o.Host.String(), "3269"), net.JoinHostPort(o.Host.String(), "3268")
	}
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}
	ioTimeout := o.Dialer.IOTimeout()
	withTimeout := func(l *ldap.Conn) *ldap.Conn {
		if ioTimeout > 0 {
			l.SetTimeout(ioTimeout)
		}
		return l
	}

	// LDAPS
	if raw, err := o.Dialer.DialTracked(ctx, "tcp", ldapsAddr); err == nil {
		tlsConn := tls.Client(raw, tlsConfig)
		// handshake now, bounded by the connect timeout, so a server that
		// accepts TCP but never speaks TLS cannot hang the scan
		handshakeCtx, cancel := context.WithTimeout(ctx, o.Dialer.ConnectTimeout())
		err = tlsConn.HandshakeContext(handshakeCtx)
		cancel()
		if err == nil {
			l := ldap.NewConn(tlsConn, true)
			l.Start()
			return withTimeout(l), transportLDAPS, nil
		}
		_ = raw.Close()
	}

	// LDAP with StartTLS
	logger.Warnf("Failed to connect to LDAPS on %s, trying LDAP with STARTTLS", ldapsAddr)
	raw, err := o.Dialer.DialTracked(ctx, "tcp", ldapAddr)
	if err != nil {
		return nil, 0, err
	}
	l := ldap.NewConn(raw, false)
	l.Start()
	// bound the StartTLS exchange and handshake, then lift the deadline:
	// afterwards go-ldap's request timeout governs the connection
	if ioTimeout > 0 {
		_ = raw.SetDeadline(time.Now().Add(ioTimeout))
	}
	err = l.StartTLS(tlsConfig)
	_ = raw.SetDeadline(time.Time{})
	if err == nil {
		return withTimeout(l), transportStartTLS, nil
	}
	_ = l.Close()

	// plain LDAP: a password goes into an NTLM bind unless a simple bind was
	// explicitly allowed
	if method, _ := chooseBind(o, transportPlain); method == bindSimple {
		logger.Warnf("Failed to set up STARTTLS on %s; trying plain LDAP with a simple bind, which sends the password in clear text (--allow-plaintext-ldap)", ldapAddr)
	} else {
		logger.Warnf("Failed to set up STARTTLS on %s, trying plain LDAP without sending the password", ldapAddr)
	}
	raw, err = o.Dialer.DialTracked(ctx, "tcp", ldapAddr)
	if err != nil {
		return nil, 0, err
	}
	l = ldap.NewConn(raw, false)
	l.Start()
	return withTimeout(l), transportPlain, nil
}

// newGSSAPIClient builds a Kerberos client from the AES key, KRB5CCNAME or the
// password.
func newGSSAPIClient(o LDAPOptions) (*gssapi.Client, error) {
	if o.DCHostname == "" {
		return nil, fmt.Errorf("dcHostname is required for Kerberos (used as KDC and SPN host)")
	}

	// build krb5 config in memory — no temp files
	realm := strings.ToUpper(o.Domain)
	krb5Conf, err := newKrb5Config(realm, o.Host.String())
	if err != nil {
		return nil, fmt.Errorf("krb5 config: %w", err)
	}

	// an AES key given with --aes-key first, then the ccache (KRB5CCNAME),
	// then the password
	if len(o.AESKey) > 0 {
		kt, err := aesKeytab(o.Username, realm, o.AESKey)
		if err != nil {
			return nil, fmt.Errorf("gssapi: %w", err)
		}
		return &gssapi.Client{Client: client.NewWithKeytab(o.Username, realm, kt, krb5Conf)}, nil
	}
	if ccachePath, ccErr := ccachePathFromEnv(); ccErr == nil {
		ccache, err := credentials.LoadCCache(ccachePath)
		if err != nil {
			return nil, fmt.Errorf("gssapi: load ccache file: %w", err)
		}
		krbClient, err := client.NewFromCCache(ccache, krb5Conf)
		if err != nil {
			return nil, fmt.Errorf("gssapi: ccache client: %w", err)
		}
		return &gssapi.Client{Client: krbClient}, nil
	}
	if o.Password != "" {
		return &gssapi.Client{Client: client.NewWithPassword(o.Username, realm, o.Password, krb5Conf)}, nil
	}
	return nil, fmt.Errorf("kerberos requires --aes-key, a KRB5CCNAME ccache or a password")
}

func (c *LDAPConnection) Close() error {
	var first error
	if c.connection != nil {
		if err := c.connection.Close(); err != nil && first == nil {
			first = err
		}
	}
	if c.gssClient != nil {
		if err := c.gssClient.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// --- helpers ---

func ccachePathFromEnv() (string, error) {
	cc := os.Getenv("KRB5CCNAME")
	if cc == "" {
		return "", fmt.Errorf("KRB5CCNAME not set; a Kerberos ccache is required for GSSAPI bind")
	}
	if strings.HasPrefix(cc, "FILE:") {
		return strings.TrimPrefix(cc, "FILE:"), nil
	}
	// If it's a bare path, just return it. Other schemes (DIR:, KEYRING:, API:) are not handled here.
	return cc, nil
}

// newKrb5Config builds a minimal krb5 config in memory for the given AD realm and KDC address.
func newKrb5Config(realm, kdcAddr string) (*config.Config, error) {
	confStr := fmt.Sprintf(`[libdefaults]
  default_realm = %s
  dns_lookup_kdc = false
  dns_canonicalize_hostname = false
  rdns = false
[realms]
  %s = {
    kdc = %s:88
  }
[domain_realm]
  .%s = %s
  %s = %s
`, realm, realm, kdcAddr, strings.ToLower(realm), realm, strings.ToLower(realm), realm)

	return config.NewFromString(confStr)
}

func (conn *LDAPConnection) SearchComputers(baseDN string) (*ldap.SearchResult, error) {
	searchRequest := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		math.MaxInt32,
		0,
		false,
		"(objectCategory=Computer)",
		[]string{"dNSHostName"},
		nil,
	)
	sr, err := conn.connection.SearchWithPaging(searchRequest, math.MaxInt32)
	if err != nil {
		return nil, err
	}
	return sr, nil
}

func (conn *LDAPConnection) SearchForestDomains() ([]DomainPartition, error) {
	rootDSERequest := ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		1,
		0,
		false,
		"(objectClass=*)",
		[]string{"configurationNamingContext"},
		nil,
	)
	rootDSEResult, err := conn.connection.Search(rootDSERequest)
	if err != nil {
		return nil, err
	}
	if len(rootDSEResult.Entries) == 0 {
		return nil, fmt.Errorf("empty rootDSE response")
	}

	configNC := rootDSEResult.Entries[0].GetAttributeValue("configurationNamingContext")
	if configNC == "" {
		return nil, fmt.Errorf("configurationNamingContext not found")
	}

	searchRequest := ldap.NewSearchRequest(
		configNC,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		math.MaxInt32,
		0,
		false,
		"(&(objectClass=crossRef)(systemFlags:1.2.840.113556.1.4.803:=2)(dnsRoot=*)(nCName=*))",
		[]string{"dnsRoot", "nCName"},
		nil,
	)
	sr, err := conn.connection.SearchWithPaging(searchRequest, math.MaxInt32)
	if err != nil {
		return nil, err
	}

	return extractDomainPartitions(sr.Entries)
}

func extractDomainPartitions(entries []*ldap.Entry) ([]DomainPartition, error) {
	seen := make(map[string]struct{})
	results := make([]DomainPartition, 0, len(entries))
	for _, entry := range entries {
		name := strings.ToLower(strings.TrimSpace(entry.GetAttributeValue("dnsRoot")))
		baseDN := strings.TrimSpace(entry.GetAttributeValue("nCName"))
		if name == "" || baseDN == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		results = append(results, DomainPartition{Name: name, BaseDN: baseDN})
	}

	if len(results) == 0 {
		return nil, fmt.Errorf("no forest domains found")
	}

	return results, nil
}
