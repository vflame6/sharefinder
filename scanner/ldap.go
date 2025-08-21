package scanner

import (
	"crypto/tls"
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"github.com/go-ldap/ldap/v3/gssapi"
	"github.com/vflame6/sharefinder/logger"
	"golang.org/x/net/proxy"
	"math"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type LDAPConnection struct {
	connection *ldap.Conn
	gssClient  *gssapi.Client
}

func GetBaseDN(domain string) string {
	result := "dc="
	dns := strings.Split(domain, ".")
	result += strings.Join(dns, ",dc=")
	return result
}

func NewLDAPConnection(host net.IP, username, password string, hash string, domain string, timeout time.Duration, proxyDialer proxy.Dialer, kerberos bool, dcHostname string) (*LDAPConnection, error) {
	var l *ldap.Conn
	var err error

	dialLDAPS := fmt.Sprintf("%s:636", host.String())
	dialLDAP := fmt.Sprintf("%s:389", host.String())

	var dialer proxy.Dialer
	if proxyDialer != nil {
		dialer = proxyDialer
	} else {
		dialer = &net.Dialer{Timeout: timeout}
	}
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}

	// LDAP connection setup

	// try to connect over LDAPS
	var isLDAPS bool
	connect, err := dialer.Dial("tcp", dialLDAPS)
	if err == nil {
		// Wrap raw TCP connection in TLS with our config
		tlsConn := tls.Client(connect, tlsConfig)

		// Force handshake now so errors are caught early
		if err = tlsConn.Handshake(); err != nil {
			isLDAPS = false
		} else {
			// Hand the TLS connection to go-ldap
			l = ldap.NewConn(tlsConn, true)
			l.Start()
			isLDAPS = true
		}
	} else {
		isLDAPS = false
	}

	if !isLDAPS {
		// try LDAP with STARTTLS if LDAPS is failed
		logger.Warnf("Failed to connect to LDAPS on %s, trying LDAP with STARTTLS", dialLDAPS)

		connect, err = dialer.Dial("tcp", dialLDAP)
		if err != nil {
			return nil, err
		}
		l = ldap.NewConn(connect, false)
		l.Start()
		err = l.StartTLS(tlsConfig)

		// if all of that failed go plain LDAP
		if err != nil {
			logger.Warnf("Failed to set up STARTTLS on %s, trying plain LDAP", dialLDAP)
			connect, err = dialer.Dial("tcp", dialLDAP)
			if err != nil {
				return nil, err
			}
			l = ldap.NewConn(connect, false)
			l.Start()
		}
	}

	conn := &LDAPConnection{connection: l}

	// LDAP authentication

	// --- Bind: Kerberos -> NTLM hash -> simple ---
	if kerberos {
		// 1) read ccache path from env (no system krb5.conf dependency)
		ccachePath, err := ccachePathFromEnv()
		if err != nil {
			_ = l.Close()
			return nil, err
		}

		// 2) generate a minimal krb5.conf in a temp file (no global files needed)
		realm := strings.ToUpper(domain) // AD realm = uppercased DNS domain
		if dcHostname == "" {
			_ = l.Close()
			return nil, fmt.Errorf("dcHostname is required for Kerberos (used as KDC and SPN host)")
		}
		krbConfPath, cleanup, err := writeMinimalKrb5Conf(realm, dcHostname+"."+domain)
		if err != nil {
			_ = l.Close()
			return nil, fmt.Errorf("create krb5.conf: %w", err)
		}
		// ensure cleanup later if we fail after this
		defer func() {
			if conn.gssClient == nil { // didn’t succeed binding
				_ = os.Remove(krbConfPath)
			}
		}()

		// 3) build GSSAPI client from ccache + our generated krb5.conf
		gc, err := gssapi.NewClientFromCCache(ccachePath, krbConfPath)
		if err != nil {
			_ = l.Close()
			cleanup()
			return nil, fmt.Errorf("gssapi: load ccache: %w", err)
		}
		conn.gssClient = gc // keep alive for SASL sign/seal

		// 4) SPN must be host-based ldap/<fqdn>
		servicePrincipal := fmt.Sprintf("ldap/%s", strings.ToLower(dcHostname))

		// 5) SASL GSSAPI bind (authzid usually empty)
		if err := l.GSSAPIBind(gc, servicePrincipal, ""); err != nil {
			_ = l.Close()
			_ = gc.Close()
			cleanup()
			return nil, fmt.Errorf("kerberos GSSAPI bind failed: %w", err)
		}

		cleanup()

		return conn, nil
	}

	// Non-Kerberos paths
	if len(hash) > 0 {
		// NTLM bind with hash (domain\user semantics vary by function; this uses go-ldap extension)
		if err := l.NTLMBindWithHash(domain, username, hash); err != nil {
			_ = l.Close()
			return nil, fmt.Errorf("NTLM bind failed: %w", err)
		}
		return conn, nil
	} else {
		// Simple bind with UPN (user@domain)
		if err := l.Bind(username+"@"+domain, password); err != nil {
			_ = l.Close()
			return nil, fmt.Errorf("simple bind failed: %w", err)
		}
		return conn, nil
	}
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

// writeMinimalKrb5Conf creates a tiny krb5.conf pointing to the given AD realm and KDC (dcHostname).
// This avoids any dependency on system krb5.conf / krb5.ini.
func writeMinimalKrb5Conf(realm, dcHostname string) (path string, cleanup func(), err error) {
	content := fmt.Sprintf(`
[libdefaults]
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
`, realm, realm, dcHostname, strings.ToLower(realm), realm, strings.ToLower(realm), realm)

	dir := os.TempDir()
	file := filepath.Join(dir, fmt.Sprintf("krb5_%d.conf", time.Now().UnixNano()))
	if err := os.WriteFile(file, []byte(strings.TrimSpace(content)+"\n"), 0600); err != nil {
		return "", nil, err
	}
	return file, func() { _ = os.Remove(file) }, nil
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
		[]string{},
		nil,
	)
	sr, err := conn.connection.SearchWithPaging(searchRequest, math.MaxInt32)
	if err != nil {
		return nil, err
	}
	return sr, nil
}
