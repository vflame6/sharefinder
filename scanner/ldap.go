package scanner

import (
	"crypto/tls"
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"github.com/go-ldap/ldap/v3/gssapi"
	"github.com/vflame6/sharefinder/logger"
	"golang.org/x/net/proxy"
	"log"
	"math"
	"net"
	"os"
	"runtime"
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

func NewLDAPConnection(host net.IP, username, password string, hash []byte, domain string, timeout time.Duration, proxyDialer proxy.Dialer, kerberos bool, dcHostname string) (*LDAPConnection, error) {
	var l *ldap.Conn
	var err error

	hashes := string(hash)

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

	if kerberos {
		// Build GSSAPI client from ccache and krb5.conf, then SASL/GSSAPI bind.
		// SPN must be host-based: ldap/<fqdn>; realm comes from krb5.conf/ccache.
		spnHost := dcHostname
		if spnHost == "" {
			// using an IP in SPN usually fails; warn and attempt anyway
			spnHost = host.String()
			log.Printf("warning: dcHostname is empty; using %q for SPN which may fail with Kerberos", spnHost)
		}
		servicePrincipal := fmt.Sprintf("ldap/%s", strings.ToLower(spnHost))

		ccachePath, err := ccachePathFromEnv()
		if err != nil {
			_ = l.Close()
			return nil, err
		}
		krbConfPath := krb5ConfPathFromEnv()

		gc, err := gssapi.NewClientFromCCache(ccachePath, krbConfPath /* optional client.Settings... */)
		if err != nil {
			_ = l.Close()
			return nil, fmt.Errorf("gssapi: load ccache: %w", err)
		}
		// Keep the client alive for the lifetime of the LDAP connection (sign/seal).
		conn.gssClient = gc

		// authzid: usually empty (server derives it from the ticket)
		if err := l.GSSAPIBind(gc, servicePrincipal, ""); err != nil {
			_ = l.Close()
			_ = gc.Close()
			return nil, fmt.Errorf("kerberos GSSAPI bind failed: %w", err)
		}

		return conn, nil
	}

	// Non-Kerberos paths
	if len(hashes) > 0 {
		// NTLM bind with hash (domain\user semantics vary by function; this uses go-ldap extension)
		if err := l.NTLMBindWithHash(domain, username, hashes); err != nil {
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

// Close closes the LDAP connection and the GSSAPI context if used.
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

// ---- helpers ----

// ccachePathFromEnv reads KRB5CCNAME and normalizes FILE: URIs to a filesystem path.
func ccachePathFromEnv() (string, error) {
	cc := os.Getenv("KRB5CCNAME")
	if cc == "" {
		return "", fmt.Errorf("KRB5CCNAME not set; a Kerberos ccache (TGT) is required for GSSAPI bind")
	}
	// Handle FILE:/path form; other schemes (DIR:, KEYRING:, API:) are not supported by this helper.
	const filePrefix = "FILE:"
	if strings.HasPrefix(cc, filePrefix) {
		return strings.TrimPrefix(cc, filePrefix), nil
	}
	return cc, nil
}

// krb5ConfPathFromEnv resolves a krb5.conf path from KRB5_CONFIG or common OS defaults.
func krb5ConfPathFromEnv() string {
	if p := os.Getenv("KRB5_CONFIG"); p != "" {
		return p
	}
	switch runtime.GOOS {
	case "windows":
		// Typical locations for MIT Kerberos for Windows
		if _, err := os.Stat(`C:\Windows\krb5.ini`); err == nil {
			return `C:\Windows\krb5.ini`
		}
		return `C:\ProgramData\MIT\Kerberos5\krb5.ini`
	case "darwin":
		// macOS uses profile files; /etc/krb5.conf is commonly present
		return "/etc/krb5.conf"
	default:
		return "/etc/krb5.conf"
	}
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
