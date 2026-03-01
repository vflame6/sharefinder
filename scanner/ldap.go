package scanner

import (
	"crypto/tls"
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"github.com/go-ldap/ldap/v3/gssapi"
	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/vflame6/sharefinder/logger"
	"golang.org/x/net/proxy"
	"math"
	"net"
	"os"
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
		if dcHostname == "" {
			_ = l.Close()
			return nil, fmt.Errorf("dcHostname is required for Kerberos (used as KDC and SPN host)")
		}

		// build krb5 config in memory — no temp files
		realm := strings.ToUpper(domain)
		krb5Conf, err := newKrb5Config(realm, host.String())
		if err != nil {
			_ = l.Close()
			return nil, fmt.Errorf("krb5 config: %w", err)
		}

		var gc *gssapi.Client

		// try ccache first (KRB5CCNAME), fall back to password-based TGT
		ccachePath, ccErr := ccachePathFromEnv()
		if ccErr == nil {
			ccache, err := credentials.LoadCCache(ccachePath)
			if err != nil {
				_ = l.Close()
				return nil, fmt.Errorf("gssapi: load ccache file: %w", err)
			}
			krbClient, err := client.NewFromCCache(ccache, krb5Conf)
			if err != nil {
				_ = l.Close()
				return nil, fmt.Errorf("gssapi: ccache client: %w", err)
			}
			gc = &gssapi.Client{Client: krbClient}
		} else if password != "" {
			krbClient := client.NewWithPassword(username, realm, password, krb5Conf)
			gc = &gssapi.Client{Client: krbClient}
		} else {
			_ = l.Close()
			return nil, fmt.Errorf("kerberos requires either KRB5CCNAME ccache or -p password")
		}
		conn.gssClient = gc

		// SPN must be host-based ldap/<fqdn>
		servicePrincipal := fmt.Sprintf("ldap/%s", strings.ToLower(dcHostname))

		// SASL GSSAPI bind
		if err := l.GSSAPIBind(gc, servicePrincipal, ""); err != nil {
			// GSSAPI bind failed — fall back to simple bind
			_ = gc.Close()
			conn.gssClient = nil
			logger.Warnf("Kerberos GSSAPI bind failed, falling back to simple bind for LDAP")
			if bindErr := l.Bind(username+"@"+domain, password); bindErr != nil {
				_ = l.Close()
				return nil, fmt.Errorf("LDAP bind failed: kerberos: %w, simple: %v", err, bindErr)
			}
		}

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
