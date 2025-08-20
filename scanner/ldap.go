package scanner

import (
	"crypto/tls"
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"github.com/vflame6/sharefinder/logger"
	"golang.org/x/net/proxy"
	"math"
	"net"
	"strings"
	"time"
)

type LDAPConnection struct {
	connection *ldap.Conn
}

func GetBaseDN(domain string) string {
	result := "dc="
	dns := strings.Split(domain, ".")
	result += strings.Join(dns, ",dc=")
	return result
}

func NewLDAPConnection(host net.IP, username, password, domain string, timeout time.Duration, proxyOption bool, proxyDialer proxy.Dialer) (*LDAPConnection, error) {
	var l *ldap.Conn
	var err error

	dialLDAPS := fmt.Sprintf("%s:636", host.String())
	dialLDAP := fmt.Sprintf("%s:389", host.String())

	var dialer proxy.Dialer
	if proxyOption {
		dialer = proxyDialer
	} else {
		dialer = &net.Dialer{Timeout: timeout}
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}

	// try to connect over LDAPS
	var isLDAPS bool
	conn, err := dialer.Dial("tcp", dialLDAPS)
	if err == nil {
		// Wrap raw TCP connection in TLS with our config
		tlsConn := tls.Client(conn, tlsConfig)

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

		conn, err = dialer.Dial("tcp", dialLDAP)
		if err != nil {
			return nil, err
		}
		l = ldap.NewConn(conn, false)
		l.Start()
		err = l.StartTLS(tlsConfig)

		// if all of that failed go plain LDAP
		if err != nil {
			logger.Warnf("Failed to set up STARTTLS on %s, trying plain LDAP", dialLDAP)
			conn, err = dialer.Dial("tcp", dialLDAP)
			if err != nil {
				return nil, err
			}
			l = ldap.NewConn(conn, false)
			l.Start()
		}
	}

	// username in format user@example.com
	err = l.Bind(username+"@"+domain, password)
	if err != nil {
		return nil, err
	}
	return &LDAPConnection{
		connection: l,
	}, nil
}

func (conn *LDAPConnection) Close() {
	_ = conn.connection.Close()
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
