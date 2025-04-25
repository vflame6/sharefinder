package scanner

import (
	"crypto/tls"
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"log"
	"math"
	"net"
	"strings"
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

func NewLDAPConnection(host net.IP, username, password, domain string) (*LDAPConnection, error) {
	dialLDAPS := fmt.Sprintf("ldaps://%s:636", host.String())
	l, err := ldap.DialURL(dialLDAPS, ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true}))
	if err != nil {
		// if LDAPS is failed try ldap
		log.Printf("Failed to connect to LDAPS on %s, trying LDAP", host)

		dialLDAP := fmt.Sprintf("ldap://%s:389", host.String())
		l, err = ldap.DialURL(dialLDAP)
		if err != nil {
			return nil, err
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
