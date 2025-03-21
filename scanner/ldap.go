package scanner

import (
	"crypto/tls"
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"log"
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
	dialURL := fmt.Sprintf("ldaps://%s:636", host.String())

	l, err := ldap.DialURL(dialURL, ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true}))
	if err != nil {
		log.Fatal(err)
	}

	err = l.Bind(username+"@"+domain, password)
	if err != nil {
		return nil, err
	}
	return &LDAPConnection{
		connection: l,
	}, nil
}

func (conn *LDAPConnection) Close() {
	conn.connection.Close()
}

func (conn *LDAPConnection) SearchComputers(baseDN string) (*ldap.SearchResult, error) {
	searchRequest := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(objectCategory=Computer)", []string{}, nil,
	)
	sr, err := conn.connection.Search(searchRequest)
	if err != nil {
		return nil, err
	}
	return sr, nil
}
