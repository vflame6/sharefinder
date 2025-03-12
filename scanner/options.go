package scanner

import (
	"net"
)

type Options struct {
	Target           string
	Username         string
	Password         string
	Domain           string
	Search           string
	LocalAuth        bool
	List             bool
	DomainController net.IP
}

func NewOptions(target, username, password, domain, search string, localAuth, list bool, domainController net.IP) *Options {
	return &Options{
		Target:           target,
		Username:         username,
		Password:         password,
		Domain:           domain,
		Search:           search,
		LocalAuth:        localAuth,
		List:             list,
		DomainController: domainController,
	}
}
