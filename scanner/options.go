package scanner

import (
	"net"
)

type Options struct {
	Exclude          []string
	Target           chan string
	Username         string
	Password         string
	Domain           string
	List             bool
	Search           string
	LocalAuth        bool
	DomainController net.IP
}

func NewOptions(exclude []string, target chan string, username, password, domain, search string, localAuth, list bool, domainController net.IP) *Options {
	return &Options{
		Exclude:          exclude,
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
