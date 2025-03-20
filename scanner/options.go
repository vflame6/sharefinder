package scanner

import (
	"net"
	"time"
)

type Options struct {
	Output           string
	Timeout          time.Duration
	Exclude          []string
	Target           chan string
	Username         string
	Password         string
	Domain           string
	List             bool
	RecurseList      bool
	LocalAuth        bool
	DomainController net.IP
}

func NewOptions(output string, timeout time.Duration, exclude []string, target chan string, username, password, domain string, localAuth, list bool, domainController net.IP) *Options {
	return &Options{
		Output:           output,
		Timeout:          timeout,
		Exclude:          exclude,
		Target:           target,
		Username:         username,
		Password:         password,
		Domain:           domain,
		LocalAuth:        localAuth,
		List:             list,
		DomainController: domainController,
	}
}
