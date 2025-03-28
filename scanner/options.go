package scanner

import (
	"net"
	"os"
	"time"
)

type Options struct {
	Output           bool
	Writer           *OutputWriter
	File             *os.File
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

func NewOptions(output bool, writer *OutputWriter, file *os.File, timeout time.Duration, exclude []string, target chan string, username, password, domain string, localAuth, list bool, domainController net.IP) *Options {
	return &Options{
		Output:           output,
		Writer:           writer,
		File:             file,
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
