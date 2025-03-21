package scanner

import (
	"bufio"
	"errors"
	"os"
	"strings"
	"sync"
)

type Scanner struct {
	Options *Options
	Threads int
	Exclude []string
	Stop    chan bool
}

func NewScanner(options *Options, threads int) *Scanner {
	return &Scanner{
		Options: options,
		Threads: threads,
		Stop:    make(chan bool),
	}
}

func (s *Scanner) ParseTargets(target string) error {
	var targets []string
	if _, err := os.Stat(target); errors.Is(err, os.ErrNotExist) {
		// target file does not exist
		// try to parse as IP/CIDR
		targets, err = ParseIPOrCIDR(target)
		if err != nil {
			return err
		}
		for _, t := range targets {
			s.Options.Target <- t
		}
		close(s.Options.Target)
		return nil
	}
	file, err := os.Open(target)
	if err != nil {
		return err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		// skip empty line
		line := strings.TrimSpace(scanner.Text())
		if len(line) == 0 {
			continue
		}

		targets, err = ParseIPOrCIDR(line)
		if err != nil {
			return err
		}
		for _, t := range targets {
			s.Options.Target <- t
		}
	}
	close(s.Options.Target)
	return nil
}

//func (s *Scanner) RunAnonEnumeration() error {
//
//	return nil
//}

func (s *Scanner) RunAuthEnumeration(wg *sync.WaitGroup) {
	for i := 0; i < s.Threads; i++ {
		wg.Add(1)
		go authThread(s.Stop, s.Options, wg)
	}
}

//func (s *Scanner) RunHuntEnumeration() {
//
//}

func (s *Scanner) Shutdown() {
	for i := 0; i < s.Threads; i++ {
		s.Stop <- true
	}
	close(s.Stop)
}
