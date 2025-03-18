package scanner

import (
	"bufio"
	"errors"
	"github.com/vflame6/sharefinder/utils"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

type Scanner struct {
	Options *Options
	Output  string
	Threads int
	Timeout time.Duration
	Exclude []string
	Stop    chan bool
}

func NewScanner(options *Options, output string, threads int, timeout time.Duration) *Scanner {
	return &Scanner{
		Options: options,
		Output:  output,
		Threads: threads,
		Timeout: timeout,
		Stop:    make(chan bool),
	}
}

func (s *Scanner) ParseTargets(target string) error {
	var targets []string
	if _, err := os.Stat(target); errors.Is(err, os.ErrNotExist) {
		// target file does not exist
		// try to parse as IP/CIDR
		targets, err = utils.ParseIPOrCIDR(target)
		if err != nil {
			return err
		}
		for _, t := range targets {
			s.Options.Target <- t
		}
		close(s.Options.Target)
		return nil
	}
	log.Printf("Using targets from %s", target)
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

		targets, err = utils.ParseIPOrCIDR(line)
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
	log.Println("Starting auth enumeration")
	for i := 0; i < s.Threads; i++ {
		wg.Add(1)
		go authThread(s.Stop, s.Options, wg)
	}
}

func (s *Scanner) Shutdown() {
	for i := 0; i < s.Threads; i++ {
		s.Stop <- true
	}
	close(s.Stop)
}
