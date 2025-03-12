package scanner

import "time"

type Scanner struct {
	options *Options
	Output  string
	Threads int
	Timeout time.Duration
}

func NewScanner(options *Options, output string, threads int, timeout time.Duration) *Scanner {
	return &Scanner{
		options: options,
		Output:  output,
		Threads: threads,
		Timeout: timeout,
	}
}

func (s *Scanner) RunAnonEnumeration() error {

	return nil
}
