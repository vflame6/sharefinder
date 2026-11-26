package scanner

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

// AuthGuard keeps a scan with wrong credentials from locking accounts out.
//
// Until one logon has succeeded, logons are sent one at a time, so a wrong
// password reaches a single target instead of every target the workers hold.
// After a success they run in parallel. Every rejected logon is counted; once
// the count reaches the limit, the guard trips: logons that have not been sent
// fail with ErrAuthLimitReached and Done is closed so the scan can stop.
type AuthGuard struct {
	max int

	mu       sync.Mutex
	verified bool          // a logon succeeded: no more serialisation
	probing  bool          // a logon is in flight before verification
	failures int           // rejected logons sent
	tripped  error         // set once failures reach max
	changed  chan struct{} // closed and replaced on every state change
	done     chan struct{} // closed when the guard trips
}

// NewAuthGuard returns a guard that trips after maxFailures rejected logons.
// maxFailures <= 0 disables it: logons are neither serialised nor limited.
func NewAuthGuard(maxFailures int) *AuthGuard {
	return &AuthGuard{
		max:     maxFailures,
		changed: make(chan struct{}),
		done:    make(chan struct{}),
	}
}

// Do runs logon under the guard and returns its error, or an error wrapping
// ErrAuthLimitReached when the guard has tripped before logon was sent, or the
// context's cause when ctx ends while waiting for the probe logon.
func (g *AuthGuard) Do(ctx context.Context, logon func() error) error {
	if g.max <= 0 {
		err := logon()
		g.record(false, err)
		return err
	}
	for {
		g.mu.Lock()
		if g.tripped != nil {
			err := g.tripped
			g.mu.Unlock()
			return err
		}
		if g.verified || !g.probing {
			probe := !g.verified
			if probe {
				g.probing = true
			}
			g.mu.Unlock()

			err := logon()
			g.record(probe, err)
			return err
		}
		wait := g.changed
		g.mu.Unlock()

		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case <-wait:
		}
	}
}

// record updates the guard with the outcome of one logon.
func (g *AuthGuard) record(probe bool, err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if probe {
		g.probing = false
	}
	switch {
	case err == nil:
		g.verified = true
	case IsCredentialRejection(err):
		var hostOnly *hostRejection
		if g.verified && errors.As(err, &hostOnly) {
			// the credentials work; this host just does not know the account
			break
		}
		g.failures++
		if g.max > 0 && g.failures >= g.max && g.tripped == nil {
			g.tripped = &authLimitError{failures: g.failures, max: g.max, last: err}
			close(g.done)
		}
	}
	close(g.changed)
	g.changed = make(chan struct{})
}

// Done is closed when the guard trips.
// Max is the number of rejected logons that trips the guard; 0 for none.
func (g *AuthGuard) Max() int { return g.max }

func (g *AuthGuard) Done() <-chan struct{} { return g.done }

// Err returns the error the guard tripped with, or nil.
func (g *AuthGuard) Err() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.tripped
}

// Failures returns the number of rejected logons sent so far.
func (g *AuthGuard) Failures() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.failures
}

// authLimitError explains why the scan stopped.
type authLimitError struct {
	failures, max int
	last          error
}

func (e *authLimitError) Error() string {
	host, reason := "a target", e.last.Error()
	var se *StageError
	if errors.As(e.last, &se) {
		host, reason = se.Host, se.Err.Error()
	}
	return fmt.Sprintf("stopping: credentials rejected by %s (%s); %d failed logon(s) sent, --max-auth-failures=%d", host, reason, e.failures, e.max)
}

func (e *authLimitError) Unwrap() []error { return []error{ErrAuthLimitReached, e.last} }
