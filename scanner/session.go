package scanner

import (
	"context"
	"errors"
	"strings"

	"github.com/jfjallid/go-smb/smb"
)

// Session types reported on the host line and in the outputs.
const (
	SessionUser  = "user"
	SessionGuest = "guest"
	SessionNull  = "null"
)

// sessionSetupper is the part of a negotiated go-smb connection that logs on.
type sessionSetupper interface {
	SessionSetup() error
	IsGuestSession() bool
	IsNullSession() bool
	// ServerDomains returns the NetBIOS and DNS domain the server announced
	// in its NTLM challenge; empty without NTLM.
	ServerDomains() []string
}

// accountScope tells which hosts validate the credential's account.
type accountScope struct {
	Domain    string // the credential's domain, NetBIOS or DNS form
	LocalAuth bool   // --local-auth: every host has its own accounts
}

// foreignHost reports whether a host that announced serverDomains does not
// validate the credential's account. Without an announced domain (Kerberos)
// the host is assumed to be in the domain.
func (a accountScope) foreignHost(serverDomains []string) bool {
	if a.LocalAuth {
		return true
	}
	if a.Domain == "" {
		return false
	}
	announced := false
	for _, d := range serverDomains {
		if d == "" {
			continue
		}
		announced = true
		if strings.EqualFold(d, a.Domain) {
			return false
		}
		// CORP given, only corp.local announced (or the reverse)
		if first, _, _ := strings.Cut(d, "."); strings.EqualFold(first, a.Domain) {
			return false
		}
		if first, _, _ := strings.Cut(a.Domain, "."); strings.EqualFold(first, d) {
			return false
		}
	}
	return announced
}

// establishSession logs on and returns the session type the server granted.
//
// With real credentials (AuthUser) the logon runs under guard, and a session
// the server mapped to its Guest account counts as rejected credentials: the
// findings would otherwise carry the wrong identity. A rejection by a host
// outside the credential's scope is marked host-level, so it stops the scan
// only while no logon has succeeded yet. Errors are StageErrors for host.
func establishSession(ctx context.Context, s sessionSetupper, mode AuthMode, guard *AuthGuard, host string, scope accountScope) (string, error) {
	rejected := func(err error) error {
		var stageErr error = &StageError{Stage: StageAuth, Host: host, Err: err}
		if IsCredentialRejection(err) && scope.foreignHost(s.ServerDomains()) {
			stageErr = &hostRejection{err: stageErr}
		}
		return stageErr
	}
	logon := func() error {
		if err := s.SessionSetup(); err != nil {
			var stageErr *StageError
			if errors.As(err, &stageErr) {
				return err
			}
			return rejected(err)
		}
		if mode == AuthUser && s.IsGuestSession() {
			return rejected(ErrGuestFallback)
		}
		return nil
	}

	var err error
	if mode == AuthUser && guard != nil {
		err = guard.Do(ctx, logon)
	} else {
		err = logon()
	}
	if err != nil {
		var stageErr *StageError
		if !errors.As(err, &stageErr) {
			err = &StageError{Stage: StageAuth, Host: host, Err: err}
		}
		return "", err
	}
	return sessionTypeOf(s), nil
}

// smbSession adapts a go-smb connection to sessionSetupper.
type smbSession struct{ *smb.Connection }

func (s smbSession) ServerDomains() []string {
	info := s.GetTargetInfo()
	if info == nil {
		return nil
	}
	return []string{info.NBDomainName, info.DnsDomainName}
}

// sessionTypeOf names the session: the server's guest verdict wins over a
// requested null session.
func sessionTypeOf(s sessionSetupper) string {
	switch {
	case s.IsGuestSession():
		return SessionGuest
	case s.IsNullSession():
		return SessionNull
	default:
		return SessionUser
	}
}
