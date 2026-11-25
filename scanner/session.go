package scanner

import "context"

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
}

// establishSession logs on and returns the session type the server granted.
//
// With real credentials (AuthUser) the logon runs under guard, and a session
// the server mapped to its Guest account counts as rejected credentials: the
// findings would otherwise carry the wrong identity. Errors are authentication
// StageErrors for host.
func establishSession(ctx context.Context, s sessionSetupper, mode AuthMode, guard *AuthGuard, host string) (string, error) {
	logon := func() error {
		if err := s.SessionSetup(); err != nil {
			return &StageError{Stage: StageAuth, Host: host, Err: err}
		}
		if mode == AuthUser && s.IsGuestSession() {
			return &StageError{Stage: StageAuth, Host: host, Err: ErrGuestFallback}
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
		if _, ok := err.(*StageError); !ok {
			err = &StageError{Stage: StageAuth, Host: host, Err: err}
		}
		return "", err
	}
	return sessionTypeOf(s), nil
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
