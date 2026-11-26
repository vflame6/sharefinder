package scanner

import (
	"errors"
	"fmt"
	"strings"

	"github.com/jfjallid/go-smb/smb"
)

// AuthMode is the kind of identity a scan logs on with.
type AuthMode int

const (
	AuthUser  AuthMode = iota // real credentials: auth, hunt
	AuthGuest                 // a made-up user, expecting a guest session
	AuthNull                  // an anonymous (null) session
)

// Stage is the step of a host scan that failed.
type Stage int

const (
	StageConnect   Stage = iota // TCP connect and SMB negotiation
	StageAuth                   // session setup
	StageEnumerate              // share listing and checks
)

func (s Stage) String() string {
	switch s {
	case StageConnect:
		return "connection"
	case StageAuth:
		return "authentication"
	default:
		return "enumeration"
	}
}

// StageError records which stage of a host scan failed.
type StageError struct {
	Stage Stage
	Host  string
	Err   error
}

func (e *StageError) Error() string {
	return fmt.Sprintf("%s failed on %s: %v", e.Stage, e.Host, e.Err)
}

func (e *StageError) Unwrap() error { return e.Err }

// ErrGuestFallback reports a logon with real credentials that the server
// accepted only as its Guest account: the credentials were rejected.
var ErrGuestFallback = errors.New("server mapped the logon to the Guest account")

// ErrAuthLimitReached is wrapped by every error the AuthGuard returns once
// --max-auth-failures rejected logons have been sent.
var ErrAuthLimitReached = errors.New("authentication failure limit reached")

// hostRejection marks credentials refused by a host whose accounts are not
// the credential's own: a host outside the credential's domain, or any host
// with --local-auth. Once a logon has succeeded such a refusal says nothing
// about the account and does not count towards --max-auth-failures.
type hostRejection struct{ err error }

func (e *hostRejection) Error() string { return e.err.Error() }
func (e *hostRejection) Unwrap() error { return e.err }

// rejectionStatuses are the NTSTATUS codes go-smb maps to sentinel errors
// that mean the credentials were refused (and may count towards a lockout).
var rejectionStatuses = []uint32{
	smb.StatusLogonFailure,
	smb.StatusAccountLockedOut,
	smb.StatusAccountDisabled,
	smb.StatusPasswordExpired,
	smb.StatusPasswordMustChange,
}

// statusAccountExpired (STATUS_ACCOUNT_EXPIRED) has no sentinel in go-smb; it
// arrives as an *smb.NTStatusError carrying the raw status.
const statusAccountExpired uint32 = 0xc0000193

// rejectionMarkers match Kerberos KDC refusals, which gokrb5 reports as text.
var rejectionMarkers = []string{
	"kdc_err_preauth_failed",
	"kdc_err_client_revoked",
	"kdc_err_key_expired",
}

// IsCredentialRejection reports whether err means the server refused the
// credentials, as opposed to a network or protocol problem.
func IsCredentialRejection(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrGuestFallback) {
		return true
	}
	for _, status := range rejectionStatuses {
		if errors.Is(err, smb.StatusMap[status]) {
			return true
		}
	}
	var statusErr *smb.NTStatusError
	if errors.As(err, &statusErr) && statusErr.Status == statusAccountExpired {
		return true
	}
	msg := strings.ToLower(err.Error())
	for _, marker := range rejectionMarkers {
		if strings.Contains(msg, marker) {
			return true
		}
	}
	return false
}
