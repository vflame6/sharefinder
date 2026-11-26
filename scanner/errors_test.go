package scanner

import (
	"errors"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/jfjallid/go-smb/smb"
)

func TestIsCredentialRejection(t *testing.T) {
	wrap := func(status uint32) error {
		return fmt.Errorf("session setup: %w", smb.StatusMap[status])
	}
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"logon failure", wrap(smb.StatusLogonFailure), true},
		{"account locked out", wrap(smb.StatusAccountLockedOut), true},
		{"account disabled", wrap(smb.StatusAccountDisabled), true},
		{"password expired", wrap(smb.StatusPasswordExpired), true},
		{"password must change", wrap(smb.StatusPasswordMustChange), true},
		{"account expired (unmapped in go-smb)", errors.New("Received unknown SMB Header status for SessionSetup response: 0xc0000193"), true},
		{"kerberos pre-auth failed", errors.New("KRB Error: (24) KDC_ERR_PREAUTH_FAILED Pre-authentication information was invalid"), true},
		{"kerberos client revoked", errors.New("KRB Error: (18) KDC_ERR_CLIENT_REVOKED Clients credentials have been revoked"), true},
		{"kerberos key expired", errors.New("KRB Error: (23) KDC_ERR_KEY_EXPIRED Password has expired"), true},
		{"guest fallback", ErrGuestFallback, true},
		{"wrapped in a stage error", &StageError{Stage: StageAuth, Host: "h", Err: wrap(smb.StatusLogonFailure)}, true},
		{"access denied", wrap(smb.StatusAccessDenied), false},
		{"bad network name", wrap(smb.StatusBadNetworkName), false},
		{"EOF", io.EOF, false},
		{"timeout", os.ErrDeadlineExceeded, false},
		{"nil", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsCredentialRejection(tt.err); got != tt.want {
				t.Fatalf("IsCredentialRejection(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestStageError(t *testing.T) {
	inner := smb.StatusMap[smb.StatusLogonFailure]
	err := &StageError{Stage: StageAuth, Host: "10.0.0.5", Err: inner}
	if got, want := err.Error(), "authentication failed on 10.0.0.5: Logon failed"; got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
	if !errors.Is(err, inner) {
		t.Fatal("StageError must unwrap to its cause")
	}
	if got := (&StageError{Stage: StageConnect, Host: "h", Err: io.EOF}).Error(); got != "connection failed on h: EOF" {
		t.Fatalf("connect stage message = %q", got)
	}
	if got := (&StageError{Stage: StageEnumerate, Host: "h", Err: io.EOF}).Error(); got != "enumeration failed on h: EOF" {
		t.Fatalf("enumerate stage message = %q", got)
	}
}
