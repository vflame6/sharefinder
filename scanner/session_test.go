package scanner

import (
	"context"
	"errors"
	"testing"
)

// fakeSession stands in for a go-smb connection after negotiation.
type fakeSession struct {
	setupErr    error
	guest, null bool
	setups      int
}

func (f *fakeSession) SessionSetup() error  { f.setups++; return f.setupErr }
func (f *fakeSession) IsGuestSession() bool { return f.guest }
func (f *fakeSession) IsNullSession() bool  { return f.null }

func TestEstablishSession(t *testing.T) {
	setupErr := errors.New("negotiation broke")
	tests := []struct {
		name     string
		session  *fakeSession
		mode     AuthMode
		wantType string
		wantErr  error
	}{
		{name: "user credentials", session: &fakeSession{}, mode: AuthUser, wantType: "user"},
		{name: "user credentials mapped to guest", session: &fakeSession{guest: true}, mode: AuthUser, wantErr: ErrGuestFallback},
		{name: "guest probe", session: &fakeSession{guest: true}, mode: AuthGuest, wantType: "guest"},
		{name: "guest probe accepted as user", session: &fakeSession{}, mode: AuthGuest, wantType: "user"},
		{name: "null session", session: &fakeSession{null: true}, mode: AuthNull, wantType: "null"},
		{name: "null session mapped to guest", session: &fakeSession{null: true, guest: true}, mode: AuthNull, wantType: "guest"},
		{name: "setup error", session: &fakeSession{setupErr: setupErr}, mode: AuthNull, wantErr: setupErr},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			guard := NewAuthGuard(5)
			got, err := establishSession(context.Background(), tt.session, tt.mode, guard, "10.0.0.5")
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("error = %v, want %v", err, tt.wantErr)
				}
				var stageErr *StageError
				if !errors.As(err, &stageErr) || stageErr.Stage != StageAuth || stageErr.Host != "10.0.0.5" {
					t.Fatalf("error must be an authentication StageError for the host, got %#v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.wantType {
				t.Fatalf("session type = %q, want %q", got, tt.wantType)
			}
		})
	}
}

func TestEstablishSession_GuestFallbackCountsAsRejection(t *testing.T) {
	guard := NewAuthGuard(1)
	_, err := establishSession(context.Background(), &fakeSession{guest: true}, AuthUser, guard, "10.0.0.5")
	if !errors.Is(err, ErrGuestFallback) {
		t.Fatalf("error = %v, want ErrGuestFallback", err)
	}
	if guard.Failures() != 1 || guard.Err() == nil {
		t.Fatalf("a guest-mapped logon must count as rejected credentials (failures %d, tripped %v)", guard.Failures(), guard.Err())
	}
}

func TestEstablishSession_GuestProbeIsNotGuarded(t *testing.T) {
	guard := NewAuthGuard(1)
	session := &fakeSession{setupErr: ErrGuestFallback}
	_, _ = establishSession(context.Background(), session, AuthGuest, guard, "10.0.0.5")
	if guard.Failures() != 0 {
		t.Fatal("guest and null probes must not count towards --max-auth-failures")
	}
}
