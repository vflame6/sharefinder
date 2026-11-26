package scanner

import (
	"context"
	"errors"
	"testing"
	"time"
)

// fakeSession stands in for a go-smb connection after negotiation.
type fakeSession struct {
	setupErr    error
	guest, null bool
	domains     []string
	setups      int
}

func (f *fakeSession) SessionSetup() error     { f.setups++; return f.setupErr }
func (f *fakeSession) IsGuestSession() bool    { return f.guest }
func (f *fakeSession) IsNullSession() bool     { return f.null }
func (f *fakeSession) ServerDomains() []string { return f.domains }

// fakeConn is a negotiated connection that records Close.
type fakeConn struct {
	*fakeSession
	closed bool
}

func (f *fakeConn) Close() { f.closed = true }

func TestFreshSession_RenegotiatesAfterLongWait(t *testing.T) {
	stale := &fakeConn{fakeSession: &fakeSession{setupErr: errors.New("Remote connection has closed!")}}
	fresh := &fakeConn{fakeSession: &fakeSession{}}
	redials := 0
	f := &freshSession{
		conn:    stale,
		ready:   time.Now().Add(-10 * time.Second), // waited at the guard
		maxIdle: time.Second,
		redial:  func() (sessionConn, error) { redials++; return fresh, nil },
		host:    "10.0.0.5",
	}
	if err := f.SessionSetup(); err != nil {
		t.Fatalf("SessionSetup after a long wait = %v, want a logon on a fresh connection", err)
	}
	if redials != 1 || !stale.closed || stale.setups != 0 || fresh.setups != 1 {
		t.Fatalf("redials %d, stale closed %v, stale setups %d, fresh setups %d", redials, stale.closed, stale.setups, fresh.setups)
	}
}

func TestFreshSession_KeepsRecentConnection(t *testing.T) {
	conn := &fakeConn{fakeSession: &fakeSession{}}
	f := &freshSession{conn: conn, ready: time.Now(), maxIdle: time.Minute, host: "10.0.0.5",
		redial: func() (sessionConn, error) { t.Fatal("must not redial a fresh connection"); return nil, nil }}
	if err := f.SessionSetup(); err != nil || conn.setups != 1 {
		t.Fatalf("SessionSetup = %v, setups %d", err, conn.setups)
	}
}

func TestFreshSession_RedialFailureIsConnectionError(t *testing.T) {
	f := &freshSession{
		conn:    &fakeConn{fakeSession: &fakeSession{}},
		ready:   time.Now().Add(-time.Hour),
		maxIdle: time.Second,
		redial:  func() (sessionConn, error) { return nil, errors.New("connection refused") },
		host:    "10.0.0.5",
	}
	err := f.SessionSetup()
	var stageErr *StageError
	if !errors.As(err, &stageErr) || stageErr.Stage != StageConnect {
		t.Fatalf("a failed re-dial is a connection error, got %#v", err)
	}
	if IsCredentialRejection(err) {
		t.Fatal("a failed re-dial says nothing about the credentials")
	}
}

func TestAccountScope_ForeignHost(t *testing.T) {
	tests := []struct {
		name    string
		scope   accountScope
		domains []string
		want    bool
	}{
		{"same NetBIOS domain", accountScope{Domain: "CORP"}, []string{"CORP", "corp.local"}, false},
		{"same DNS domain", accountScope{Domain: "corp.local"}, []string{"CORP", "corp.local"}, false},
		{"case-insensitive", accountScope{Domain: "corp"}, []string{"CORP", ""}, false},
		{"NetBIOS name given, only DNS name reported", accountScope{Domain: "CORP"}, []string{"", "corp.local"}, false},
		{"workgroup NAS", accountScope{Domain: "CORP"}, []string{"WORKGROUP", ""}, true},
		{"standalone host", accountScope{Domain: "corp.local"}, []string{"WS01", "ws01"}, true},
		{"no target info (Kerberos)", accountScope{Domain: "CORP"}, nil, false},
		{"local accounts", accountScope{LocalAuth: true}, []string{"CORP", "corp.local"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.scope.foreignHost(tt.domains); got != tt.want {
				t.Fatalf("foreignHost(%v) = %v, want %v", tt.domains, got, tt.want)
			}
		})
	}
}

func TestEstablishSession_ForeignRejectionIsHostLevel(t *testing.T) {
	session := &fakeSession{setupErr: logonFailure(), domains: []string{"WORKGROUP", ""}}
	_, err := establishSession(context.Background(), session, AuthUser, NewAuthGuard(5), "10.0.0.9", accountScope{Domain: "CORP"})
	var hr *hostRejection
	if !errors.As(err, &hr) {
		t.Fatalf("a rejection by a host outside the domain must be host-level, got %#v", err)
	}
	if !IsCredentialRejection(err) {
		t.Fatal("it is still a credential rejection for that host")
	}

	session = &fakeSession{setupErr: logonFailure(), domains: []string{"CORP", "corp.local"}}
	_, err = establishSession(context.Background(), session, AuthUser, NewAuthGuard(5), "10.0.0.5", accountScope{Domain: "CORP"})
	if errors.As(err, &hr) {
		t.Fatal("a rejection by a host in the credential's domain must count against the account")
	}
}

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
			got, err := establishSession(context.Background(), tt.session, tt.mode, guard, "10.0.0.5", accountScope{})
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
	_, err := establishSession(context.Background(), &fakeSession{guest: true}, AuthUser, guard, "10.0.0.5", accountScope{})
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
	_, _ = establishSession(context.Background(), session, AuthGuest, guard, "10.0.0.5", accountScope{})
	if guard.Failures() != 0 {
		t.Fatal("guest and null probes must not count towards --max-auth-failures")
	}
}
