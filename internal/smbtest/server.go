// Package smbtest runs go-smb's SMB server inside tests: file-backed shares,
// one account, the guest and anonymous switches, and the srvsvc pipe that
// share enumeration needs. It is not Windows: ACLs are not enforced on
// write-access opens, so negative mask write checks need a real server.
package smbtest

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	srvsvcsrv "github.com/jfjallid/go-smb/dcerpc/mssrvs/server"
	dcserver "github.com/jfjallid/go-smb/dcerpc/server"
	"github.com/jfjallid/go-smb/ntlmssp"
	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/server"
	"github.com/jfjallid/go-smb/smb/server/filevfs"
)

// Share is one disk share served from a temporary directory.
type Share struct {
	Name   string
	Remark string
	// Files maps a slash-separated path to its content; a path ending in "/"
	// creates a directory.
	Files map[string]string
	// Writable lets the configured user write; GuestWritable and
	// AnonymousWritable do the same for guest and null sessions.
	Writable, GuestWritable, AnonymousWritable bool
}

// Config describes the server.
type Config struct {
	Shares         []Share
	User, Password string
	// AllowGuest maps failed logons with a user name to a guest session;
	// AllowAnonymous accepts null sessions.
	AllowGuest, AllowAnonymous bool
	SigningRequired            bool
	// Latency delays every request, to keep long operations in flight.
	Latency time.Duration
}

// Server is a running in-process SMB server.
type Server struct {
	port   int
	roots  map[string]string
	logons atomic.Int64
}

// Start serves cfg on 127.0.0.1 until the test ends.
func Start(t testing.TB, cfg Config) *Server {
	t.Helper()
	s := &Server{roots: make(map[string]string)}

	accounts := map[string]*server.Account{}
	if cfg.User != "" {
		accounts[cfg.User] = &server.Account{NTHash: ntlmssp.Ntowfv1(cfg.Password)}
	}
	srv := &server.Server{Config: &server.ServerConfig{
		NetBIOSName:   "SMBTEST",
		NetBIOSDomain: "WORKGROUP",
		// no Domain: accept the account whatever domain the client names,
		// as a standalone server does for local accounts
		Authenticator:   &server.MapAuthenticator{Accounts: accounts},
		AllowGuest:      cfg.AllowGuest,
		AllowAnonymous:  cfg.AllowAnonymous,
		SigningRequired: cfg.SigningRequired,
		OnSessionSetup: func(_ *server.Conn, _ *server.Session, _ []byte, stage server.SessionSetupStage) (*server.Status, error) {
			if stage == server.SessionSetupStageAuthenticate {
				s.logons.Add(1)
			}
			return nil, nil
		},
	}}
	if cfg.Latency > 0 {
		srv.Config.OnRawRequest = func(*server.Conn, []byte) (bool, error) {
			time.Sleep(cfg.Latency)
			return false, nil
		}
	}

	for _, share := range cfg.Shares {
		root := t.TempDir()
		writeFiles(t, root, share.Files)
		vfs, err := filevfs.New(filevfs.Options{Root: root})
		if err != nil {
			t.Fatalf("smbtest: share %s: %v", share.Name, err)
		}
		writers := map[string]bool{} // non-nil: only listed users may write
		if share.Writable && cfg.User != "" {
			writers[strings.ToLower(cfg.User)] = true
		}
		srv.RegisterShare(share.Name, server.Share{
			Type:              smb.ShareTypeDisk,
			Remark:            share.Remark,
			VFS:               vfs,
			WritableUsers:     writers,
			GuestWritable:     share.GuestWritable,
			AnonymousWritable: share.AnonymousWritable,
		})
		s.roots[share.Name] = root
	}

	srvsvc := &srvsvcsrv.Service{ServerName: "SMBTEST", Shares: srvsvcsrv.FromConfig(srv.Config)}
	srv.Config.PipeOpener = &server.MapPipeOpener{Pipes: map[string]func(*server.Session) (server.PipeBackend, error){
		"srvsvc": func(*server.Session) (server.PipeBackend, error) {
			return dcserver.NewPipeHandler("srvsvc", srvsvc), nil
		},
	}}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("smbtest: listen: %v", err)
	}
	served := make(chan struct{})
	go func() {
		defer close(served)
		_ = srv.Serve(l)
	}()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		<-served
	})
	s.port = l.Addr().(*net.TCPAddr).Port
	return s
}

// Port is the TCP port the server listens on.
func (s *Server) Port() int { return s.port }

// LogonAttempts counts authenticate-stage session setups the server received.
func (s *Server) LogonAttempts() int { return int(s.logons.Load()) }

// Root returns the directory backing a share.
func (s *Server) Root(share string) string { return s.roots[share] }

func writeFiles(t testing.TB, root string, files map[string]string) {
	t.Helper()
	for path, content := range files {
		full := filepath.Join(root, filepath.FromSlash(path))
		if strings.HasSuffix(path, "/") {
			if err := os.MkdirAll(full, 0o755); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// StartSilent accepts TCP connections and never answers. It returns the port.
func StartSilent(t testing.TB) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var conns []net.Conn
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		_ = l.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
	})
	return l.Addr().(*net.TCPAddr).Port
}
