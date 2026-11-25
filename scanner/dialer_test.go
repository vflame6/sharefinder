package scanner

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

// silentListener accepts TCP connections and never writes to them. It returns
// the listener address; connections and the listener close on test cleanup.
func silentListener(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var conns []net.Conn
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
	})
	return ln.Addr().String()
}

func TestDialer_ReadTimesOutOnSilentPeer(t *testing.T) {
	addr := silentListener(t)
	d, err := NewDialer("", time.Second, 200*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := d.DialContext(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	start := time.Now()
	_, err = conn.Read(make([]byte, 1))
	if err == nil {
		t.Fatal("expected a timeout error from a silent peer")
	}
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("expected a timeout error, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("read returned after %v, want under 1s", elapsed)
	}
}

func TestDialer_ActivityRearmsDeadline(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		for i := 0; i < 5; i++ {
			time.Sleep(100 * time.Millisecond)
			if _, err := c.Write([]byte{byte(i)}); err != nil {
				return
			}
		}
		time.Sleep(time.Second)
	}()

	d, err := NewDialer("", time.Second, 300*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := d.DialContext(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	buf := make([]byte, 1)
	for i := 0; i < 5; i++ {
		if _, err := conn.Read(buf); err != nil {
			t.Fatalf("read %d failed: %v", i, err)
		}
	}
}

func TestDialer_CloseAllUnblocksAndRefuses(t *testing.T) {
	addr := silentListener(t)
	d, err := NewDialer("", time.Second, 0)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := d.DialContext(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	readErr := make(chan error, 1)
	go func() {
		_, err := conn.Read(make([]byte, 1))
		readErr <- err
	}()

	time.Sleep(100 * time.Millisecond)
	d.CloseAll()

	select {
	case err := <-readErr:
		if err == nil {
			t.Fatal("expected an error from a read on a closed connection")
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("blocked read did not return within 500ms of CloseAll")
	}

	if _, err := d.DialContext(context.Background(), "tcp", addr); !errors.Is(err, ErrDialerClosed) {
		t.Fatalf("expected ErrDialerClosed after CloseAll, got %v", err)
	}
}

func TestDialer_DialTrackedHasNoIODeadline(t *testing.T) {
	addr := silentListener(t)
	d, err := NewDialer("", time.Second, 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := d.DialTracked(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	readErr := make(chan error, 1)
	go func() {
		_, err := conn.Read(make([]byte, 1))
		readErr <- err
	}()
	select {
	case err := <-readErr:
		t.Fatalf("DialTracked connection read returned early: %v", err)
	case <-time.After(400 * time.Millisecond):
	}
	d.CloseAll()
	select {
	case <-readErr:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("CloseAll did not unblock a DialTracked connection")
	}
}

func TestNormalizeHostPort(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"10.0.0.1:445", "10.0.0.1:445"},
		{"::1:445", "[::1]:445"},
		{"[::1]:445", "[::1]:445"},
		{"fs01.corp.local:445", "fs01.corp.local:445"},
		{"fe80::1%en0:445", "[fe80::1%en0]:445"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := normalizeHostPort(tt.in); got != tt.want {
				t.Fatalf("normalizeHostPort(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
