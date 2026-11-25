package scanner

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// silentScanner returns a scanner whose targets all point at a listener that
// accepts TCP and never answers, so every worker blocks in SMB negotiation.
func silentScanner(t *testing.T, threads int, ioTimeout time.Duration) *Scanner {
	t.Helper()
	addr := silentListener(t)
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(portStr)
	d, err := NewDialer("", time.Second, ioTimeout)
	if err != nil {
		t.Fatal(err)
	}
	opts := &Options{
		Dialer:      d,
		IOTimeout:   ioTimeout,
		NullSession: true,
		SmbPort:     port,
		Timeout:     time.Second,
		Writer:      NewOutputWriter(),
	}
	return NewScanner(opts, nil, time.Now(), threads)
}

func TestRun_CancelReturnsPromptly(t *testing.T) {
	s := silentScanner(t, 4, 30*time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(300*time.Millisecond, cancel)

	produce := func(ctx context.Context, out chan<- DNHost) error {
		for i := 0; i < 20; i++ {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case out <- DNHost{IP: net.ParseIP("127.0.0.1")}:
			}
		}
		return nil
	}

	start := time.Now()
	err := s.Run(ctx, produce)
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("Run returned after %v, want under 2s", elapsed)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error = %v, want context.Canceled", err)
	}
}

func TestRun_ProducerStopsOnCancel(t *testing.T) {
	s := silentScanner(t, 2, 30*time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)

	produce := func(ctx context.Context, out chan<- DNHost) error {
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case out <- DNHost{IP: net.ParseIP("127.0.0.1")}:
			}
		}
	}

	done := make(chan error, 1)
	go func() { done <- s.Run(ctx, produce) }()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run error = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return within 2s of cancellation with an endless producer")
	}
}

func TestRun_ProducerErrorStopsRun(t *testing.T) {
	s := silentScanner(t, 2, 30*time.Second)
	want := errors.New("bad target")
	produce := func(ctx context.Context, out chan<- DNHost) error {
		select {
		case <-ctx.Done():
		case out <- DNHost{IP: net.ParseIP("127.0.0.1")}:
		}
		return want
	}

	start := time.Now()
	err := s.Run(context.Background(), produce)
	if !errors.Is(err, want) {
		t.Fatalf("Run error = %v, want %v", err, want)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("Run returned after %v, want under 2s", elapsed)
	}
}

// captureStdout returns what fn printed to os.Stdout.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = orig }()

	fn()

	_ = w.Close()
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	return buf.String()
}

func TestCloseOutputter_Idempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.xml")
	writer := NewOutputWriter()
	f, err := writer.CreateFile(path, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteXMLHeader("test", []string{"null", "10.0.0.1"}, time.Now(), f); err != nil {
		t.Fatal(err)
	}
	s := NewScanner(&Options{FileXML: f, OutputXMLFileName: path, Writer: writer}, nil, time.Now(), 1)

	s.CloseOutputter()
	if out := captureStdout(t, s.CloseOutputter); out != "" {
		t.Fatalf("second CloseOutputter printed %q, want nothing", out)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(data), "</SharefinderRun>"); n != 1 {
		t.Fatalf("found %d closing tags, want 1", n)
	}
	if _, err := ParseSharefinderRun(data); err != nil {
		t.Fatalf("XML does not parse: %v", err)
	}
}

func TestCloseOutputter_DefaultsTimeEnd(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.xml")
	writer := NewOutputWriter()
	f, err := writer.CreateFile(path, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteXMLHeader("test", nil, time.Now(), f); err != nil {
		t.Fatal(err)
	}
	s := NewScanner(&Options{FileXML: f, OutputXMLFileName: path, Writer: writer}, nil, time.Now(), 1)

	s.CloseOutputter()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	run, err := ParseSharefinderRun(data)
	if err != nil {
		t.Fatal(err)
	}
	if run.TimeEnd.Time.IsZero() {
		t.Fatal("interrupted runs must still record an end time")
	}
}
