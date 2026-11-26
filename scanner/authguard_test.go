package scanner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jfjallid/go-smb/smb"
)

func logonFailure() error {
	return fmt.Errorf("session setup: %w", smb.StatusMap[smb.StatusLogonFailure])
}

// runConcurrently calls guard.Do from n goroutines and returns their errors.
func runConcurrently(n int, guard *AuthGuard, logon func() error) []error {
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = guard.Do(context.Background(), logon)
		}(i)
	}
	wg.Wait()
	return errs
}

func TestAuthGuard_WrongPasswordSixTargetsOneLogon(t *testing.T) {
	guard := NewAuthGuard(1)
	var logons atomic.Int32
	errs := runConcurrently(6, guard, func() error {
		logons.Add(1)
		time.Sleep(20 * time.Millisecond)
		return logonFailure()
	})

	if n := logons.Load(); n != 1 {
		t.Fatalf("%d logons sent with a wrong password, want exactly 1", n)
	}
	limited := 0
	for i, err := range errs {
		if err == nil {
			t.Fatalf("caller %d got no error", i)
		}
		if errors.Is(err, ErrAuthLimitReached) {
			limited++
		}
	}
	if limited != 5 {
		t.Fatalf("%d callers got ErrAuthLimitReached, want 5", limited)
	}
	if guard.Err() == nil || !errors.Is(guard.Err(), ErrAuthLimitReached) {
		t.Fatalf("guard must report the limit, got %v", guard.Err())
	}
	select {
	case <-guard.Done():
	default:
		t.Fatal("Done must be closed once the limit is reached")
	}
}

func TestAuthGuard_ParallelAfterFirstSuccess(t *testing.T) {
	guard := NewAuthGuard(1)
	var active, peak atomic.Int32
	errs := runConcurrently(10, guard, func() error {
		n := active.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
		active.Add(-1)
		return nil
	})
	for i, err := range errs {
		if err != nil {
			t.Fatalf("caller %d: %v", i, err)
		}
	}
	if peak.Load() < 2 {
		t.Fatalf("logons did not run in parallel after the first success (peak %d)", peak.Load())
	}
}

func TestAuthGuard_MaxThree(t *testing.T) {
	guard := NewAuthGuard(3)
	var logons atomic.Int32
	runConcurrently(8, guard, func() error {
		logons.Add(1)
		return logonFailure()
	})
	if n := logons.Load(); n != 3 {
		t.Fatalf("%d logons sent, want exactly 3", n)
	}
}

func TestAuthGuard_InconclusiveReleasesProbe(t *testing.T) {
	guard := NewAuthGuard(1)
	var calls atomic.Int32
	errs := runConcurrently(2, guard, func() error {
		if calls.Add(1) == 1 {
			time.Sleep(30 * time.Millisecond)
			return io.EOF // connection problem, says nothing about the password
		}
		return nil
	})
	if calls.Load() != 2 {
		t.Fatalf("the waiting caller must probe after an inconclusive error, got %d calls", calls.Load())
	}
	if guard.Failures() != 0 {
		t.Fatalf("an inconclusive error must not count as a failed logon, got %d", guard.Failures())
	}
	if errs[0] == nil && errs[1] == nil {
		t.Fatal("one caller must see io.EOF")
	}
}

func TestAuthGuard_CancelWhileWaiting(t *testing.T) {
	guard := NewAuthGuard(1)
	release := make(chan struct{})
	started := make(chan struct{})
	go func() {
		_ = guard.Do(context.Background(), func() error {
			close(started)
			<-release
			return nil
		})
	}()
	<-started
	defer close(release)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- guard.Do(ctx, func() error { return nil }) }()
	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("waiting caller returned %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("waiting caller did not return after cancellation")
	}
}

func TestAuthGuard_Disabled(t *testing.T) {
	guard := NewAuthGuard(0)
	var logons int
	for i := 0; i < 3; i++ {
		err := guard.Do(context.Background(), func() error {
			logons++
			return logonFailure()
		})
		if errors.Is(err, ErrAuthLimitReached) {
			t.Fatalf("a disabled guard must never trip: %v", err)
		}
	}
	if logons != 3 {
		t.Fatalf("%d logons sent, want 3", logons)
	}
}

func TestAuthGuard_HostRejectionAfterSuccessIsNotCounted(t *testing.T) {
	guard := NewAuthGuard(1)
	if err := guard.Do(context.Background(), func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	// a NAS outside the domain refuses the (valid) domain credentials
	err := guard.Do(context.Background(), func() error { return &hostRejection{err: logonFailure()} })
	if err == nil {
		t.Fatal("the host's rejection must still be returned")
	}
	if guard.Failures() != 0 || guard.Err() != nil {
		t.Fatalf("a host-level rejection after a successful logon must not stop the scan (failures %d, tripped %v)", guard.Failures(), guard.Err())
	}
}

func TestAuthGuard_HostRejectionBeforeSuccessCounts(t *testing.T) {
	guard := NewAuthGuard(1)
	_ = guard.Do(context.Background(), func() error { return &hostRejection{err: logonFailure()} })
	if guard.Failures() != 1 || guard.Err() == nil {
		t.Fatal("before any logon succeeded, every rejection must count: the password may be wrong")
	}
}

func TestAuthGuard_DomainRejectionAfterSuccessCounts(t *testing.T) {
	guard := NewAuthGuard(1)
	_ = guard.Do(context.Background(), func() error { return nil })
	_ = guard.Do(context.Background(), func() error { return logonFailure() })
	if guard.Err() == nil {
		t.Fatal("a rejection from a host in the credential's domain must still stop the scan (password changed or account locked)")
	}
}

func TestAuthGuard_LimitErrorNamesHostAndReason(t *testing.T) {
	guard := NewAuthGuard(1)
	_ = guard.Do(context.Background(), func() error {
		return &StageError{Stage: StageAuth, Host: "10.0.0.5", Err: smb.StatusMap[smb.StatusLogonFailure]}
	})
	err := guard.Err()
	want := "stopping: credentials rejected by 10.0.0.5 (Logon failed); 1 failed logon(s) sent, --max-auth-failures=1"
	if err == nil || err.Error() != want {
		t.Fatalf("limit error = %q, want %q", err, want)
	}
}
