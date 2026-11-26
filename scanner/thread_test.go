package scanner

import (
	"context"
	"errors"
	"testing"

	"github.com/jfjallid/go-smb/dcerpc/mssrvs"
)

// fakeChecker answers share checks; onRead runs before a read check.
type fakeChecker struct {
	readable map[string]bool
	writable map[string]bool
	onRead   func(share string)
}

func (f *fakeChecker) CheckReadAccess(share string) error {
	if f.onRead != nil {
		f.onRead(share)
	}
	if f.readable[share] {
		return nil
	}
	return errors.New("access denied")
}

func (f *fakeChecker) CheckWriteAccess(share string, mode WriteCheckMode) []string {
	if f.writable[share] {
		return []string{WriteLabel}
	}
	return nil
}

func TestCheckShares(t *testing.T) {
	checker := &fakeChecker{readable: map[string]bool{"Data": true}, writable: map[string]bool{"Data": true}}
	shares := []mssrvs.NetShare{
		{Name: "Data", Comment: "Department data", TypeId: mssrvs.StypeDisktree},
		{Name: "IPC$", TypeId: mssrvs.StypeIPC},
		{Name: "Printer", TypeId: mssrvs.StypePrintq},
	}
	got := checkShares(context.Background(), checker, shares, &Options{Exclude: []string{"IPC$"}, WriteCheck: WriteCheckFile})
	if len(got) != 2 {
		t.Fatalf("got %d shares, want 2 (IPC$ excluded): %+v", len(got), got)
	}
	if !got[0].ReadPermission || !got[0].WritePermission || got[0].WriteAccess != WriteLabel || got[0].Description != "Department data" {
		t.Fatalf("Data = %+v", got[0])
	}
	if got[1].WritePermission {
		t.Fatal("a print queue must never be write-checked")
	}
}

func TestCheckShares_CancelledShareIsLeftOut(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	checker := &fakeChecker{
		readable: map[string]bool{"A": true, "B": true, "C": true},
		onRead: func(share string) {
			if share == "B" {
				cancel() // Ctrl+C while B is being checked: its connection is gone
			}
		},
	}
	shares := []mssrvs.NetShare{{Name: "A"}, {Name: "B"}, {Name: "C"}}
	got := checkShares(ctx, checker, shares, &Options{WriteCheck: WriteCheckOff})
	if len(got) != 1 || got[0].ShareName != "A" {
		t.Fatalf("got %+v, want only A: B's checks were cut short and C never ran", got)
	}
}
