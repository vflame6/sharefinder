package scanner

import (
	"errors"
	"fmt"
	"io"

	"github.com/jfjallid/go-smb/dcerpc/mssrvs"
	"github.com/jfjallid/go-smb/smb"
	"github.com/vflame6/sharefinder/logger"
	"github.com/vflame6/sharefinder/utils"
)

// WriteCheckMode selects how write access to a share is tested.
type WriteCheckMode string

const (
	// WriteCheckMask opens the share root with write access masks; it
	// creates nothing.
	WriteCheckMask WriteCheckMode = "mask"
	// WriteCheckFile creates and deletes a temporary file in the share root.
	WriteCheckFile WriteCheckMode = "file"
	// WriteCheckOff skips the write check.
	WriteCheckOff WriteCheckMode = "off"
)

// Write access labels, as NetExec reports them.
const (
	WriteLabel       = "WRITE"          // files can be created in the share root
	WriteLabelSubdir = "WRITE (SUBDIR)" // only subdirectories can be created
	WriteLabelACL    = "WRITE (ACL)"    // the DACL or owner can be changed to grant write
)

var writeLabelOrder = []string{WriteLabel, WriteLabelSubdir, WriteLabelACL}

// maskProbes are the access masks requested on the share root in mask mode.
var maskProbes = []struct {
	mask  uint32
	label string
}{
	{smb.FAccMaskGenericWrite, WriteLabel},
	{smb.DAccMaskFileAddFile, WriteLabel},
	{smb.DAccMaskFileAddSubDirectory, WriteLabelSubdir},
	{smb.DAccMaskWriteDac, WriteLabelACL},
	{smb.DAccMaskWriteOwner, WriteLabelACL},
}

// ParseWriteCheckMode validates a --write-check value.
func ParseWriteCheckMode(s string) (WriteCheckMode, error) {
	switch mode := WriteCheckMode(s); mode {
	case WriteCheckMask, WriteCheckFile, WriteCheckOff:
		return mode, nil
	}
	return "", fmt.Errorf("invalid --write-check %q: use mask, file or off", s)
}

// writeLabels deduplicates granted labels into a fixed order; plain WRITE
// makes the narrower labels redundant.
func writeLabels(granted []string) []string {
	set := make(map[string]bool, len(granted))
	for _, g := range granted {
		set[g] = true
	}
	if set[WriteLabel] {
		return []string{WriteLabel}
	}
	var out []string
	for _, label := range writeLabelOrder {
		if set[label] {
			out = append(out, label)
		}
	}
	return out
}

// isDiskShare reports whether a share holds files. Print queues, devices and
// IPC shares are never write-checked: a test file sent to a print queue is a
// print job.
func isDiskShare(typeID uint32) bool {
	switch typeID {
	case mssrvs.StypeDisktree, mssrvs.StypeClusterFS, mssrvs.StypeClusterSOFS, mssrvs.StypeClusterDFS:
		return true
	}
	return false
}

// CheckWriteAccess tests write access to a disk share and returns the
// granted write labels, or nil when the share is not writable or the check
// is off.
func (conn *Connection) CheckWriteAccess(share string, mode WriteCheckMode) []string {
	switch mode {
	case WriteCheckOff:
		return nil
	case WriteCheckMask:
		return conn.checkWriteMask(share)
	default:
		if conn.checkWriteFile(share) {
			return []string{WriteLabel}
		}
		return nil
	}
}

// checkWriteMask opens the share root with one write access mask at a time.
// An open that succeeds proves the right without creating anything.
func (conn *Connection) checkWriteMask(share string) []string {
	if err := conn.session.TreeConnect(share); err != nil {
		return nil
	}
	defer func() {
		logCloseError("failed to disconnect tree "+share, conn.session.TreeDisconnect(share))
	}()

	var granted []string
	for _, probe := range maskProbes {
		if contains(granted, probe.label) {
			continue
		}
		opts := smb.NewCreateReqOpts()
		opts.DesiredAccess = probe.mask
		opts.ShareAccess = smb.FileShareRead | smb.FileShareWrite | smb.FileShareDelete
		opts.CreateDisp = smb.FileOpen
		opts.CreateOpts = smb.FileDirectoryFile
		f, err := conn.session.OpenFileExt(share, "", opts)
		if err != nil {
			logger.Debugf("no %s on %s\\%s (mask 0x%08x): %v", probe.label, conn.host, printable(share), probe.mask, err)
			continue
		}
		logCloseError("failed to close share root of "+share, f.CloseFile())
		granted = append(granted, probe.label)
	}
	return writeLabels(granted)
}

// checkWriteFile creates a random file in the share root and deletes it.
func (conn *Connection) checkWriteFile(share string) bool {
	if err := conn.session.TreeConnect(share); err != nil {
		return false
	}
	defer func() {
		logCloseError("failed to disconnect tree "+share, conn.session.TreeDisconnect(share))
	}()

	return probeWriteFile(conn.session, conn.host, share, utils.RandSeq(16)+".txt")
}

// fileProber is the part of a connected share the file write probe uses.
type fileProber interface {
	PutFile(share, path string, offset uint64, callback func([]byte) (int, error)) error
	DeleteFile(share, path string) error
}

// probeWriteFile creates name in the share root and deletes it. It reports
// whether the file could be created; a file that may have been left behind is
// always reported at Error level with its full path, even after Ctrl+C.
func probeWriteFile(p fileProber, host, share, name string) bool {
	data := utils.RandSeq(32)
	sent := false
	err := p.PutFile(share, name, 0, func(buffer []byte) (int, error) {
		if sent {
			return 0, io.EOF
		}
		copy(buffer, data)
		sent = true
		return len(data), nil
	})
	leftover := func(why error) {
		logger.Error(fmt.Errorf("write probe file \\\\%s\\%s\\%s may remain: %w", host, printable(share), name, why))
	}

	if err == nil {
		if delErr := p.DeleteFile(share, name); delErr != nil {
			leftover(fmt.Errorf("delete failed: %w", delErr))
		}
		return true
	}
	if isExpectedSMBWriteDeniedError(err) {
		// the create itself was refused: nothing exists
		logger.Debugf("write probe denied on share %s\\%s: %v", host, printable(share), err)
		return false
	}

	// The create may have succeeded before writing failed (quota, full disk,
	// connection cut): remove whatever may be there.
	delErr := p.DeleteFile(share, name)
	switch {
	case delErr == nil:
		logger.Debugf("write probe on %s\\%s failed after creating its file (%v); file removed", host, printable(share), err)
		return true
	case isNotFoundError(delErr):
		logger.Debugf("write probe failed on share %s\\%s: %v", host, printable(share), err)
		return false
	default:
		leftover(fmt.Errorf("write failed (%v), delete failed: %w", err, delErr))
		return false
	}
}

// isNotFoundError reports STATUS_OBJECT_NAME_NOT_FOUND.
func isNotFoundError(err error) bool {
	return errors.Is(err, smb.StatusMap[smb.StatusObjectNameNotFound])
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
