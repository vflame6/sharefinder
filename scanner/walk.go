package scanner

import (
	"context"
	"encoding/binary"
	"hash/fnv"
	"slices"
	"strings"

	"github.com/jfjallid/go-smb/smb"
)

// ListLimits bounds a share listing.
type ListLimits struct {
	// MaxDepth is the number of directory levels listed, the share root
	// being level 1; 0, the default of --depth, lists every level.
	MaxDepth int
	// FollowLinks descends into directory symlinks and junctions, such as
	// the domain folder in SYSVOL; on unless --disable-follow-links. A link
	// back up the tree is not followed round: see visit.
	FollowLinks bool
	// MaxFiles stops the listing of a share after this many entries. 0 means
	// no limit.
	MaxFiles int
}

// dirLister lists one directory of a connected share.
type dirLister interface {
	ListDirectory(share, dir, pattern string) ([]smb.SharedFile, error)
}

// walkStats summarises a share listing.
type walkStats struct {
	Files, Dirs  int64
	Truncated    bool // MaxFiles stopped the listing
	DepthLimited bool // deeper directories were not listed
	Loops        int  // directories not listed: they repeat one above them
}

// walkShare lists a share pre-order: the root (depth 0), then each
// subdirectory in listing order when recurse is set. emit receives every
// listed directory with its entries; the root is an empty SharedFile.
// onErr, when set, receives subdirectory listing errors, which do not stop the
// walk; a root listing error or cancellation does and is returned.
func walkShare(ctx context.Context, l dirLister, share string, lim ListLimits, recurse bool,
	emit func(dir smb.SharedFile, depth int, entries []smb.SharedFile),
	onErr func(dir string, err error)) (walkStats, error) {

	w := &walker{ctx: ctx, l: l, share: share, lim: lim, recurse: recurse, emit: emit, onErr: onErr}
	entries, err := l.ListDirectory(share, "", "")
	if err != nil {
		return w.stats, err
	}
	err = w.visit(smb.SharedFile{}, 0, entries)
	return w.stats, err
}

type walker struct {
	ctx     context.Context
	l       dirLister
	share   string
	lim     ListLimits
	recurse bool
	emit    func(dir smb.SharedFile, depth int, entries []smb.SharedFile)
	onErr   func(dir string, err error)
	stats   walkStats
	// the listings of the directories above the one being visited
	ancestors []uint64
}

// visit emits one listed directory and descends into its subdirectories.
//
// A link back up the tree, a junction or a symlink the server resolves
// itself (which shows no link flag), leads to a directory that lists exactly
// what a directory above it listed: the same entries with the same times.
// Such a directory is not listed again, so the walk ends even with no
// --depth. Last access times are left out of the comparison: listing a
// directory may change them.
func (w *walker) visit(dir smb.SharedFile, depth int, entries []smb.SharedFile) error {
	entries = w.take(entries)
	w.emit(dir, depth, entries)
	if !w.recurse {
		return nil
	}
	w.ancestors = append(w.ancestors, listingSignature(entries))
	defer func() { w.ancestors = w.ancestors[:len(w.ancestors)-1] }()
	for _, entry := range entries {
		if !entry.IsDir {
			continue
		}
		if entry.IsJunction && !w.lim.FollowLinks {
			continue
		}
		// depth is 0 at the share root, which is level 1
		if w.lim.MaxDepth > 0 && depth+2 > w.lim.MaxDepth {
			w.stats.DepthLimited = true
			continue
		}
		if w.stats.Truncated {
			return nil
		}
		if w.ctx.Err() != nil {
			return context.Cause(w.ctx)
		}
		children, err := w.l.ListDirectory(w.share, entry.FullPath, "*")
		if err != nil {
			if w.onErr != nil {
				w.onErr(entry.FullPath, err)
			}
			continue
		}
		if slices.Contains(w.ancestors, listingSignature(children)) {
			w.stats.Loops++
			continue
		}
		if err := w.visit(entry, depth+1, children); err != nil {
			return err
		}
	}
	return nil
}

// take applies MaxFiles to the next directory's entries and counts them.
func (w *walker) take(entries []smb.SharedFile) []smb.SharedFile {
	if w.lim.MaxFiles > 0 {
		left := int64(w.lim.MaxFiles) - (w.stats.Files + w.stats.Dirs)
		if left <= 0 {
			w.stats.Truncated = true
			return nil
		}
		if int64(len(entries)) > left {
			entries = entries[:left]
			w.stats.Truncated = true
		}
	}
	for _, entry := range entries {
		if entry.IsDir {
			w.stats.Dirs++
		} else {
			w.stats.Files++
		}
	}
	return entries
}

// listingSignature identifies a directory by what it lists: each entry's
// name, kind, size and creation, write and change times, in name order.
func listingSignature(entries []smb.SharedFile) uint64 {
	sorted := slices.Clone(entries)
	slices.SortFunc(sorted, func(a, b smb.SharedFile) int { return strings.Compare(a.Name, b.Name) })
	h := fnv.New64a()
	var num [8]byte
	for _, e := range sorted {
		_, _ = h.Write([]byte(e.Name))
		flags := byte(0)
		if e.IsDir {
			flags |= 1
		}
		if e.IsJunction {
			flags |= 2
		}
		_, _ = h.Write([]byte{0, flags})
		for _, v := range []uint64{e.Size, e.CreationTime, e.LastWriteTime, e.ChangeTime} {
			binary.LittleEndian.PutUint64(num[:], v)
			_, _ = h.Write(num[:])
		}
	}
	return h.Sum64()
}
