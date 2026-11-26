package scanner

import (
	"context"

	"github.com/jfjallid/go-smb/smb"
)

// ListLimits bounds a share listing.
type ListLimits struct {
	// MaxDepth is the deepest directory level listed below the share root,
	// which is level 0. --depth, default 5.
	MaxDepth int
	// FollowLinks descends into directory symlinks and junctions. Off by
	// default: they can point back up the tree and loop.
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
}

// visit emits one listed directory and descends into its subdirectories.
func (w *walker) visit(dir smb.SharedFile, depth int, entries []smb.SharedFile) error {
	entries = w.take(entries)
	w.emit(dir, depth, entries)
	if !w.recurse {
		return nil
	}
	for _, entry := range entries {
		if !entry.IsDir {
			continue
		}
		// a directory symlink or junction may point back up the tree
		if entry.IsJunction && !w.lim.FollowLinks {
			continue
		}
		if depth+1 > w.lim.MaxDepth {
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
