package scanner

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/jfjallid/go-smb/smb"
)

// fakeLister serves directory listings from a function of the directory path.
type fakeLister struct {
	list  func(dir string) ([]smb.SharedFile, error)
	calls []string
}

func (f *fakeLister) ListDirectory(share, dir, pattern string) ([]smb.SharedFile, error) {
	f.calls = append(f.calls, dir)
	return f.list(dir)
}

func join(parent, name string) string {
	if parent == "" {
		return name
	}
	return parent + `\` + name
}

func dirEntry(parent, name string) smb.SharedFile {
	return smb.SharedFile{Name: name, FullPath: join(parent, name), IsDir: true}
}

func fileEntry(parent, name string) smb.SharedFile {
	return smb.SharedFile{Name: name, FullPath: join(parent, name)}
}

// treeLister serves a fixed tree: directory path -> entries.
func treeLister(tree map[string][]smb.SharedFile) *fakeLister {
	return &fakeLister{list: func(dir string) ([]smb.SharedFile, error) { return tree[dir], nil }}
}

// walkDirs walks and returns the emitted directory paths in order.
func walkDirs(t *testing.T, l dirLister, lim ListLimits) ([]string, walkStats) {
	t.Helper()
	var dirs []string
	stats, err := walkShare(context.Background(), l, "share", lim, true,
		func(dir smb.SharedFile, depth int, entries []smb.SharedFile) { dirs = append(dirs, dir.FullPath) },
		func(dir string, err error) { t.Errorf("unexpected listing error in %q: %v", dir, err) })
	if err != nil {
		t.Fatal(err)
	}
	return dirs, stats
}

func TestWalkShare_DepthLimit(t *testing.T) {
	tree := map[string][]smb.SharedFile{}
	parent := ""
	for _, name := range []string{"a", "b", "c", "d", "e", "f", "g", "h"} {
		tree[parent] = []smb.SharedFile{dirEntry(parent, name)}
		parent = join(parent, name)
	}
	dirs, stats := walkDirs(t, treeLister(tree), ListLimits{MaxDepth: 3})
	want := []string{"", "a", `a\b`, `a\b\c`}
	if !reflect.DeepEqual(dirs, want) {
		t.Fatalf("listed %v, want %v", dirs, want)
	}
	if !stats.DepthLimited {
		t.Fatal("DepthLimited must be set when deeper directories were skipped")
	}
}

func TestWalkShare_DepthZeroListsRootOnly(t *testing.T) {
	tree := map[string][]smb.SharedFile{"": {dirEntry("", "a")}, "a": {fileEntry("a", "x")}}
	dirs, _ := walkDirs(t, treeLister(tree), ListLimits{MaxDepth: 0})
	if !reflect.DeepEqual(dirs, []string{""}) {
		t.Fatalf("listed %v, want only the root", dirs)
	}
}

func TestWalkShare_SymlinkLoopStops(t *testing.T) {
	// a directory symlink to "." that the server resolves itself: every level
	// contains "loop" again and no reparse flag is visible
	l := &fakeLister{list: func(dir string) ([]smb.SharedFile, error) {
		return []smb.SharedFile{dirEntry(dir, "loop")}, nil
	}}
	dirs, stats := walkDirs(t, l, ListLimits{MaxDepth: 5})
	if len(dirs) != 6 {
		t.Fatalf("listed %d directories, want 6 (root plus 5 levels): %v", len(dirs), dirs)
	}
	if !stats.DepthLimited {
		t.Fatal("DepthLimited must be set")
	}
}

func TestWalkShare_SkipsJunctionUnlessFollow(t *testing.T) {
	junction := dirEntry("", "j")
	junction.IsJunction = true
	tree := map[string][]smb.SharedFile{
		"":  {junction, dirEntry("", "d")},
		"j": {fileEntry("j", "x")},
		"d": {fileEntry("d", "y")},
	}
	dirs, _ := walkDirs(t, treeLister(tree), ListLimits{MaxDepth: 5})
	if !reflect.DeepEqual(dirs, []string{"", "d"}) {
		t.Fatalf("listed %v, want the junction skipped with --disable-follow-links", dirs)
	}
	dirs, _ = walkDirs(t, treeLister(tree), ListLimits{MaxDepth: 5, FollowLinks: true})
	if !reflect.DeepEqual(dirs, []string{"", "j", "d"}) {
		t.Fatalf("listed %v, want the junction followed", dirs)
	}
}

func TestWalkShare_MaxFiles(t *testing.T) {
	tree := map[string][]smb.SharedFile{}
	for _, d := range []string{"d1", "d2", "d3"} {
		tree[""] = append(tree[""], dirEntry("", d))
		for i := 0; i < 10; i++ {
			tree[d] = append(tree[d], fileEntry(d, fmt.Sprintf("f%d", i)))
		}
	}
	var entries int
	stats, err := walkShare(context.Background(), treeLister(tree), "share", ListLimits{MaxDepth: 5, MaxFiles: 15}, true,
		func(dir smb.SharedFile, depth int, e []smb.SharedFile) { entries += len(e) }, nil)
	if err != nil {
		t.Fatal(err)
	}
	if entries != 15 {
		t.Fatalf("emitted %d entries, want 15", entries)
	}
	if !stats.Truncated {
		t.Fatal("Truncated must be set when --max-files stops the listing")
	}
	if stats.Files+stats.Dirs != 15 {
		t.Fatalf("stats count %d entries, want 15", stats.Files+stats.Dirs)
	}
}

func TestWalkShare_NoRecurseListsRootOnly(t *testing.T) {
	tree := map[string][]smb.SharedFile{"": {dirEntry("", "a")}, "a": {fileEntry("a", "x")}}
	var dirs []string
	_, err := walkShare(context.Background(), treeLister(tree), "share", ListLimits{MaxDepth: 5}, false,
		func(dir smb.SharedFile, depth int, e []smb.SharedFile) { dirs = append(dirs, dir.FullPath) }, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(dirs, []string{""}) {
		t.Fatalf("listed %v without --recurse, want only the root", dirs)
	}
}

func TestWalkShare_CancelStops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	l := &fakeLister{}
	l.list = func(dir string) ([]smb.SharedFile, error) {
		if dir == "a" {
			cancel()
		}
		return []smb.SharedFile{dirEntry(dir, "a"), dirEntry(dir, "b")}, nil
	}
	_, err := walkShare(ctx, l, "share", ListLimits{MaxDepth: 50}, true,
		func(smb.SharedFile, int, []smb.SharedFile) {}, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("walk returned %v, want context.Canceled", err)
	}
	if len(l.calls) > 2 {
		t.Fatalf("walk kept listing after cancellation: %v", l.calls)
	}
}

func TestWalkShare_SubdirectoryErrorContinues(t *testing.T) {
	denied := errors.New("access denied")
	l := &fakeLister{list: func(dir string) ([]smb.SharedFile, error) {
		switch dir {
		case "":
			return []smb.SharedFile{dirEntry("", "locked"), dirEntry("", "open")}, nil
		case "locked":
			return nil, denied
		default:
			return nil, nil
		}
	}}
	var dirs []string
	var failed []string
	_, err := walkShare(context.Background(), l, "share", ListLimits{MaxDepth: 5}, true,
		func(dir smb.SharedFile, depth int, e []smb.SharedFile) { dirs = append(dirs, dir.FullPath) },
		func(dir string, err error) { failed = append(failed, dir) })
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(dirs, []string{"", "open"}) || !reflect.DeepEqual(failed, []string{"locked"}) {
		t.Fatalf("listed %v, failed %v", dirs, failed)
	}
}

func TestWalkShare_RootErrorReturned(t *testing.T) {
	denied := errors.New("access denied")
	l := &fakeLister{list: func(string) ([]smb.SharedFile, error) { return nil, denied }}
	_, err := walkShare(context.Background(), l, "share", ListLimits{MaxDepth: 5}, true,
		func(smb.SharedFile, int, []smb.SharedFile) {}, nil)
	if !errors.Is(err, denied) {
		t.Fatalf("walk returned %v, want the root listing error", err)
	}
}
