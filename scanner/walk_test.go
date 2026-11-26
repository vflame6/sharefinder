package scanner

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
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

// --depth counts the share root as level 1: 4 lists the root and 3 levels
// below it.
func TestWalkShare_DepthLimit(t *testing.T) {
	tree := map[string][]smb.SharedFile{}
	parent := ""
	for _, name := range []string{"a", "b", "c", "d", "e", "f", "g", "h"} {
		tree[parent] = []smb.SharedFile{dirEntry(parent, name)}
		parent = join(parent, name)
	}
	dirs, stats := walkDirs(t, treeLister(tree), ListLimits{MaxDepth: 4})
	want := []string{"", "a", `a\b`, `a\b\c`}
	if !reflect.DeepEqual(dirs, want) {
		t.Fatalf("listed %v, want %v", dirs, want)
	}
	if !stats.DepthLimited {
		t.Fatal("DepthLimited must be set when deeper directories were skipped")
	}
}

func TestWalkShare_DepthOneListsRootOnly(t *testing.T) {
	tree := map[string][]smb.SharedFile{"": {dirEntry("", "a")}, "a": {fileEntry("a", "x")}}
	dirs, stats := walkDirs(t, treeLister(tree), ListLimits{MaxDepth: 1})
	if !reflect.DeepEqual(dirs, []string{""}) || !stats.DepthLimited {
		t.Fatalf("listed %v (depth limited %v), want only the root", dirs, stats.DepthLimited)
	}
}

// --depth 0, the default, lists every level.
func TestWalkShare_DepthZeroIsUnlimited(t *testing.T) {
	tree := map[string][]smb.SharedFile{}
	parent := ""
	for i := range 40 {
		name := fmt.Sprintf("d%02d", i)
		tree[parent] = []smb.SharedFile{dirEntry(parent, name)}
		parent = join(parent, name)
	}
	dirs, stats := walkDirs(t, treeLister(tree), ListLimits{})
	if len(dirs) != 41 || stats.DepthLimited {
		t.Fatalf("listed %d directories (depth limited %v), want all 41", len(dirs), stats.DepthLimited)
	}
}

// runaway serves list, and fails a walk that keeps descending, so a missing
// loop guard fails the test instead of hanging it.
func runaway(list func(dir string) []smb.SharedFile) *fakeLister {
	return &fakeLister{list: func(dir string) ([]smb.SharedFile, error) {
		if strings.Count(dir, `\`) > 30 {
			return nil, errors.New("runaway walk")
		}
		return list(dir), nil
	}}
}

func last(dir string) string {
	return dir[strings.LastIndex(dir, `\`)+1:]
}

func junctionEntry(parent, name string) smb.SharedFile {
	e := dirEntry(parent, name)
	e.IsJunction = true
	return e
}

// A directory symlink to "." that the server resolves itself shows no link
// flag: every level lists "loop" again. With no depth limit the walk stops
// at the first directory that lists what a directory above it listed.
func TestWalkShare_SymlinkLoopStops(t *testing.T) {
	l := runaway(func(dir string) []smb.SharedFile {
		return []smb.SharedFile{dirEntry(dir, "loop")}
	})
	dirs, stats := walkDirs(t, l, ListLimits{})
	if !reflect.DeepEqual(dirs, []string{""}) || stats.Loops != 1 {
		t.Fatalf("listed %v with %d loop(s), want the root and 1 loop", dirs, stats.Loops)
	}
}

// A junction back to the share root is followed once, and its listing,
// the root's, is recognised as a loop.
func TestWalkShare_JunctionLoopStops(t *testing.T) {
	l := runaway(func(dir string) []smb.SharedFile {
		switch last(dir) {
		case "", "up": // up is a junction to the share root
			return []smb.SharedFile{dirEntry(dir, "a")}
		default:
			return []smb.SharedFile{junctionEntry(dir, "up"), fileEntry(dir, "f")}
		}
	})
	dirs, stats := walkDirs(t, l, ListLimits{FollowLinks: true})
	if !reflect.DeepEqual(dirs, []string{"", "a"}) || stats.Loops != 1 {
		t.Fatalf("listed %v with %d loop(s), want the root, a and 1 loop", dirs, stats.Loops)
	}
}

// Two junctions that point at each other's folders make a cycle.
func TestWalkShare_LinkCycleStops(t *testing.T) {
	l := runaway(func(dir string) []smb.SharedFile {
		switch last(dir) {
		case "":
			return []smb.SharedFile{dirEntry(dir, "a"), dirEntry(dir, "b")}
		case "a", "toA":
			return []smb.SharedFile{junctionEntry(dir, "toB")}
		default:
			return []smb.SharedFile{junctionEntry(dir, "toA")}
		}
	})
	dirs, stats := walkDirs(t, l, ListLimits{FollowLinks: true})
	want := []string{"", "a", `a\toB`, "b", `b\toA`}
	if !reflect.DeepEqual(dirs, want) || stats.Loops != 2 {
		t.Fatalf("listed %v with %d loop(s), want %v and 2 loops", dirs, stats.Loops, want)
	}
}

// Nested directories of the same name are no loop when they are other
// directories: their times differ.
func TestWalkShare_SameNamesAreNoLoop(t *testing.T) {
	outer, inner := dirEntry("", "a"), dirEntry("a", "a")
	outer.LastWriteTime, inner.LastWriteTime = 100, 200
	tree := map[string][]smb.SharedFile{"": {outer}, "a": {inner}, `a\a`: {fileEntry(`a\a`, "x")}}
	dirs, stats := walkDirs(t, treeLister(tree), ListLimits{})
	if !reflect.DeepEqual(dirs, []string{"", "a", `a\a`}) || stats.Loops != 0 {
		t.Fatalf("listed %v with %d loop(s), want every directory", dirs, stats.Loops)
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
