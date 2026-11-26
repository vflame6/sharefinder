package scanner

import (
	"cmp"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/vflame6/sharefinder/logger"
)

// ShareKey identifies a share across scans: the identity that saw it, the
// host's address and the share name, the last two case-insensitively. Hosts
// are matched by address, not by name: NetBIOS names repeat across hosts.
type ShareKey struct{ Identity, Host, Share string }

// ShareChange is one difference between two scans.
type ShareChange struct {
	// "new", "removed", "changed"; "unchecked" for a share the new scan's
	// host still lists but did not check (it was stopped early), "unreached"
	// for a host the new scan did not scan at all
	Kind     string
	Identity string
	UNC      string // //host for an unreached host
	Old, New string // permissions such as "READ,WRITE (SUBDIR)"; "" is no access
	Shares   int    // shares of an unreached host in the earlier scan
}

type diffShare struct{ unc, perms string }

// diffScan is what diff reads from one scan.
type diffScan struct {
	shares   map[ShareKey]diffShare
	scanned  map[resumeHost]bool            // hosts with a host record or a share record
	declared map[resumeHost]map[string]bool // the shares each host record lists
}

// DiffScans compares the shares of two JSONL scans. A share written more than
// once (a resumed scan) counts with its last record. A share missing from the
// new scan is "removed" only when its host was scanned and no longer lists it.
func DiffScans(oldPath, newPath string) ([]ShareChange, error) {
	before, err := loadDiffScan(oldPath, "new")
	if err != nil {
		return nil, err
	}
	after, err := loadDiffScan(newPath, "not checked")
	if err != nil {
		return nil, err
	}

	var changes []ShareChange
	for key, now := range after.shares {
		was, ok := before.shares[key]
		switch {
		case !ok:
			changes = append(changes, ShareChange{Kind: "new", Identity: key.Identity, UNC: now.unc, New: now.perms})
		case was.perms != now.perms:
			changes = append(changes, ShareChange{Kind: "changed", Identity: key.Identity, UNC: now.unc, Old: was.perms, New: now.perms})
		}
	}
	unreached := make(map[resumeHost]*ShareChange)
	for key, was := range before.shares {
		if _, ok := after.shares[key]; ok {
			continue
		}
		host := newResumeHost(key.Identity, key.Host)
		switch {
		case !after.scanned[host]:
			c := unreached[host]
			if c == nil {
				c = &ShareChange{Kind: "unreached", Identity: key.Identity, UNC: was.unc[:max(strings.LastIndex(was.unc, "/"), 0)]}
				unreached[host] = c
			}
			c.Shares++
		case after.declared[host][key.Share]:
			changes = append(changes, ShareChange{Kind: "unchecked", Identity: key.Identity, UNC: was.unc, Old: was.perms})
		default:
			changes = append(changes, ShareChange{Kind: "removed", Identity: key.Identity, UNC: was.unc, Old: was.perms})
		}
	}
	for _, c := range unreached {
		changes = append(changes, *c)
	}
	sortChanges(changes)
	return changes, nil
}

// loadDiffScan reads a scan; unreached describes how the shares an unfinished
// scan did not reach look in the diff.
func loadDiffScan(path, unreached string) (*diffScan, error) {
	d := &diffScan{
		shares:   make(map[ShareKey]diffShare),
		scanned:  make(map[resumeHost]bool),
		declared: make(map[resumeHost]map[string]bool),
	}
	scans, complete, interrupted := 0, false, false
	bad, err := readRecordsFile(path, func(typ string, raw []byte) error {
		switch typ {
		case RecordScan:
			scans++
		case RecordEnd:
			var rec EndRecord
			if json.Unmarshal(raw, &rec) == nil {
				complete, interrupted = true, interrupted || rec.Interrupted
			}
		case RecordHost:
			// a host whose shares could not be listed was not scanned
			var rec HostRecord
			if json.Unmarshal(raw, &rec) != nil || rec.Error != "" {
				return nil
			}
			host := newResumeHost(rec.Identity, rec.Host)
			d.scanned[host] = true
			if d.declared[host] == nil {
				d.declared[host] = make(map[string]bool)
			}
			for _, share := range rec.Shares {
				d.declared[host][strings.ToLower(share)] = true
			}
		case RecordShare:
			var rec ShareRecord
			if json.Unmarshal(raw, &rec) != nil {
				return nil
			}
			key := ShareKey{Identity: rec.Identity, Host: strings.ToLower(rec.Host), Share: strings.ToLower(rec.Share)}
			d.shares[key] = diffShare{unc: rec.UNC, perms: recordPermissions(rec)}
			d.scanned[newResumeHost(rec.Identity, rec.Host)] = true
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if scans == 0 {
		return nil, fmt.Errorf("%s is not a sharefinder JSONL file: it has no scan record", path)
	}
	if bad > 0 {
		logger.Warnf("Skipped %d unreadable line(s) in %s", bad, path)
	}
	switch {
	case !complete:
		logger.Warnf("%s: the scan did not finish; shares it did not reach show as %s", path, unreached)
	case interrupted:
		logger.Warnf("%s: the scan was interrupted; shares it did not reach show as %s", path, unreached)
	}
	return d, nil
}

// recordPermissions spells a share record's access as the text output does.
func recordPermissions(rec ShareRecord) string {
	return sharePermissions(Share{ReadPermission: rec.Read, WritePermission: rec.Write, WriteAccess: strings.Join(rec.WriteAccess, ",")})
}

var changeOrder = map[string]int{"new": 0, "removed": 1, "changed": 2, "unchecked": 3, "unreached": 4}

func sortChanges(changes []ShareChange) {
	slices.SortFunc(changes, func(a, b ShareChange) int {
		return cmp.Or(
			cmp.Compare(changeOrder[a.Kind], changeOrder[b.Kind]),
			cmp.Compare(strings.ToLower(a.UNC), strings.ToLower(b.UNC)),
			cmp.Compare(a.Identity, b.Identity),
		)
	})
}

// FormatDiff prints changes in sections: new shares (+), removed shares (-),
// permission changes (~ old -> new) and what the new scan did not check (?).
func FormatDiff(changes []ShareChange) string {
	if len(changes) == 0 {
		return "No changes\n"
	}
	changes = slices.Clone(changes)
	sortChanges(changes)
	identities := make(map[string]bool)
	for _, c := range changes {
		identities[c.Identity] = true
	}

	var b strings.Builder
	for _, section := range []struct {
		kinds       []string
		title, mark string
	}{
		{[]string{"new"}, "New shares", "+ "},
		{[]string{"removed"}, "Removed shares", "- "},
		{[]string{"changed"}, "Permission changes", "~ "},
		{[]string{"unchecked", "unreached"}, "Not checked in the new scan", "? "},
	} {
		started := false
		for _, c := range changes {
			if !slices.Contains(section.kinds, c.Kind) {
				continue
			}
			if !started {
				if b.Len() > 0 {
					b.WriteString("\n")
				}
				b.WriteString(section.title + "\n")
				started = true
			}
			b.WriteString(section.mark + printable(c.UNC) + "  ")
			switch c.Kind {
			case "new":
				b.WriteString(permsText(c.New))
			case "removed", "unchecked":
				b.WriteString(permsText(c.Old))
			case "unreached":
				noun := "shares"
				if c.Shares == 1 {
					noun = "share"
				}
				fmt.Fprintf(&b, "host not scanned, %d %s", c.Shares, noun)
			default:
				b.WriteString(permsText(c.Old) + " -> " + permsText(c.New))
			}
			if len(identities) > 1 {
				b.WriteString("  (as " + printable(c.Identity) + ")")
			}
			b.WriteString("\n")
		}
	}
	return b.String()
}

func permsText(perms string) string {
	if perms == "" {
		return "no access"
	}
	return perms
}
