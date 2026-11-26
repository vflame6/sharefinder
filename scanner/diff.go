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
	Kind     string // "new", "removed" or "changed"
	Identity string
	UNC      string
	Old, New string // permissions such as "READ,WRITE (SUBDIR)"; "" is no access
}

type diffShare struct{ unc, perms string }

// DiffScans compares the shares of two JSONL scans. A share written more than
// once (a resumed scan) counts with its last record.
func DiffScans(oldPath, newPath string) ([]ShareChange, error) {
	before, err := loadDiffShares(oldPath, "new")
	if err != nil {
		return nil, err
	}
	after, err := loadDiffShares(newPath, "removed")
	if err != nil {
		return nil, err
	}

	var changes []ShareChange
	for key, now := range after {
		was, ok := before[key]
		switch {
		case !ok:
			changes = append(changes, ShareChange{Kind: "new", Identity: key.Identity, UNC: now.unc, New: now.perms})
		case was.perms != now.perms:
			changes = append(changes, ShareChange{Kind: "changed", Identity: key.Identity, UNC: now.unc, Old: was.perms, New: now.perms})
		}
	}
	for key, was := range before {
		if _, ok := after[key]; !ok {
			changes = append(changes, ShareChange{Kind: "removed", Identity: key.Identity, UNC: was.unc, Old: was.perms})
		}
	}
	sortChanges(changes)
	return changes, nil
}

// loadDiffShares reads the share records of a scan; unreached describes how
// the shares an unfinished scan did not reach would look in the diff.
func loadDiffShares(path, unreached string) (map[ShareKey]diffShare, error) {
	shares := make(map[ShareKey]diffShare)
	scans, complete := 0, false
	bad, err := readRecordsFile(path, func(typ string, raw []byte) error {
		switch typ {
		case RecordScan:
			scans++
		case RecordEnd:
			complete = true
		case RecordShare:
			var rec ShareRecord
			if json.Unmarshal(raw, &rec) != nil {
				return nil
			}
			key := ShareKey{Identity: rec.Identity, Host: strings.ToLower(rec.Host), Share: strings.ToLower(rec.Share)}
			shares[key] = diffShare{unc: rec.UNC, perms: recordPermissions(rec)}
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
	if !complete {
		logger.Warnf("%s: the scan did not finish; shares it did not reach show as %s", path, unreached)
	}
	return shares, nil
}

// recordPermissions spells a share record's access as the text output does.
func recordPermissions(rec ShareRecord) string {
	return sharePermissions(Share{ReadPermission: rec.Read, WritePermission: rec.Write, WriteAccess: strings.Join(rec.WriteAccess, ",")})
}

var changeOrder = map[string]int{"new": 0, "removed": 1, "changed": 2}

func sortChanges(changes []ShareChange) {
	slices.SortFunc(changes, func(a, b ShareChange) int {
		return cmp.Or(
			cmp.Compare(changeOrder[a.Kind], changeOrder[b.Kind]),
			cmp.Compare(strings.ToLower(a.UNC), strings.ToLower(b.UNC)),
			cmp.Compare(a.Identity, b.Identity),
		)
	})
}

// FormatDiff prints changes in sections: new shares (+), removed shares (-)
// and permission changes (~ old -> new).
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
	for _, section := range []struct{ kind, title, mark string }{
		{"new", "New shares", "+ "},
		{"removed", "Removed shares", "- "},
		{"changed", "Permission changes", "~ "},
	} {
		started := false
		for _, c := range changes {
			if c.Kind != section.kind {
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
			case "removed":
				b.WriteString(permsText(c.Old))
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
