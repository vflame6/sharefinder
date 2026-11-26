package scanner

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// knownExtensions are the output extensions stripped from a base name, longest
// first so ".unc.txt" wins over ".txt".
var knownExtensions = []string{".relay.txt", ".unc.txt", ".jsonl", ".json", ".html", ".xml", ".csv", ".txt"}

// OutputPath turns an output base name into a file name with extension ext.
// One known extension is stripped first (case-insensitively), so -o plain.txt
// writes plain.txt and not plain.txt.txt.
func OutputPath(base, ext string) string {
	lower := strings.ToLower(base)
	for _, known := range knownExtensions {
		if strings.HasSuffix(lower, known) {
			base = base[:len(base)-len(known)]
			break
		}
	}
	return base + ext
}

// CheckOverwrite refuses output paths that already exist unless force is set,
// and two outputs that would write the same file.
func CheckOverwrite(paths []string, force bool) error {
	seen := make(map[string]bool, len(paths))
	var existing []string
	for _, p := range paths {
		key := filepath.Clean(p)
		if seen[key] {
			return fmt.Errorf("two outputs would write %s; give them different names", p)
		}
		seen[key] = true
		if _, err := os.Stat(p); err == nil {
			existing = append(existing, p)
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("output %s: %w", p, err)
		}
	}
	if len(existing) > 0 && !force {
		return fmt.Errorf("output files already exist: %s (use --force to overwrite them)", strings.Join(existing, ", "))
	}
	return nil
}
