package cmd

import (
	"github.com/vflame6/sharefinder/logger"
	"github.com/vflame6/sharefinder/scanner"
)

// ExecuteDiff prints the shares that are new, removed or have other
// permissions in the newer of two JSONL scans.
func ExecuteDiff(oldPath, newPath string) error {
	changes, err := scanner.DiffScans(oldPath, newPath)
	if err != nil {
		return err
	}
	logger.Info(scanner.FormatDiff(changes))
	return nil
}
