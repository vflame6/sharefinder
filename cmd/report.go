package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/vflame6/sharefinder/logger"
	"github.com/vflame6/sharefinder/scanner"
)

// ExecuteReport renders the HTML report of a JSONL file written by
// --output-json. The report is named after output, or after the input when
// output is empty, with the .html extension; an existing file is replaced
// only with force, and only once the new report is complete.
func ExecuteReport(input, output string, force bool) error {
	if output == "" {
		output = input
	}
	path := scanner.OutputPath(output, ".html")
	if filepath.Clean(path) == filepath.Clean(input) {
		return fmt.Errorf("the report would overwrite its input %s; name it with -o", input)
	}
	if err := scanner.CheckOverwrite([]string{path}, force); err != nil {
		return err
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), ".sharefinder-report-*.html")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // a no-op once renamed
	if err := scanner.WriteReport(input, tmp); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	logger.Warnf("Report written to %s", path)
	return nil
}
