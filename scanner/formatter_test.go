package scanner

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/vflame6/sharefinder/utils"
)

// The reference* functions are the quadratic implementations the formatter
// replaced; the new ones must produce byte-identical output.

func referenceSprintFiles(files []File) string {
	var result string
	for _, file := range files {
		lastWrite := time.Time.Format(file.LastModified, dateTimeFormat)
		fileSize := utils.BytesToHumanReadableSize(file.Size)
		result += fmt.Sprintf("%-4s  %8s  %-16s  %s\n", file.Type, fileSize, lastWrite, file.Name)
	}
	return result
}

func referenceSprintDirectories(ip, share string, dirs []Directory) string {
	var result string
	for _, dir := range dirs {
		result += fmt.Sprintf("Listing directory %s\\%s\\%s\n", ip, share, dir.Name)
		result += fmt.Sprintf("%-4s  %8s  %-16s  %s\n", "Type", "Size", "LastWriteTime", "Name")
		result += fmt.Sprintf("%-4s  %8s  %-16s  %s\n", "----", "----", "-------------", "----")
		result += referenceSprintFiles(dir.Files)
		result += "\n"
	}
	return result
}

func fixtureHost() Host {
	when := time.Date(2024, 6, 15, 10, 30, 0, 0, time.UTC)
	files := []File{
		{Type: "dir", Name: "Documents", LastModified: when},
		{Type: "file", Name: "readme.txt", Size: 1024, LastModified: when},
	}
	return Host{IP: "10.0.0.1", Shares: []Share{
		{ShareName: "Data", Description: "User data", ReadPermission: true, WritePermission: true, WriteAccess: "WRITE (SUBDIR)",
			Files: files, Directories: []Directory{{Name: `Documents`, Files: files}, {Name: `Documents\Sub`, Files: files[1:]}}},
		{ShareName: "Locked", Description: "No access"},
	}}
}

func TestFormatter_MatchesReference(t *testing.T) {
	h := fixtureHost()
	share := h.Shares[0]
	if got, want := SprintFiles(share.Files), referenceSprintFiles(share.Files); got != want {
		t.Errorf("SprintFiles:\n%q\nwant\n%q", got, want)
	}
	if got, want := SprintDirectories(h.IP, share.ShareName, share.Directories), referenceSprintDirectories(h.IP, share.ShareName, share.Directories); got != want {
		t.Errorf("SprintDirectories:\n%q\nwant\n%q", got, want)
	}
	wantShares := "Listing share 10.0.0.1\\Data\n" +
		fmt.Sprintf("%-4s  %8s  %-16s  %s\n", "Type", "Size", "LastWriteTime", "Name") +
		fmt.Sprintf("%-4s  %8s  %-16s  %s\n", "----", "----", "-------------", "----") +
		referenceSprintFiles(share.Files) + "\n" +
		referenceSprintDirectories(h.IP, share.ShareName, share.Directories)
	if got := SprintShares(h, nil); got != wantShares {
		t.Errorf("SprintShares:\n%q\nwant\n%q", got, wantShares)
	}
	wantHost := "\n" + fmt.Sprintf("%-16s %-16s %-16s\n", "Share", "Permissions", "Description") +
		fmt.Sprintf("%-16s %-16s %-16s\n", "-----", "-----------", "----------") +
		fmt.Sprintf("%-16s %-16s %-16s\n", "Data", "READ,WRITE (SUBDIR)", "User data") +
		fmt.Sprintf("%-16s %-16s %-16s\n", "Locked", "", "No access") + "\n"
	// the permissions column widens to fit "READ,WRITE (SUBDIR)" (19 chars)
	wantHost = strings.ReplaceAll(wantHost, "Permissions      ", "Permissions         ")
	wantHost = strings.ReplaceAll(wantHost, "-----------      ", "-----------         ")
	wantHost = strings.ReplaceAll(wantHost, "Locked                            ", "Locked                               ")
	if got := SprintHost(h, nil); got != wantHost {
		t.Errorf("SprintHost:\n%q\nwant\n%q", got, wantHost)
	}
}

func manyFiles(n int) []File {
	when := time.Date(2024, 6, 15, 10, 30, 0, 0, time.UTC)
	files := make([]File, n)
	for i := range files {
		files[i] = File{Type: "file", Name: fmt.Sprintf("document-%06d.docx", i), Size: uint64(i * 37), LastModified: when}
	}
	return files
}

func TestSprintFiles_80kIsFast(t *testing.T) {
	if testing.Short() {
		t.Skip("timing test")
	}
	files := manyFiles(80000)
	start := time.Now()
	out := SprintFiles(files)
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("formatting 80,000 files took %v, want under 2s", elapsed)
	}
	if strings.Count(out, "\n") != 80000 {
		t.Fatal("one line per file expected")
	}
}

func BenchmarkSprintFiles(b *testing.B) {
	files := manyFiles(80000)
	for i := 0; i < b.N; i++ {
		_ = SprintFiles(files)
	}
}
