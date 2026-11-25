package scanner

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/vflame6/sharefinder/utils"
)

var (
	dateTimeFormat        = "02/01/2006 15:04"
	dateTimeSecondsFormat = "02/01/2006 15:04:05"
)

// SprintHostLine formats the one-line summary of a scanned host. The session
// type and admin status are left out when unknown.
func SprintHostLine(h Host) string {
	result := fmt.Sprintf("[+] %s: %s (name:%s) (domain:%s) (signing:%v)", h.IP, h.Version, h.Hostname, h.Domain, h.Signing)
	if h.Session != "" {
		result += fmt.Sprintf(" (session:%s)", h.Session)
	}
	if h.Admin != nil {
		result += fmt.Sprintf(" (admin:%v)", *h.Admin)
	}
	return result
}

func SprintFiles(files []File) string {
	var shareListResult string

	if len(files) > 0 {
		for _, file := range files {
			// Microsoft handles time as number of 100-nanosecond intervals since January 1, 1601 UTC
			// So to get a timestamp with unix time, subtract difference in 100-nanosecond intervals
			// and divide by 10 to convert to microseconds
			lastWrite := time.Time.Format(file.LastModified, dateTimeFormat)
			fileSize := utils.BytesToHumanReadableSize(file.Size)
			shareListResult += fmt.Sprintf("%-4s  %8s  %-16s  %s\n", file.Type, fileSize, lastWrite, file.Name)
		}
	}
	return shareListResult
}

func SprintDirectories(ip, share string, dirs []Directory) string {
	var shareListResult string

	if len(dirs) > 0 {
		for _, dir := range dirs {
			shareListResult += fmt.Sprintf("Listing directory %s\\%s\\%s\n", ip, share, dir.Name)
			shareListResult += fmt.Sprintf("%-4s  %8s  %-16s  %s\n", "Type", "Size", "LastWriteTime", "ShareName")
			shareListResult += fmt.Sprintf("%-4s  %8s  %-16s  %s\n", "----", "----", "-------------", "----")
			for _, file := range dir.Files {
				lastWrite := time.Time.Format(file.LastModified, dateTimeFormat)
				fileSize := utils.BytesToHumanReadableSize(file.Size)
				shareListResult += fmt.Sprintf("%-4s  %8s  %-16s  %s\n", file.Type, fileSize, lastWrite, file.Name)
			}
			shareListResult += "\n"
		}
	}
	return shareListResult
}

func SprintHost(h Host, exclude []string) string {
	var result string

	result += fmt.Sprintf("\n%-16s %-16s %-16s\n", "Share", "Permissions", "Description")
	result += fmt.Sprintf("%-16s %-16s %-16s\n", strings.Repeat("-", 5), strings.Repeat("-", 11), strings.Repeat("-", 10))

	for _, share := range h.Shares {
		if slices.Contains(exclude, share.ShareName) {
			continue
		}

		var permissions []string
		if share.ReadPermission {
			permissions = append(permissions, "READ")
		}
		if share.WritePermission {
			permissions = append(permissions, "WRITE")
		}

		result += fmt.Sprintf("%-16s %-16s %-16s\n", share.ShareName, strings.Join(permissions, ","), share.Description)
	}
	result += "\n"

	return result
}

func SprintShares(h Host, exclude []string) string {
	var result string

	for _, share := range h.Shares {
		if !share.ReadPermission {
			continue
		}
		if slices.Contains(exclude, share.ShareName) {
			continue
		}

		result += fmt.Sprintf("Listing share %s\\%s\n", h.IP, share.ShareName)
		result += fmt.Sprintf("%-4s  %8s  %-16s  %s\n", "Type", "Size", "LastWriteTime", "ShareName")
		result += fmt.Sprintf("%-4s  %8s  %-16s  %s\n", "----", "----", "-------------", "----")
		result += SprintFiles(share.Files)
		result += "\n"
		result += SprintDirectories(h.IP, share.ShareName, share.Directories)
	}

	return result
}
