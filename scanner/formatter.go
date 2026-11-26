package scanner

import (
	"fmt"
	"slices"
	"strconv"
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
			shareListResult += fmt.Sprintf("%-4s  %8s  %-16s  %s\n", "Type", "Size", "LastWriteTime", "Name")
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

// sharePermissions renders a share's access as READ plus its write labels.
func sharePermissions(share Share) string {
	var permissions []string
	if share.ReadPermission {
		permissions = append(permissions, "READ")
	}
	switch {
	case share.WriteAccess != "":
		permissions = append(permissions, share.WriteAccess)
	case share.WritePermission:
		permissions = append(permissions, WriteLabel)
	}
	return strings.Join(permissions, ",")
}

func SprintHost(h Host, exclude []string) string {
	var result string

	// widen the permissions column for labels such as WRITE (SUBDIR)
	width := 16
	for _, share := range h.Shares {
		if n := len(sharePermissions(share)); n > width {
			width = n
		}
	}
	row := "%-16s %-" + strconv.Itoa(width) + "s %-16s\n"

	result += fmt.Sprintf("\n"+row, "Share", "Permissions", "Description")
	result += fmt.Sprintf(row, strings.Repeat("-", 5), strings.Repeat("-", 11), strings.Repeat("-", 10))

	for _, share := range h.Shares {
		if slices.Contains(exclude, share.ShareName) {
			continue
		}
		result += fmt.Sprintf(row, share.ShareName, sharePermissions(share), share.Description)
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
		result += fmt.Sprintf("%-4s  %8s  %-16s  %s\n", "Type", "Size", "LastWriteTime", "Name")
		result += fmt.Sprintf("%-4s  %8s  %-16s  %s\n", "----", "----", "-------------", "----")
		result += SprintFiles(share.Files)
		result += "\n"
		result += SprintDirectories(h.IP, share.ShareName, share.Directories)
	}

	return result
}
