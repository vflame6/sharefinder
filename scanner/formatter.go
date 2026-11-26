package scanner

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/vflame6/sharefinder/utils"
)

var (
	dateTimeFormat        = "02/01/2006 15:04"
	dateTimeSecondsFormat = "02/01/2006 15:04:05"
)

// SprintHostLine formats the one-line summary of a scanned host. The session
// type and admin status are left out when unknown.
func SprintHostLine(h Host) string {
	result := fmt.Sprintf("[+] %s: %s (name:%s) (domain:%s) (signing:%v)", h.IP, printable(h.Version), printable(h.Hostname), printable(h.Domain), h.Signing)
	if h.Session != "" {
		result += fmt.Sprintf(" (session:%s)", h.Session)
	}
	if h.Admin != nil {
		result += fmt.Sprintf(" (admin:%v)", *h.Admin)
	}
	return result
}

// listingRow is the layout of one listing line.
const listingRow = "%-4s  %8s  %-16s  %s\n"

// writeListingHeader writes the column header of a file listing.
func writeListingHeader(b *strings.Builder) {
	fmt.Fprintf(b, listingRow, "Type", "Size", "LastWriteTime", "Name")
	fmt.Fprintf(b, listingRow, "----", "----", "-------------", "----")
}

// writeFiles writes one listing line per file.
func writeFiles(b *strings.Builder, files []File) {
	for _, file := range files {
		lastWrite := file.LastModified.Format(dateTimeFormat)
		fmt.Fprintf(b, listingRow, file.Type, utils.BytesToHumanReadableSize(file.Size), lastWrite, printable(file.Name))
	}
}

// SprintFiles formats a file listing. It runs in linear time: 80,000 files
// used to take over a minute with string concatenation.
func SprintFiles(files []File) string {
	var b strings.Builder
	b.Grow(len(files) * 64)
	writeFiles(&b, files)
	return b.String()
}

// SprintDirectories formats the listing of each directory.
func SprintDirectories(ip, share string, dirs []Directory) string {
	var b strings.Builder
	writeDirectories(&b, ip, share, dirs)
	return b.String()
}

func writeDirectories(b *strings.Builder, ip, share string, dirs []Directory) {
	for _, dir := range dirs {
		fmt.Fprintf(b, "Listing directory %s\\%s\\%s\n", ip, share, dir.Name)
		writeListingHeader(b)
		writeFiles(b, dir.Files)
		b.WriteString("\n")
	}
}

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

// SprintHost formats the share table of a host.
func SprintHost(h Host, exclude []string) string {
	// widen the permissions column for labels such as WRITE (SUBDIR)
	width := 16
	for _, share := range h.Shares {
		if n := len(sharePermissions(share)); n > width {
			width = n
		}
	}
	row := "%-16s %-" + strconv.Itoa(width) + "s %-16s\n"

	var b strings.Builder
	b.WriteString("\n")
	fmt.Fprintf(&b, row, "Share", "Permissions", "Description")
	fmt.Fprintf(&b, row, strings.Repeat("-", 5), strings.Repeat("-", 11), strings.Repeat("-", 10))
	for _, share := range h.Shares {
		if slices.Contains(exclude, share.ShareName) {
			continue
		}
		fmt.Fprintf(&b, row, printable(share.ShareName), sharePermissions(share), printable(share.Description))
	}
	b.WriteString("\n")
	return b.String()
}

// SprintShares formats the listings of the readable shares of a host.
func SprintShares(h Host, exclude []string) string {
	var b strings.Builder
	for _, share := range h.Shares {
		if !share.ReadPermission || slices.Contains(exclude, share.ShareName) {
			continue
		}
		fmt.Fprintf(&b, "Listing share %s\\%s\n", h.IP, share.ShareName)
		writeListingHeader(&b)
		writeFiles(&b, share.Files)
		b.WriteString("\n")
		writeDirectories(&b, h.IP, share.ShareName, share.Directories)
	}
	return b.String()
}
