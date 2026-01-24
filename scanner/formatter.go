package scanner

import (
	"fmt"
	"math"
	"math/rand"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"
)

var (
	letters               = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	dateTimeFormat        = "02/01/2006 15:04"
	dateTimeSecondsFormat = "02/01/2006 15:04:05"
)

func logn(n, b float64) float64 {
	return math.Log(n) / math.Log(b)
}

func BytesToHumanReadableSize(s uint64) string {
	base := float64(1000)
	sizes := []string{"B", "kB", "MB", "GB", "TB", "PB", "EB"}

	if s < 10 {
		return fmt.Sprintf("%d B", s)
	}
	e := math.Floor(logn(float64(s), base))
	suffix := sizes[int(e)]
	val := math.Floor(float64(s)/math.Pow(base, e)*10+0.5) / 10
	f := "%.0f %s"
	if val < 10 {
		f = "%.1f %s"
	}

	return fmt.Sprintf(f, val, suffix)
}

func SPrintHostInfo(host, version, hostname, domain string, signing bool) string {
	return fmt.Sprintf("[+] %s: %s (name:%s) (domain:%s) (signing:%v)", host, version, hostname, domain, signing)
}

func RandSeq(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func SprintFiles(files []File) string {
	var shareListResult string

	if len(files) > 0 {
		for _, file := range files {
			// Microsoft handles time as number of 100-nanosecond intervals since January 1, 1601 UTC
			// So to get a timestamp with unix time, subtract difference in 100-nanosecond intervals
			// and divide by 10 to convert to microseconds
			lastWrite := time.Time.Format(file.LastModified, dateTimeFormat)
			fileSize := BytesToHumanReadableSize(file.Size)
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
				fileSize := BytesToHumanReadableSize(file.Size)
				shareListResult += fmt.Sprintf("%-4s  %8s  %-16s  %s\n", file.Type, fileSize, lastWrite, file.Name)
			}
			shareListResult += "\n"
		}
	}
	return shareListResult
}

func SprintHost(h Host, exclude []string) string {
	var result string

	result += fmt.Sprintf("\n%-16s %-16s %-16s\n", "Share", "Permissions", "Decription")
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

// ParseIPOrCIDR parses a string input and returns an array of valid IP addresses.
func ParseIPOrCIDR(input string) ([]string, error) {
	if strings.Contains(input, "-") {
		return parseIPRange(input)
	}

	ip := net.ParseIP(input)
	if ip != nil {
		return []string{ip.String()}, nil
	}

	_, ipNet, err := net.ParseCIDR(input)
	if err != nil {
		return nil, fmt.Errorf("invalid IP, CIDR, or range format: %s", input)
	}

	var ips []string
	for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); incrementIP(ip) {
		if isNetworkOrBroadcast(ip, ipNet) {
			continue
		}
		ips = append(ips, ip.String())
	}

	return ips, nil
}

// parseIPRange handles IP range inputs like "192.168.0.1-10"
func parseIPRange(input string) ([]string, error) {
	parts := strings.Split(input, "-")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid range format: %s", input)
	}

	baseIP := net.ParseIP(parts[0])
	if baseIP == nil {
		return nil, fmt.Errorf("invalid IP address in range: %s", parts[0])
	}

	lastOctet, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid range end: %s", parts[1])
	}

	octets := strings.Split(parts[0], ".")
	if len(octets) != 4 {
		return nil, fmt.Errorf("invalid IPv4 format: %s", parts[0])
	}

	startOctet, err := strconv.Atoi(octets[3])
	if err != nil {
		return nil, fmt.Errorf("invalid start octet: %s", octets[3])
	}

	if lastOctet < startOctet || lastOctet > 255 {
		return nil, fmt.Errorf("invalid range: %d-%d", startOctet, lastOctet)
	}

	var ips []string
	for i := startOctet; i <= lastOctet; i++ {
		octets[3] = strconv.Itoa(i)
		ips = append(ips, strings.Join(octets, "."))
	}

	return ips, nil
}

// incrementIP increases the IP address by one.
func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] != 0 {
			break
		}
	}
}

// isNetworkOrBroadcast checks if an IP is a network or broadcast address.
func isNetworkOrBroadcast(ip net.IP, ipNet *net.IPNet) bool {
	if ip.Equal(ipNet.IP) {
		return true // Network address
	}

	broadcast := make(net.IP, len(ip))
	copy(broadcast, ipNet.IP)
	for i := range broadcast {
		broadcast[i] |= ^ipNet.Mask[i]
	}

	if ip.Equal(broadcast) {
		return true // Broadcast address
	}

	return false
}

// ConvertToUnixTimestamp is a function to convert Microsoft's timestamp value to Unix one
func ConvertToUnixTimestamp(timestamp uint64) time.Time {
	// Microsoft handles time as number of 100-nanosecond intervals since January 1, 1601 UTC
	// So to get a timestamp with unix time, subtract difference in 100-nanosecond intervals
	// and divide by 10 to convert to microseconds
	return time.UnixMicro(int64((timestamp - 116444736000000000) / 10))
}

func GetFilePath(fullpath string) string {
	separator := "\\"

	// 1. Split the string by the separator
	parts := strings.Split(fullpath, separator)

	if len(parts) > 1 {
		// 2. Slice the array to exclude the last element
		// The slicing operation `[:len(parts)-1]` creates a new slice
		// from the start (index 0) up to, but not including, the last element.
		partsWithoutLast := parts[:len(parts)-1]

		// 3. Join the remaining parts back into a single string using the same separator
		return strings.Join(partsWithoutLast, separator)
	} else {
		return ""
	}
}
