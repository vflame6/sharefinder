package utils

import (
	"fmt"
	"github.com/jfjallid/go-smb/smb"
	"math"
	"math/rand"
	"time"
)

var (
	letters        = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	dateTimeFormat = "02/01/2006 15:04"
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

func SPrintHostInfo(host, version, hostname, domain string, signing, smbv1 bool) string {
	return fmt.Sprintf("[+] %s: %s (name:%s) (domain:%s) (signing:%v) (SMBv1:%v)\n", host, version, hostname, domain, signing, smbv1)
}

func RandSeq(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func SprintFilesExt(files []smb.SharedFile) string {
	var shareListResult string

	if len(files) > 0 {
		shareListResult += fmt.Sprintf("%-4s  %8s  %-16s  %s\n", "Type", "Size", "LastWriteTime", "Name")
		shareListResult += fmt.Sprintf("%-4s  %8s  %-16s  %s\n", "----", "----", "-------------", "----")
		for _, file := range files {
			fileType := "file"
			if file.IsDir {
				fileType = "dir"
			} else if file.IsJunction {
				fileType = "link"
			}
			// Microsoft handles time as number of 100-nanosecond intervals since January 1, 1601 UTC
			// So to get a timestamp with unix time, subtract difference in 100-nanosecond intervals
			// and divide by 10 to convert to microseconds
			lastWriteTime := time.UnixMicro(int64((file.LastWriteTime - 116444736000000000) / 10))
			lastWrite := lastWriteTime.Format(dateTimeFormat)
			fileSize := BytesToHumanReadableSize(file.Size)
			shareListResult += fmt.Sprintf("%-4s  %8s  %-16s  %s\n", fileType, fileSize, lastWrite, file.Name)
		}
	}
	return shareListResult
}
