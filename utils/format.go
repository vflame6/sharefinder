package utils

import (
	"fmt"
	"github.com/jfjallid/go-smb/smb"
	"math/rand"
	"time"
)

var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

// func SPrintPermissionsTable() {
//
// }
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
			lastWrite := lastWriteTime.Format("Mon Jan 2 15:04:05 MST 2006")
			shareListResult += fmt.Sprintf("%-4s  %10d  %-30s  %s\n", fileType, file.Size, lastWrite, file.Name)
		}
	}
	return shareListResult
}
