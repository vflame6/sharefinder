package scanner

import (
	"fmt"
	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/spnego"
	"time"
)

var (
	fileSizeThreshold = uint64(0)
)

func GetNTLMOptions(host, username, password, domain string) smb.Options {
	smbOptions := smb.Options{
		Host: host,
		Port: 445,
		Initiator: &spnego.NTLMInitiator{
			User:     username,
			Password: password,
			Domain:   domain,
		},
	}
	return smbOptions
}

func GetSession(options smb.Options) (*smb.Connection, error) {
	session, err := smb.NewConnection(options)
	if err != nil {
		return nil, err
	}
	return session, nil
}

//func GetShares() {
//
//}
//

func listShare(session *smb.Connection, share string, recurse bool) error {
	fmt.Printf("Attempting to open share: %s and list content\n", share)
	// Connect to share
	err := session.TreeConnect(share)
	if err != nil {
		if err == smb.StatusMap[smb.StatusBadNetworkName] {
			fmt.Printf("Share %s can not be found!\n", share)
			return err
		}
		return err
	}
	files, err := session.ListDirectory(share, "", "")
	if err != nil {
		if err == smb.StatusMap[smb.StatusAccessDenied] {
			session.TreeDisconnect(share)
			fmt.Printf("Could connect to [%s] but listing files was prohibited\n", share)
			return err
		}

		session.TreeDisconnect(share)
		return err
	}

	fmt.Printf("\n#### Listing files for share (%s) ####\n", share)
	printFilesExt(files)
	if recurse {
		for _, file := range files {
			if file.IsDir && !file.IsJunction {
				err = listFilesRecursively(session, share, file.Name, file.FullPath)
				if err != nil {
					session.TreeDisconnect(share)
					return err
				}
			}
		}
	}
	session.TreeDisconnect(share)
	return nil
}

func printFilesExt(files []smb.SharedFile) {
	if len(files) > 0 {
		for _, file := range files {
			fileType := "file"
			if file.IsDir {
				fileType = "dir"
			} else if file.IsJunction {
				fileType = "link"
			}
			if (fileType == "file") && (file.Size < fileSizeThreshold) {
				// Skip displaying file
				continue
			}
			// Microsoft handles time as number of 100-nanosecond intervals since January 1, 1601 UTC
			// So to get a timestamp with unix time, subtract difference in 100-nanosecond intervals
			// and divide by 10 to convert to microseconds
			lastWriteTime := time.UnixMicro(int64((file.LastWriteTime - 116444736000000000) / 10))
			lastWrite := lastWriteTime.Format("Mon Jan 2 15:04:05 MST 2006")
			fmt.Printf("%-4s  %10d  %-30s  %s\n", fileType, file.Size, lastWrite, file.Name)
		}
	}
	fmt.Println()
}

func listFilesRecursively(session *smb.Connection, share, parent, dir string) error {
	parent = fmt.Sprintf("%s\\%s", share, parent)
	files, err := session.ListDirectory(share, dir, "*")
	if err != nil {
		fmt.Printf("Failed to list files in directory (%s) with error: %s\n", dir, err)
		return nil
	}

	if len(files) == 0 {
		return nil
	}

	fmt.Printf("%s:\n", parent)
	printFilesExt(files)

	for _, file := range files {
		if file.IsDir && !file.IsJunction {
			// Check if folder is filtered
			err = listFilesRecursively(session, share, file.FullPath, file.FullPath)
			if err != nil {
				return err
			}
		}
	}
	return nil
}
