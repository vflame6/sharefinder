package scanner

import (
	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/dcerpc"
	"github.com/jfjallid/go-smb/spnego"
	"io"
	"log"
	"time"
)

// TODO: implement Windows versions check
//const ()
//
//var (
//	fileSizeThreshold = uint64(0)
//)

type Connection struct {
	host    string
	session *smb.Connection
}

func NewNTLMConnection(host, username, password, domain string, timeout time.Duration, smbPort int) (*Connection, error) {
	options := smb.Options{
		Host: host,
		Port: smbPort,
		Initiator: &spnego.NTLMInitiator{
			User:     username,
			Password: password,
			Domain:   domain,
		},
		DialTimeout: timeout,
	}
	session, err := smb.NewConnection(options)
	if err != nil {
		return nil, err
	}
	conn := &Connection{
		host:    host,
		session: session,
	}
	return conn, nil
}

func (conn *Connection) Close() {
	conn.session.Close()
}

func (conn *Connection) GetTargetInfo() *smb.TargetInfo {
	return conn.session.GetTargetInfo()
}

// TODO: implement Guest check
// func CheckGuest() bool {}

// TODO: implement admin check - https://github.com/Pennyw0rth/NetExec/blob/91c339ea30bc87118fefa8236cb86a95c1717643/nxc/protocols/smb.py#L637
//func CheckAdmin(session *smb.Connection) bool {
//	return false
//}

func (conn *Connection) ListShares() ([]dcerpc.NetShare, error) {
	share := "IPC$"
	err := conn.session.TreeConnect(share)
	if err != nil {
		return nil, err
	}
	defer conn.session.TreeDisconnect(share)
	f, err := conn.session.OpenFile(share, "srvsvc")
	if err != nil {
		return nil, err
	}
	defer f.CloseFile()
	bind, err := dcerpc.Bind(f, dcerpc.MSRPCUuidSrvSvc, 3, 0, dcerpc.MSRPCUuidNdr)
	if err != nil {
		return nil, err
	}
	shares, err := bind.NetShareEnumAll(conn.host)
	if err != nil {
		return nil, err
	}
	return shares, nil
}

func (conn *Connection) CheckReadAccess(share string) error {
	conn.session.TreeConnect(share)
	defer conn.session.TreeDisconnect(share)

	_, err := conn.session.ListShare(share, "", false)
	return err
}

func (conn *Connection) CheckWriteAccess(share string) bool {
	tempFile := RandSeq(16) + ".txt"
	tempData := RandSeq(32)
	//tempDir := RandSeq(16)
	conn.session.TreeConnect(share)
	defer conn.session.TreeDisconnect(share)

	// try to write a file
	dataSent := false // Track if data has been sent
	err := conn.session.PutFile(share, tempFile, 0, func(buffer []byte) (int, error) {
		if dataSent {
			return 0, io.EOF // Indicate end of file
		}
		copy(buffer, tempData) // Copy data into buffer
		dataSent = true        // Mark as sent
		return len(tempData), nil
	})
	if err == nil {
		err = conn.session.DeleteFile(share, tempFile)
		if err != nil {
			log.Printf("[!] Failed to delete created file %s on share %s\\%s", tempFile, conn.host, share)
		}
		return true
	}

	// TODO: review why it works bad. The library outputs error 0xc0000061 and I can't get it silent
	// if failed to create a file, try create a directory
	//err = conn.session.MkdirAll(share, tempDir)
	//if err == nil {
	//	err = conn.session.DeleteDir(share, tempDir)
	//	if err != nil {
	//		log.Printf("[!] Failed to delete created directory %s on share %s\\%s", tempDir, conn.host, share)
	//	}
	//	return true
	//}

	return false
}

func (conn *Connection) ListShare(share string) ([]smb.SharedFile, error) {
	// Connect to share
	err := conn.session.TreeConnect(share)
	if err != nil {
		return nil, err
	}
	defer conn.session.TreeDisconnect(share)

	files, err := conn.session.ListDirectory(share, "", "")
	if err != nil {
		return nil, err
	}
	return files, nil
}

func (conn *Connection) ListDirectoryRecursively(share string, dir smb.SharedFile) ([]Directory, error) {
	var result []Directory
	var currentFiles []File
	lastWriteTime := time.UnixMicro(int64((dir.LastWriteTime - 116444736000000000) / 10))

	currentDir := NewDirectory(
		dir.FullPath,
		dir.Size,
		lastWriteTime,
		currentFiles,
	)

	conn.session.TreeConnect(share)
	defer conn.session.TreeDisconnect(share)

	files, err := conn.session.ListDirectory(share, dir.FullPath, "*")
	if err != nil {
		return nil, err
	}

	// process current directory
	for _, file := range files {
		if file.IsDir {
			lastWriteTime := time.UnixMicro(int64((file.LastWriteTime - 116444736000000000) / 10))

			fileType := "dir"
			singleFile := NewFile(fileType, file.Name, file.Size, lastWriteTime)
			currentDir.Files = append(currentDir.Files, *singleFile)
		} else {
			continue
		}
	}

	for _, file := range files {
		if !file.IsDir {
			lastWriteTime := time.UnixMicro(int64((file.LastWriteTime - 116444736000000000) / 10))
			fileType := "file"
			if file.IsJunction {
				fileType = "link"
			}
			singleFile := NewFile(fileType, file.Name, file.Size, lastWriteTime)
			currentDir.Files = append(currentDir.Files, *singleFile)
		} else {
			continue
		}
	}

	result = append(result, *currentDir)

	// recurse all directories
	for _, file := range files {
		if file.IsDir {
			recurseDirectory, err := conn.ListDirectoryRecursively(share, file)
			if err != nil {
				log.Printf("Failed to list directory %s\\%s\\%s: %s\n", conn.host, share, file.Name, err)
			}
			result = append(result, recurseDirectory...)
		} else {
			continue
		}
	}

	return result, nil
}
