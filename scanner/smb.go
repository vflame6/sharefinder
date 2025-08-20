package scanner

import (
	"fmt"
	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/dcerpc"
	"github.com/jfjallid/go-smb/spnego"
	"github.com/vflame6/sharefinder/logger"
	"golang.org/x/net/proxy"
	"io"
	"time"
)

type Connection struct {
	host    string
	session *smb.Connection
}

func NewNTLMConnection(host, username, password, hash, domain string, timeout time.Duration, smbPort int, proxyOption bool, proxyDialer proxy.Dialer) (*Connection, error) {
	options := GetSMBOptions(host, username, password, hash, domain, timeout, smbPort, proxyOption, proxyDialer)

	// establish the connection
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

func GetSMBOptions(host, username, password, hash, domain string, timeout time.Duration, smbPort int, proxyOption bool, proxyDialer proxy.Dialer) smb.Options {
	var options smb.Options
	var initiator *spnego.NTLMInitiator

	// check if password or hash is provided
	// hash will be preferred if it is not empty
	// if both are empty, then password is used
	if hash != "" {
		initiator = &spnego.NTLMInitiator{
			User:   username,
			Hash:   []byte(hash),
			Domain: domain,
		}
	} else {
		initiator = &spnego.NTLMInitiator{
			User:     username,
			Password: password,
			Domain:   domain,
		}
	}

	// set up a proxy if enabled
	if proxyOption {
		options = smb.Options{
			Host:        host,
			Port:        smbPort,
			Initiator:   initiator,
			DialTimeout: timeout,
			ProxyDialer: proxyDialer,
		}
	} else {
		options = smb.Options{
			Host:        host,
			Port:        smbPort,
			Initiator:   initiator,
			DialTimeout: timeout,
		}
	}
	return options
}

// Close is a function to close the active connection
func (conn *Connection) Close() {
	conn.session.Close()
}

func (conn *Connection) GetTargetInfo() *smb.TargetInfo {
	return conn.session.GetTargetInfo()
}

func (conn *Connection) GetSharesList() ([]dcerpc.NetShare, error) {
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
	err := conn.session.TreeConnect(share)
	if err != nil {
		return err
	}
	defer conn.session.TreeDisconnect(share)

	_, err = conn.session.ListShare(share, "", false)
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
			logger.Error(fmt.Errorf("failed to delete created file %s on share %s\\%s", tempFile, conn.host, share))
		}
		return true
	}

	// TODO: review why it works bad. The library outputs error 0xc0000061 and I can't get it silent
	// if failed to create a file, try create a directory
	//err = conn.session.MkdirAll(share, tempDir)
	//if err == nil {
	//	err = conn.session.DeleteDir(share, tempDir)
	//	if err != nil {
	//		logger.Error(fmt.Errorf("[!] Failed to delete created directory %s on share %s\\%s", tempDir, conn.host, share))
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

	lastWriteTime := ConvertToUnixTimestamp(dir.LastWriteTime)
	currentDir := NewDirectory(
		dir.FullPath,
		dir.Size,
		lastWriteTime,
		currentFiles,
	)

	err := conn.session.TreeConnect(share)
	if err != nil {
		return nil, err
	}
	defer conn.session.TreeDisconnect(share)

	// process current directory
	files, err := conn.session.ListDirectory(share, dir.FullPath, "*")
	if err != nil {
		return nil, err
	}

	// loop over all files 2 times to process directories at first
	// it is done like that to make directories in the top of the output
	for _, file := range files {
		if file.IsDir {
			lastWriteTime = ConvertToUnixTimestamp(file.LastWriteTime)

			fileType := "dir"
			singleFile := NewFile(fileType, file.Name, file.FullPath, file.Size, lastWriteTime)
			currentDir.Files = append(currentDir.Files, *singleFile)
		} else {
			continue
		}
	}
	// process files
	for _, file := range files {
		if !file.IsDir {
			lastWriteTime = ConvertToUnixTimestamp(file.LastWriteTime)
			fileType := "file"
			if file.IsJunction {
				fileType = "link"
			}
			singleFile := NewFile(fileType, file.Name, file.FullPath, file.Size, lastWriteTime)
			currentDir.Files = append(currentDir.Files, *singleFile)
		} else {
			continue
		}
	}

	result = append(result, *currentDir)

	// loop over all files to list all nested directories recursively
	for _, file := range files {
		if file.IsDir {
			recurseDirectory, err := conn.ListDirectoryRecursively(share, file)
			if err != nil {
				logger.Error(fmt.Errorf("Failed to list directory %s\\%s\\%s: %s\n", conn.host, share, file.Name, err))
			}
			result = append(result, recurseDirectory...)
		} else {
			continue
		}
	}

	return result, nil
}
