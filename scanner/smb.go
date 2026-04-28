package scanner

import (
	"fmt"
	"github.com/jfjallid/go-smb/dcerpc"
	"github.com/jfjallid/go-smb/dcerpc/msrrp"
	"github.com/jfjallid/go-smb/dcerpc/msscmr"
	"github.com/jfjallid/go-smb/dcerpc/mssrvs"
	"github.com/jfjallid/go-smb/dcerpc/smbtransport"
	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/spnego"
	"github.com/vflame6/sharefinder/logger"
	"github.com/vflame6/sharefinder/utils"
	"golang.org/x/net/proxy"
	"io"
	"net"
	"strings"
	"time"
)

type Connection struct {
	host    string
	session *smb.Connection
}

func NewSMBConnection(host DNHost, username, password string, hashes []byte, kerberos, localAuth bool, domain string, timeout time.Duration, smbPort int, proxyDialer proxy.Dialer, dcIP net.IP, nullSession bool, dcHostname string) (*Connection, error) {
	options := GetSMBOptions(host, username, password, hashes, kerberos, localAuth, domain, timeout, smbPort, proxyDialer, dcIP, nullSession, dcHostname)

	// establish the connection
	session, err := smb.NewConnection(options)
	if err != nil {
		return nil, err
	}
	conn := &Connection{
		host:    host.IP.String(),
		session: session,
	}
	return conn, nil
}

func GetSMBOptions(host DNHost, username, password string, hashes []byte, kerberos, localAuth bool, domain string, timeout time.Duration, smbPort int, proxyDialer proxy.Dialer, dcIP net.IP, nullSession bool, dcHostname string) smb.Options {
	smbOptions := smb.Options{
		Host:                  host.IP.String(),
		Port:                  smbPort,
		RequireMessageSigning: false,
		ForceSMB2:             false,
		DialTimeout:           timeout,
		ProxyDialer:           proxyDialer,
	}

	if kerberos {
		hostname := host.Hostname
		if hostname == "" {
			// Kerberos requires a hostname for SPN — attempt reverse DNS lookup
			names, err := net.LookupAddr(host.IP.String())
			if err == nil && len(names) > 0 {
				hostname = strings.TrimSuffix(names[0], ".")
				logger.Debugf("Resolved %s to %s for Kerberos SPN", host.IP.String(), hostname)
			} else if dcHostname != "" && domain != "" {
				// construct FQDN from dc-hostname + domain when target is the DC itself
				hostname = dcHostname + "." + domain
				logger.Debugf("Using DC hostname for SPN: %s", hostname)
			} else {
				logger.Warnf("Kerberos requires a hostname for SPN but target %s has no hostname — use hunt command or specify target as hostname", host.IP.String())
			}
		}
		var dcIPStr string
		if dcIP != nil && !dcIP.Equal(net.IPv4zero) {
			dcIPStr = dcIP.String()
		}
		smbOptions.Initiator = &spnego.KRB5Initiator{
			Domain:      domain,
			User:        username,
			Password:    password,
			Hash:        hashes,
			AESKey:      nil,
			SPN:         "cifs/" + hostname,
			DCIP:        dcIPStr,
			DialTimeout: timeout,
			ProxyDialer: proxyDialer,
			Host:        hostname,
		}
	} else {
		smbOptions.Initiator = &spnego.NTLMInitiator{
			Domain:      domain,
			User:        username,
			Password:    password,
			Hash:        hashes,
			LocalUser:   localAuth,
			NullSession: nullSession,
		}
	}

	return smbOptions
}

// Close is a function to close the active connection
func (conn *Connection) Close() {
	conn.session.Close()
}

func (conn *Connection) GetTargetInfo() *smb.TargetInfo {
	return conn.session.GetTargetInfo()
}

func (conn *Connection) GetSharesList() ([]mssrvs.NetShare, error) {
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
	transport, err := smbtransport.NewSMBTransport(f)
	if err != nil {
		return nil, err
	}
	bind, err := dcerpc.Bind(transport, mssrvs.MSRPCUuidSrvSvc, 3, 0, dcerpc.MSRPCUuidNdr)
	if err != nil {
		return nil, err
	}
	rpccon := mssrvs.NewRPCCon(bind)
	shares, err := rpccon.NetShareEnumAll(conn.host)
	if err != nil {
		return nil, err
	}
	return shares, nil
}

func (conn *Connection) CheckLocalAdmin() (bool, error) {
	share := "IPC$"
	if err := conn.session.TreeConnect(share); err != nil {
		return false, err
	}
	defer conn.session.TreeDisconnect(share)

	f, err := conn.session.OpenFile(share, msscmr.MSRPCSvcCtlPipe)
	if err != nil {
		return false, err
	}
	defer f.CloseFile()

	transport, err := smbtransport.NewSMBTransport(f)
	if err != nil {
		return false, err
	}
	bind, err := dcerpc.Bind(transport, msscmr.MSRPCUuidSvcCtl, 2, 0, dcerpc.MSRPCUuidNdr)
	if err != nil {
		return false, err
	}

	rpccon := msscmr.NewRPCCon(bind)
	req := msscmr.ROpenSCManagerWReq{
		MachineName:   "DUMMY",
		DatabaseName:  "ServicesActive",
		DesiredAccess: msscmr.SCManagerCreateService,
	}
	reqBuf, err := req.MarshalBinary()
	if err != nil {
		return false, err
	}

	buffer, err := rpccon.MakeRequest(msscmr.SvcCtlROpenSCManagerW, reqBuf)
	if err != nil {
		return false, err
	}

	res := msscmr.ROpenSCManagerWRes{}
	if err := res.UnmarshalBinary(buffer); err != nil {
		return false, err
	}

	if res.ReturnCode == msscmr.ErrorSuccess {
		rpccon.CloseServiceHandle(res.ContextHandle[:])
		return true, nil
	}
	if res.ReturnCode == msscmr.ErrorAccessDenied {
		return false, nil
	}
	if status, found := msscmr.ServiceResponseCodeMap[res.ReturnCode]; found {
		return false, status
	}

	return false, fmt.Errorf("unexpected svcctl admin-check return code: 0x%x", res.ReturnCode)
}

func (conn *Connection) DetectWindowsVersion(fallback string) (string, error) {
	share := "IPC$"
	if err := conn.session.TreeConnect(share); err != nil {
		return buildWindowsVersionString("", "", "", "", "", 0, fallback), err
	}
	defer conn.session.TreeDisconnect(share)

	f, err := conn.session.OpenFile(share, msrrp.MSRRPPipe)
	if err != nil {
		return buildWindowsVersionString("", "", "", "", "", 0, fallback), err
	}
	defer f.CloseFile()

	transport, err := smbtransport.NewSMBTransport(f)
	if err != nil {
		return buildWindowsVersionString("", "", "", "", "", 0, fallback), err
	}
	bind, err := dcerpc.Bind(transport, msrrp.MSRRPUuid, msrrp.MSRRPMajorVersion, msrrp.MSRRPMinorVersion, dcerpc.MSRPCUuidNdr)
	if err != nil {
		return buildWindowsVersionString("", "", "", "", "", 0, fallback), err
	}

	rpccon := msrrp.NewRPCCon(bind)
	hklm, err := rpccon.OpenBaseKey(msrrp.HKEYLocalMachine)
	if err != nil {
		return buildWindowsVersionString("", "", "", "", "", 0, fallback), err
	}
	defer rpccon.CloseKeyHandle(hklm)

	currentVersionKey, err := rpccon.OpenSubKey(hklm, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`)
	if err != nil {
		return buildWindowsVersionString("", "", "", "", "", 0, fallback), err
	}
	defer rpccon.CloseKeyHandle(currentVersionKey)

	queryString := func(name string) string {
		value, _, err := rpccon.QueryValueExt(currentVersionKey, name)
		if err != nil {
			return ""
		}
		stringValue, ok := value.(string)
		if !ok {
			return ""
		}
		return strings.TrimSpace(stringValue)
	}
	queryDWORD := func(name string) uint32 {
		value, _, err := rpccon.QueryValueExt(currentVersionKey, name)
		if err != nil {
			return 0
		}
		dwordValue, ok := value.(uint32)
		if !ok {
			return 0
		}
		return dwordValue
	}

	return buildWindowsVersionString(
		queryString("ProductName"),
		queryString("DisplayVersion"),
		queryString("ReleaseId"),
		queryString("CurrentVersion"),
		queryString("CurrentBuildNumber"),
		queryDWORD("UBR"),
		fallback,
	), nil
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
	if err := conn.session.TreeConnect(share); err != nil {
		return false
	}
	defer conn.session.TreeDisconnect(share)

	// Try a file first, then fall back to a directory: NTFS ACLs can grant
	// AddSubdirectory without AddFile (or vice versa), so a single probe can
	// miss real write access.
	tempFile := utils.RandSeq(16) + ".txt"
	tempData := utils.RandSeq(32)
	dataSent := false
	err := conn.session.PutFile(share, tempFile, 0, func(buffer []byte) (int, error) {
		if dataSent {
			return 0, io.EOF
		}
		copy(buffer, tempData)
		dataSent = true
		return len(tempData), nil
	})
	if err == nil {
		if delErr := conn.session.DeleteFile(share, tempFile); delErr != nil {
			logger.Error(fmt.Errorf("failed to delete created file %s on share %s\\%s: %w", tempFile, conn.host, share, delErr))
		}
		return true
	}

	tempDir := utils.RandSeq(16)
	if err := conn.session.MkdirAll(share, tempDir); err == nil {
		if delErr := conn.session.DeleteDir(share, tempDir); delErr != nil {
			logger.Error(fmt.Errorf("failed to delete created directory %s on share %s\\%s: %w", tempDir, conn.host, share, delErr))
		}
		return true
	}

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
	err := conn.session.TreeConnect(share)
	if err != nil {
		return nil, err
	}
	defer conn.session.TreeDisconnect(share)

	return conn.listDirectoryRecursivelyInternal(share, dir)
}

func (conn *Connection) listDirectoryRecursivelyInternal(share string, dir smb.SharedFile) ([]Directory, error) {
	var result []Directory
	var currentFiles []File

	lastWriteTime := utils.ConvertToUnixTimestamp(dir.LastWriteTime)
	currentDir := NewDirectory(
		dir.FullPath,
		dir.Size,
		lastWriteTime,
		currentFiles,
	)

	// process current directory
	files, err := conn.session.ListDirectory(share, dir.FullPath, "*")
	if err != nil {
		return nil, err
	}

	// loop over all files 2 times to process directories at first
	// it is done like that to make directories in the top of the output
	for _, file := range files {
		if file.IsDir {
			lastWriteTime = utils.ConvertToUnixTimestamp(file.LastWriteTime)

			fileType := "dir"
			singleFile := NewFile(fileType, file.Name, utils.GetFilePath(file.FullPath), file.Size, lastWriteTime)
			currentDir.Files = append(currentDir.Files, *singleFile)
		} else {
			continue
		}
	}
	// process files
	for _, file := range files {
		if !file.IsDir {
			lastWriteTime = utils.ConvertToUnixTimestamp(file.LastWriteTime)
			fileType := "file"
			if file.IsJunction {
				fileType = "link"
			}
			singleFile := NewFile(fileType, file.Name, utils.GetFilePath(file.FullPath), file.Size, lastWriteTime)
			currentDir.Files = append(currentDir.Files, *singleFile)
		} else {
			continue
		}
	}

	result = append(result, *currentDir)

	// loop over all files to list all nested directories recursively
	for _, file := range files {
		if file.IsDir {
			recurseDirectory, err := conn.listDirectoryRecursivelyInternal(share, file)
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
