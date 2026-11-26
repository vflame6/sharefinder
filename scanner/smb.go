package scanner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jfjallid/go-smb/dcerpc"
	"github.com/jfjallid/go-smb/dcerpc/msrrp"
	"github.com/jfjallid/go-smb/dcerpc/msscmr"
	"github.com/jfjallid/go-smb/dcerpc/mssrvs"
	"github.com/jfjallid/go-smb/dcerpc/smbtransport"
	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/spnego"
	"github.com/vflame6/sharefinder/logger"
)

type Connection struct {
	host    string
	session *smb.Connection
	// SessionType is "user", "guest" or "null": what the server granted.
	SessionType string
}

func logCloseError(action string, err error) {
	if err != nil {
		logger.Debugf("%s: %v", action, err)
	}
}

// NewSMBConnection dials host through o.Dialer, negotiates SMB and
// authenticates with the credentials in o. With real credentials the session
// setup, the only step that sends them, runs under o.AuthGuard so a wrong
// password cannot reach every target. Errors are *StageError values.
func NewSMBConnection(ctx context.Context, host DNHost, o *Options) (*Connection, error) {
	options := GetSMBOptions(ctx, host, o)
	options.ManualLogin = true

	// dial and negotiate; no credentials are sent yet. A host whose port
	// answers but does not negotiate SMB2 is reported, not taken for
	// unreachable.
	negotiate := func() (sessionConn, error) {
		opts, dialer := options, &dialRecorder{Dialer: o.Dialer}
		if o.Dialer != nil {
			opts.ProxyDialer = dialer
		}
		session, err := smb.NewConnection(opts)
		if err != nil {
			if session != nil {
				// go-smb hands back a half-open connection on error
				session.Close()
			}
			stage := StageConnect
			if dialer.connected.Load() {
				stage = StageNegotiate
			}
			return nil, &StageError{Stage: stage, Host: host.Address(), Err: err}
		}
		return smbSession{session}, nil
	}
	first, err := negotiate()
	if err != nil {
		return nil, err
	}

	// a connection that waits at the auth guard for half the I/O timeout may
	// be closed by its read deadline: negotiate again before logging on
	session := &freshSession{conn: first, ready: time.Now(), maxIdle: o.IOTimeout / 2, redial: negotiate, host: host.Address()}
	sessionType, err := establishSession(ctx, session, o.Mode, o.AuthGuard, host.Address(), accountScope{Domain: o.Domain, LocalAuth: o.LocalAuth})
	if err != nil {
		session.Close()
		return nil, err
	}

	conn := &Connection{
		host:        host.Address(),
		session:     session.conn.(smbSession).Connection,
		SessionType: sessionType,
	}
	return conn, nil
}

// dialRecorder notes that the TCP connection was made, so a failure after it
// (the port answered, SMB negotiation failed) is told apart from an
// unreachable host.
type dialRecorder struct {
	*Dialer
	connected atomic.Bool
}

func (d *dialRecorder) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

func (d *dialRecorder) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	conn, err := d.Dialer.DialContext(ctx, network, address)
	if err == nil {
		d.connected.Store(true)
	}
	return conn, err
}

// GetSMBOptions builds the go-smb options for host from the scanner options.
// Every connection goes through o.Dialer so that it carries the I/O timeout
// and can be closed when the scan is cancelled.
func GetSMBOptions(ctx context.Context, host DNHost, o *Options) smb.Options {
	smbOptions := smb.Options{
		Host:                  host.Address(),
		Port:                  o.SmbPort,
		RequireMessageSigning: false,
		DialTimeout:           o.Timeout,
		ProxyDialer:           o.Dialer,
	}

	if o.Kerberos {
		hostname := host.Hostname
		if hostname == "" {
			// Kerberos requires a hostname for SPN — attempt reverse DNS lookup
			names, err := net.DefaultResolver.LookupAddr(ctx, host.Address())
			if err == nil && len(names) > 0 {
				hostname = strings.TrimSuffix(names[0], ".")
				logger.Debugf("Resolved %s to %s for Kerberos SPN", host.Address(), hostname)
			} else if o.DCHostname != "" && o.Domain != "" {
				// construct FQDN from dc-hostname + domain when target is the DC itself
				hostname = o.DCHostname + "." + o.Domain
				logger.Debugf("Using DC hostname for SPN: %s", hostname)
			} else {
				logger.Warnf("Kerberos requires a hostname for SPN but target %s has no hostname — use hunt command or specify target as hostname", host.Address())
			}
		}
		var dcIPStr string
		if o.DomainController != nil && !o.DomainController.Equal(net.IPv4zero) {
			dcIPStr = o.DomainController.String()
		}
		initiator := &spnego.KRB5Initiator{
			Domain:      o.Domain,
			User:        o.Username,
			Password:    o.Password,
			Hash:        o.HashBytes,
			AESKey:      nil,
			SPN:         "cifs/" + hostname,
			DCIP:        dcIPStr,
			DialTimeout: o.Timeout,
			Host:        hostname,
		}
		// The KDC is reached through the SOCKS proxy only when one is set.
		if o.Dialer.Proxied() {
			initiator.ProxyDialer = o.Dialer
		}
		smbOptions.Initiator = initiator
	} else {
		smbOptions.Initiator = &spnego.NTLMInitiator{
			Domain:      o.Domain,
			User:        o.Username,
			Password:    o.Password,
			Hash:        o.HashBytes,
			LocalUser:   o.LocalAuth,
			NullSession: o.NullSession,
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
	defer func() {
		logCloseError("failed to disconnect tree "+share, conn.session.TreeDisconnect(share))
	}()
	f, err := conn.session.OpenFile(share, "srvsvc")
	if err != nil {
		return nil, err
	}
	defer func() {
		logCloseError("failed to close srvsvc pipe", f.CloseFile())
	}()
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
	defer func() {
		logCloseError("failed to disconnect tree "+share, conn.session.TreeDisconnect(share))
	}()

	f, err := conn.session.OpenFile(share, msscmr.MSRPCSvcCtlPipe)
	if err != nil {
		return false, err
	}
	defer func() {
		logCloseError("failed to close svcctl pipe", f.CloseFile())
	}()

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
	reqBuf, err := req.Marshal()
	if err != nil {
		return false, err
	}

	buffer, err := rpccon.MakeRequest(msscmr.SvcCtlROpenSCManagerW, reqBuf)
	if err != nil {
		return false, err
	}

	res := msscmr.ROpenSCManagerWRes{}
	if err := res.Unmarshal(buffer); err != nil {
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
	defer func() {
		logCloseError("failed to disconnect tree "+share, conn.session.TreeDisconnect(share))
	}()

	f, err := conn.session.OpenFile(share, msrrp.MSRRPPipe)
	if err != nil {
		return buildWindowsVersionString("", "", "", "", "", 0, fallback), err
	}
	defer func() {
		logCloseError("failed to close winreg pipe", f.CloseFile())
	}()

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
	defer func() {
		logCloseError("failed to close hklm key handle", rpccon.CloseKeyHandle(hklm))
	}()

	currentVersionKey, err := rpccon.OpenSubKey(hklm, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`)
	if err != nil {
		return buildWindowsVersionString("", "", "", "", "", 0, fallback), err
	}
	defer func() {
		logCloseError("failed to close current version key handle", rpccon.CloseKeyHandle(currentVersionKey))
	}()

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
	defer func() {
		logCloseError("failed to disconnect tree "+share, conn.session.TreeDisconnect(share))
	}()

	_, err = conn.session.ListShare(share, "", false)
	return err
}

// statusPrivilegeNotHeld (STATUS_PRIVILEGE_NOT_HELD) has no sentinel in go-smb.
const statusPrivilegeNotHeld uint32 = 0xc0000061

// isExpectedSMBWriteDeniedError reports a write probe the server refused:
// access denied or privilege not held.
func isExpectedSMBWriteDeniedError(err error) bool {
	if errors.Is(err, smb.StatusMap[smb.StatusAccessDenied]) {
		return true
	}
	var statusErr *smb.NTStatusError
	return errors.As(err, &statusErr) && statusErr.Status == statusPrivilegeNotHeld
}

// WalkShare connects to share and lists it within lim; see walkShare.
func (conn *Connection) WalkShare(ctx context.Context, share string, lim ListLimits, recurse bool,
	emit func(dir smb.SharedFile, depth int, entries []smb.SharedFile),
	onErr func(dir string, err error)) (walkStats, error) {

	if err := conn.session.TreeConnect(share); err != nil {
		return walkStats{}, err
	}
	defer func() {
		logCloseError("failed to disconnect tree "+share, conn.session.TreeDisconnect(share))
	}()
	return walkShare(ctx, conn.session, share, lim, recurse, emit, onErr)
}
