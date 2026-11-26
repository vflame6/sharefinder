package scanner

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

// ErrDialerClosed is returned by a Dialer after CloseAll: the scan is stopping
// and no new connection may be opened.
var ErrDialerClosed = errors.New("dialer closed: scan is stopping")

// Dialer opens TCP connections directly or through a SOCKS5 proxy, bounds the
// connect with a timeout, and tracks every connection it hands out so that
// CloseAll can unblock all in-flight I/O when the scan is cancelled.
//
// Connections from DialContext additionally carry per-I/O deadlines: every
// Read and Write is given ioTimeout to make progress, so a host that accepts
// TCP but never answers fails instead of hanging its worker forever.
type Dialer struct {
	base           proxy.ContextDialer
	proxied        bool
	connectTimeout time.Duration
	ioTimeout      time.Duration

	ctx    context.Context
	cancel context.CancelFunc

	mu     sync.Mutex
	conns  map[*trackedConn]struct{}
	closed bool
}

// NewDialer returns a Dialer. proxyAddr is empty for direct connections or
// "IP:PORT" of a SOCKS5 proxy. A connectTimeout or ioTimeout <= 0 disables
// that bound.
func NewDialer(proxyAddr string, connectTimeout, ioTimeout time.Duration) (*Dialer, error) {
	direct := &net.Dialer{Timeout: connectTimeout}
	ctx, cancel := context.WithCancel(context.Background())
	d := &Dialer{
		base:           direct,
		connectTimeout: connectTimeout,
		ioTimeout:      ioTimeout,
		ctx:            ctx,
		cancel:         cancel,
		conns:          make(map[*trackedConn]struct{}),
	}

	if proxyAddr != "" {
		proxyURL, err := url.Parse("socks5://" + proxyAddr)
		if err != nil || proxyURL.Host == "" {
			cancel()
			return nil, errors.New("invalid proxy setting, try IP:PORT")
		}
		socks, err := proxy.SOCKS5("tcp", proxyURL.Host, nil, direct)
		if err != nil {
			cancel()
			return nil, errors.New("invalid proxy setting, try IP:PORT")
		}
		contextDialer, ok := socks.(proxy.ContextDialer)
		if !ok {
			cancel()
			return nil, errors.New("SOCKS5 dialer does not support contexts")
		}
		d.base = contextDialer
		d.proxied = true
	}

	return d, nil
}

// Dial implements proxy.Dialer.
func (d *Dialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

// DialContext implements proxy.ContextDialer. The returned connection applies
// the I/O timeout to every Read and Write and is closed by CloseAll.
func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d.dial(ctx, network, address, d.ioTimeout)
}

// DialTracked opens a connection that CloseAll closes but that has no per-I/O
// deadline. It suits protocols with their own request timeouts and long idle
// gaps between requests, such as LDAP.
func (d *Dialer) DialTracked(ctx context.Context, network, address string) (net.Conn, error) {
	return d.dial(ctx, network, address, 0)
}

func (d *Dialer) dial(ctx context.Context, network, address string, ioTimeout time.Duration) (net.Conn, error) {
	if d.isClosed() {
		return nil, ErrDialerClosed
	}

	// Abort the dial when either the caller's context or the dialer itself
	// (CloseAll) is done, and never wait longer than the connect timeout.
	dialCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(d.ctx, cancel)
	defer stop()
	if d.connectTimeout > 0 {
		var cancelTimeout context.CancelFunc
		dialCtx, cancelTimeout = context.WithTimeout(dialCtx, d.connectTimeout)
		defer cancelTimeout()
	}

	conn, err := d.base.DialContext(dialCtx, network, normalizeHostPort(address))
	if err != nil {
		if d.isClosed() {
			return nil, ErrDialerClosed
		}
		return nil, err
	}

	tc := &trackedConn{Conn: conn, timeout: ioTimeout, dialer: d}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		_ = conn.Close()
		return nil, ErrDialerClosed
	}
	d.conns[tc] = struct{}{}
	return tc, nil
}

// CloseAll closes every connection handed out so far and makes all further
// dials fail with ErrDialerClosed. It is safe to call more than once and on a
// nil Dialer.
func (d *Dialer) CloseAll() {
	if d == nil {
		return
	}
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return
	}
	d.closed = true
	conns := d.conns
	d.conns = nil
	d.mu.Unlock()

	d.cancel()
	for c := range conns {
		_ = c.Conn.Close()
	}
}

// Proxied reports whether connections go through a SOCKS5 proxy.
func (d *Dialer) Proxied() bool {
	return d != nil && d.proxied
}

// ConnectTimeout returns the bound on establishing a connection.
func (d *Dialer) ConnectTimeout() time.Duration {
	return d.connectTimeout
}

// IOTimeout returns the bound on each Read and Write of a DialContext connection.
func (d *Dialer) IOTimeout() time.Duration {
	return d.ioTimeout
}

func (d *Dialer) isClosed() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.closed
}

func (d *Dialer) untrack(c *trackedConn) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.conns, c)
}

// trackedConn is a connection registered with its Dialer. When timeout > 0,
// every Read gets a fresh read deadline and every Write a fresh read and write
// deadline, so progress keeps the connection alive and silence ends it.
type trackedConn struct {
	net.Conn
	timeout time.Duration
	dialer  *Dialer
}

func (c *trackedConn) Read(b []byte) (int, error) {
	if c.timeout > 0 {
		_ = c.SetReadDeadline(time.Now().Add(c.timeout))
	}
	return c.Conn.Read(b)
}

func (c *trackedConn) Write(b []byte) (int, error) {
	if c.timeout > 0 {
		deadline := time.Now().Add(c.timeout)
		_ = c.SetWriteDeadline(deadline)
		// A request was sent: give the reply a full timeout even if the
		// reader has been parked in Read for a while.
		_ = c.SetReadDeadline(deadline)
	}
	return c.Conn.Write(b)
}

func (c *trackedConn) Close() error {
	c.dialer.untrack(c)
	return c.Conn.Close()
}

// normalizeHostPort repairs "host:port" strings built with fmt.Sprintf("%s:%d")
// for IPv6 hosts, e.g. "::1:445" becomes "[::1]:445". Other input is returned
// unchanged.
func normalizeHostPort(address string) string {
	if _, _, err := net.SplitHostPort(address); err == nil {
		return address
	}
	i := strings.LastIndex(address, ":")
	if i <= 0 || i == len(address)-1 {
		return address
	}
	host, port := address[:i], address[i+1:]
	if _, err := netip.ParseAddr(host); err != nil {
		return address
	}
	return net.JoinHostPort(host, port)
}
