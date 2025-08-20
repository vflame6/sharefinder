package scanner

import (
	"context"
	"fmt"
	"net"
	"time"

	"golang.org/x/net/proxy"
)

type Resolver struct {
	resolver *net.Resolver
}

// NewUDPResolver creates a DNS resolver that uses UDP with optional proxy support
func NewUDPResolver(resolverIP net.IP, timeout time.Duration, proxyDialer proxy.Dialer) *Resolver {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			// If proxyDialer is provided, use it
			if proxyDialer != nil {
				return proxyDialer.Dial("udp", net.JoinHostPort(resolverIP.String(), "53"))
			}
			// Otherwise fall back to direct net.Dialer
			d := net.Dialer{Timeout: timeout}
			return d.DialContext(ctx, "udp", net.JoinHostPort(resolverIP.String(), "53"))
		},
	}

	// Override default resolver so Go runtime also uses this
	net.DefaultResolver = r
	return &Resolver{resolver: r}
}

// NewTCPResolver creates a DNS resolver that uses TCP with optional proxy support
func NewTCPResolver(resolverIP net.IP, timeout time.Duration, proxyDialer proxy.Dialer) *Resolver {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			// If proxyDialer is provided, use it
			if proxyDialer != nil {
				return proxyDialer.Dial("tcp", net.JoinHostPort(resolverIP.String(), "53"))
			}
			// Otherwise fall back to direct net.Dialer
			d := net.Dialer{Timeout: timeout}
			return d.DialContext(ctx, "tcp", net.JoinHostPort(resolverIP.String(), "53"))
		},
	}

	// Override default resolver so Go runtime also uses this
	net.DefaultResolver = r
	return &Resolver{resolver: r}
}

// LookupHost resolves a hostname to its first valid IP
func (r *Resolver) LookupHost(host string) (net.IP, error) {
	ips, err := r.resolver.LookupHost(context.Background(), host)
	if err != nil {
		return nil, err
	}

	for _, ipStr := range ips {
		if ip := net.ParseIP(ipStr); ip != nil {
			return ip, nil
		}
	}

	return nil, fmt.Errorf("no valid IP found for host %s", host)
}
