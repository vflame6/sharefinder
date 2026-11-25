package scanner

import (
	"context"
	"fmt"
	"net"
	"time"
)

type Resolver struct {
	resolver *net.Resolver
}

// NewResolver creates a DNS resolver that queries resolverIP over the given
// protocol. When the dialer goes through a SOCKS proxy, queries are tunnelled
// through it (use "tcp"); otherwise they are sent directly.
func NewResolver(protocol string, resolverIP net.IP, timeout time.Duration, dialer *Dialer) *Resolver {
	server := net.JoinHostPort(resolverIP.String(), "53")
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			if dialer.Proxied() {
				return dialer.DialContext(ctx, protocol, server)
			}
			d := net.Dialer{Timeout: timeout}
			return d.DialContext(ctx, protocol, server)
		},
	}

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
