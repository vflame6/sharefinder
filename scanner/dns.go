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

func NewUDPResolver(resolver net.IP, timeout time.Duration) *Resolver {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: timeout,
			}
			return d.DialContext(ctx, "udp", net.JoinHostPort(resolver.String(), "53"))
		},
	}
	net.DefaultResolver = r
	return &Resolver{resolver: r}
}

func NewTCPResolver(resolver net.IP, timeout time.Duration) *Resolver {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: timeout,
			}
			return d.DialContext(ctx, "tcp", net.JoinHostPort(resolver.String(), "53"))
		},
	}
	net.DefaultResolver = r
	return &Resolver{resolver: r}
}

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
