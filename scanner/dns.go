package scanner

import (
	"context"
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
			return d.DialContext(ctx, "udp", resolver.String()+":53")
		},
	}
	return &Resolver{resolver: r}
}

func NewTCPResolver(resolver net.IP, timeout time.Duration) *Resolver {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: timeout,
			}
			return d.DialContext(ctx, "tcp", resolver.String()+":53")
		},
	}
	return &Resolver{resolver: r}
}

func (r *Resolver) LookupHost(host string) (net.IP, error) {
	ip, err := r.resolver.LookupHost(context.Background(), host)
	if err != nil {
		return nil, err
	}
	return net.ParseIP(ip[0]), nil
}
