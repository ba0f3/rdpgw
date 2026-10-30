// Package destination validates endpoints and dials only the IPs it validated.
package destination

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"
)

type Policy struct {
	allowedPorts map[int]bool
	allowPrivate bool
	lookup       func(context.Context, string) ([]net.IPAddr, error)
	dial         func(context.Context, string, string) (net.Conn, error)
}

func New(ports []int, allowPrivate bool) Policy {
	if len(ports) == 0 {
		ports = []int{3389}
	}
	p := Policy{allowedPorts: make(map[int]bool), allowPrivate: allowPrivate}
	for _, port := range ports {
		p.allowedPorts[port] = true
	}
	return p
}

func (p Policy) resolve(ctx context.Context, hostport string) ([]string, error) {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		// Bare hostnames and IPs use the protocol default. Other malformed
		// endpoint syntax is rejected instead of being reinterpreted.
		if net.ParseIP(hostport) == nil {
			for _, c := range hostport {
				if c == ':' || c == '[' || c == ']' {
					return nil, err
				}
			}
		}
		host, port = hostport, "3389"
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 || host == "" {
		return nil, errors.New("invalid destination endpoint")
	}
	allowed := p.allowedPorts[n]
	if len(p.allowedPorts) == 0 {
		allowed = n == 3389
	}
	if !allowed {
		return nil, fmt.Errorf("port %d not in allow-list", n)
	}
	var addrs []net.IPAddr
	if ip := net.ParseIP(host); ip != nil {
		addrs = []net.IPAddr{{IP: ip}}
	} else {
		lookup := p.lookup
		if lookup == nil {
			lookup = net.DefaultResolver.LookupIPAddr
		}
		addrs, err = lookup(ctx, host)
		if err != nil {
			return nil, err
		}
	}
	if len(addrs) == 0 {
		return nil, errors.New("destination has no addresses")
	}
	result := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		ip := addr.IP
		if ip == nil || addr.Zone != "" || (!p.allowPrivate && (!ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast())) {
			return nil, fmt.Errorf("destination %q resolves to prohibited address %s", host, ip)
		}
		result = append(result, net.JoinHostPort(ip.String(), strconv.Itoa(n)))
	}
	return result, nil
}

func (p Policy) Allow(ctx context.Context, hostport string) error {
	_, err := p.resolve(ctx, hostport)
	return err
}

func (p Policy) DialContext(ctx context.Context, hostport string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	endpoints, err := p.resolve(ctx, hostport)
	if err != nil {
		return nil, err
	}
	dial := p.dial
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	for _, endpoint := range endpoints {
		conn, dialErr := dial(ctx, "tcp", endpoint)
		if dialErr == nil {
			return conn, nil
		}
		err = dialErr
	}
	return nil, err
}
