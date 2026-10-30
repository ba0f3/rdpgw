package destination

import (
	"context"
	"errors"
	"net"
	"testing"
)

func TestPolicyRejectsPrivateAndDisallowedPortsBeforeDial(t *testing.T) {
	p := New(nil, false)
	p.dial = func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("dialed forbidden destination")
		return nil, nil
	}
	for _, host := range []string{"127.0.0.1:3389", "[::1]:3389", "10.0.0.1:3389", "169.254.169.254:3389", "203.0.113.1:445", "0.0.0.0:3389"} {
		if _, err := p.DialContext(context.Background(), host); err == nil {
			t.Fatalf("allowed %s", host)
		}
	}
}

func TestDialUsesExactlyTheApprovedIP(t *testing.T) {
	p := New(nil, false)
	lookups := 0
	p.lookup = func(ctx context.Context, host string) ([]net.IPAddr, error) {
		lookups++
		if lookups > 1 {
			return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
		}
		return []net.IPAddr{{IP: net.ParseIP("203.0.113.5")}}, nil
	}
	wantErr := errors.New("test dial")
	p.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != "203.0.113.5:3389" {
			t.Fatalf("dialed %q", address)
		}
		return nil, wantErr
	}
	_, err := p.DialContext(context.Background(), "changing.example:3389")
	if !errors.Is(err, wantErr) || lookups != 1 {
		t.Fatalf("error=%v lookups=%d", err, lookups)
	}
}

func TestMixedDNSAndEmptyDNSFailClosed(t *testing.T) {
	for _, addrs := range [][]net.IPAddr{nil, {{IP: net.ParseIP("203.0.113.5")}, {IP: net.ParseIP("10.0.0.1")}}} {
		p := New(nil, false)
		p.lookup = func(context.Context, string) ([]net.IPAddr, error) { return addrs, nil }
		p.dial = func(context.Context, string, string) (net.Conn, error) {
			t.Fatal("dialed unapproved resolution")
			return nil, nil
		}
		if _, err := p.DialContext(context.Background(), "mixed.example:3389"); err == nil {
			t.Fatal("accepted unsafe DNS")
		}
	}
}

func TestPrivateTargetsCanBeExplicitlyEnabled(t *testing.T) {
	p := New([]int{3390}, true)
	if err := p.Allow(context.Background(), "10.0.0.1:3390"); err != nil {
		t.Fatal(err)
	}
	if err := p.Allow(context.Background(), "10.0.0.1:445"); err == nil {
		t.Fatal("private opt-in bypassed ports")
	}
}
