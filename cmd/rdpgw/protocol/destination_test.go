package protocol

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/destination"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/identity"
)

// This drives the actual channel-create path in token-free mode. The host
// check allows the request; the dial boundary must still enforce destination.
func TestChannelCreateEnforcesDestinationInTokenFreeMode(t *testing.T) {
	p := destination.New(nil, false)
	called := false
	gw := &Gateway{CheckHost: func(context.Context, string) (bool, error) { return true, nil }, DialHost: func(ctx context.Context, host string) (net.Conn, error) {
		called = true
		return p.DialContext(ctx, host)
	}}
	in := newTransportMock()
	client := ClientConfig{Server: "127.0.0.1", Port: 3389}
	pkt := newPacketMock()
	pkt.addBytes(client.channelRequest())
	in.addPacket(pkt)
	tunnel := &Tunnel{User: identity.NewUser(), transportIn: in, transportOut: newTransportMock()}
	processor := NewProcessor(gw, tunnel)
	processor.state = SERVER_STATE_TUNNEL_AUTHORIZE
	err := processor.Process(context.Background())
	if !called || err == nil || !strings.Contains(err.Error(), "prohibited address") || tunnel.rwc != nil {
		t.Fatalf("called=%v error=%v connection=%v", called, err, tunnel.rwc)
	}
}
