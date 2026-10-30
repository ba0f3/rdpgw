package security

import (
	"context"
	"testing"

	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/access"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/identity"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/protocol"
)

func TestLegacyPAAKeepsVerifiedEmptyMembership(t *testing.T) {
	previousEngine, previousKey, previousMode := access.Current(), SigningKey, HostSelection
	t.Cleanup(func() { access.Init(previousEngine); SigningKey = previousKey; HostSelection = previousMode })
	SigningKey = []byte("5aa3a1568fe8421cd7e127d5ace28d2d")
	HostSelection = "signed"
	access.Init(access.NewEngine(access.Policy{}, []access.Rule{{Groups: []string{"blocked"}, Deny: true}}))
	id := identity.NewUser()
	id.SetUserName("alice")
	id.SetGroups([]string{})
	ctx := context.WithValue(context.Background(), identity.CTXKey, id)
	token, err := GeneratePAAToken(ctx, "alice", "desktop:3389")
	if err != nil {
		t.Fatal(err)
	}
	tunnel := &protocol.Tunnel{User: identity.NewUser()}
	checkCtx := context.WithValue(context.Background(), protocol.CtxTunnel, tunnel)
	if ok, err := CheckPAACookie(checkCtx, token); !ok || err != nil {
		t.Fatalf("token rejected %v", err)
	}
	if ok, err := CheckHost(checkCtx, "desktop:3389"); !ok || err != nil {
		t.Fatalf("verified empty groups became unknown at gateway: %v", err)
	}
}
