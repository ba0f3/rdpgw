package security

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/access"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/identity"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/protocol"
)

// The redirect policy of the user is signed into the gateway access token
// and is applied to the tunnel when the client connects.
func TestPAATokenCarriesRedirectPolicy(t *testing.T) {
	SigningKey = []byte("5aa3a1568fe8421cd7e127d5ace28d2d")
	VerifyClientIP = false

	previous := access.Current()
	access.Init(access.NewEngine(access.Policy{Drive: true, Clipboard: true}, []access.Rule{
		{
			Users: []string{"alice"},
			Redirect: access.Overrides{
				Clipboard: boolPointer(false),
			},
		},
	}))
	defer access.Init(previous)

	id := identity.NewUser()
	id.SetUserName("alice")
	id.SetAttribute(identity.AttrClientIp, "10.0.0.1")
	ctx := context.WithValue(context.Background(), identity.CTXKey, id)

	token, err := GeneratePAAToken(ctx, "alice", "rdp.example.com")
	if err != nil {
		t.Fatalf("GeneratePAAToken: %v", err)
	}

	claims := struct {
		Redirect *access.Policy `json:"redirect"`
	}{}
	if err := json.Unmarshal([]byte(paaPayload(t, token)), &claims); err != nil {
		t.Fatalf("cannot decode the payload: %v", err)
	}

	if claims.Redirect == nil {
		t.Fatalf("the token does not carry a redirect policy")
	}

	if claims.Redirect.Clipboard {
		t.Errorf("the policy of the token allows the clipboard, want it to be denied")
	}
	if !claims.Redirect.Drive {
		t.Errorf("the policy of the token denies the drive, want it to be allowed")
	}

	// the policy of the token is applied to the tunnel
	tun := &protocol.Tunnel{User: id}
	checkCtx := context.WithValue(context.Background(), protocol.CtxTunnel, tun)

	ok, err := CheckPAACookie(checkCtx, token)
	if err != nil {
		t.Fatalf("CheckPAACookie: %v", err)
	}
	if !ok {
		t.Fatalf("CheckPAACookie rejected a valid token")
	}

	if tun.RedirectFlags == nil {
		t.Fatalf("the tunnel does not carry a redirect policy")
	}

	if tun.RedirectFlags.Clipboard {
		t.Errorf("the tunnel allows the clipboard, want it to be denied")
	}
	if !tun.RedirectFlags.Drive {
		t.Errorf("the tunnel denies the drive, want it to be allowed")
	}
}

// The lifetime of the gateway credentials is configurable. It determines
// how long a downloaded .rdp file stays usable.
func TestPAATokenLifetime(t *testing.T) {
	SigningKey = []byte("5aa3a1568fe8421cd7e127d5ace28d2d")

	previous := PAATokenLifetime
	PAATokenLifetime = 120
	defer func() { PAATokenLifetime = previous }()

	id := identity.NewUser()
	id.SetUserName("alice")
	id.SetAttribute(identity.AttrClientIp, "10.0.0.1")
	ctx := context.WithValue(context.Background(), identity.CTXKey, id)

	token, err := GeneratePAAToken(ctx, "alice", "rdp.example.com")
	if err != nil {
		t.Fatalf("GeneratePAAToken: %v", err)
	}

	claims := struct {
		Expiry int64 `json:"exp"`
	}{}
	if err := json.Unmarshal([]byte(paaPayload(t, token)), &claims); err != nil {
		t.Fatalf("cannot decode the payload: %v", err)
	}

	want := time.Now().Add(120 * time.Minute).Unix()
	if claims.Expiry < want-60 || claims.Expiry > want+60 {
		t.Errorf("the token expires at %d, want about %d", claims.Expiry, want)
	}
}

func boolPointer(b bool) *bool {
	return &b
}
