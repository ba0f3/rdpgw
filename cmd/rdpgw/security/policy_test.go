package security

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/access"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/identity"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/protocol"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
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

// The group membership and the complete user name of the user are signed
// into the token, the access policy needs them when the client connects.
func TestPAATokenCarriesUserAndGroups(t *testing.T) {
	SigningKey = []byte("5aa3a1568fe8421cd7e127d5ace28d2d")
	VerifyClientIP = false

	previous := access.Current()
	access.Init(access.NewEngine(access.Policy{}, []access.Rule{
		{
			Groups: []string{"contractors"},
			Hosts:  []string{"10.0.0.9"},
		},
	}))
	defer access.Init(previous)

	id := identity.NewUser()
	id.SetUserName("alice@example.com")
	id.SetGroups([]string{"contractors"})
	id.SetAttribute(identity.AttrClientIp, "10.0.0.1")
	ctx := context.WithValue(context.Background(), identity.CTXKey, id)

	token, err := GeneratePAAToken(ctx, "alice", "rdp.example.com")
	if err != nil {
		t.Fatalf("GeneratePAAToken: %v", err)
	}

	tun := &protocol.Tunnel{User: identity.NewUser()}
	checkCtx := context.WithValue(context.Background(), protocol.CtxTunnel, tun)

	if ok, err := CheckPAACookie(checkCtx, token); !ok || err != nil {
		t.Fatalf("CheckPAACookie: ok %v, err %v", ok, err)
	}

	if tun.User.UserName() != "alice@example.com" {
		t.Errorf("the user of the tunnel is %q, want alice@example.com", tun.User.UserName())
	}

	if len(tun.User.Groups()) != 1 || tun.User.Groups()[0] != "contractors" {
		t.Errorf("the groups of the tunnel are %v, want [contractors]", tun.User.Groups())
	}

	// the group rule applies to the session now
	if access.Current().HostAllowed(tun.User, "10.0.0.9") != true {
		t.Errorf("the group rule does not apply to the session")
	}
	if access.Current().HostAllowed(tun.User, "10.0.0.8") != false {
		t.Errorf("the group rule does not restrict the session")
	}
}

// The policy of the gateway is the ceiling of the policy that is signed
// into the token. A token that was issued under a looser policy does not
// widen the policy that is configured now.
func TestPAATokenPolicyIsNarrowedByTheGateway(t *testing.T) {
	SigningKey = []byte("5aa3a1568fe8421cd7e127d5ace28d2d")
	VerifyClientIP = false

	previous := access.Current()

	// the token is issued with a policy that allows the clipboard
	access.Init(access.NewEngine(access.Policy{Clipboard: true, Drive: true}, nil))

	id := identity.NewUser()
	id.SetUserName("alice")
	id.SetAttribute(identity.AttrClientIp, "10.0.0.1")
	ctx := context.WithValue(context.Background(), identity.CTXKey, id)

	token, err := GeneratePAAToken(ctx, "alice", "rdp.example.com")
	if err != nil {
		t.Fatalf("GeneratePAAToken: %v", err)
	}

	// the gateway tightens the policy afterwards
	access.Init(access.NewEngine(access.Policy{Drive: true}, nil))
	defer access.Init(previous)

	tun := &protocol.Tunnel{User: identity.NewUser()}
	checkCtx := context.WithValue(context.Background(), protocol.CtxTunnel, tun)

	if ok, err := CheckPAACookie(checkCtx, token); !ok || err != nil {
		t.Fatalf("CheckPAACookie: ok %v, err %v", ok, err)
	}

	if tun.RedirectFlags == nil {
		t.Fatalf("the tunnel does not carry a redirect policy")
	}

	if tun.RedirectFlags.Clipboard {
		t.Errorf("the clipboard must be disabled, the gateway does not allow it anymore")
	}
	if !tun.RedirectFlags.Drive {
		t.Errorf("the drive must be allowed")
	}
}

// Legacy tokens without a redirect claim advertise DisableAll. Persistent
// credential mode rejects legacy tokens entirely.
func TestLegacyPAATokenWithoutPolicyDisablesRedirection(t *testing.T) {
	SigningKey = []byte("5aa3a1568fe8421cd7e127d5ace28d2d")
	VerifyClientIP = false

	previous := access.Current()
	access.Init(access.NewEngine(access.Policy{Clipboard: true}, nil))
	defer access.Init(previous)

	// a token without the redirect claim, as issued by an older build
	token, err := generateTokenWithoutPolicy("alice", "rdp.example.com")
	if err != nil {
		t.Fatalf("cannot generate the token: %v", err)
	}

	tun := &protocol.Tunnel{User: identity.NewUser()}
	checkCtx := context.WithValue(context.Background(), protocol.CtxTunnel, tun)

	if ok, err := CheckPAACookie(checkCtx, token); !ok || err != nil {
		t.Fatalf("CheckPAACookie: ok %v, err %v", ok, err)
	}

	if tun.RedirectFlags == nil {
		t.Fatalf("the tunnel does not carry a redirect policy")
	}

	if !tun.RedirectFlags.DisableAll {
		t.Errorf("the policy of a token without a policy must disable every redirection, got %+v", tun.RedirectFlags)
	}
}

// generateTokenWithoutPolicy issues a gateway access token that carries no
// redirect policy.
func generateTokenWithoutPolicy(username string, server string) (string, error) {
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: SigningKey}, nil)
	if err != nil {
		return "", err
	}

	standard := jwt.Claims{
		Issuer:   "rdpgw",
		Audience: jwt.Audience{paaAudience},
		Expiry:   jwt.NewNumericDate(time.Now().Add(time.Minute * 5)),
		Subject:  username,
	}

	private := customClaims{
		RemoteServer: server,
		ClientIP:     "10.0.0.1",
	}

	return jwt.Signed(sig).Claims(standard).Claims(private).Serialize()
}
