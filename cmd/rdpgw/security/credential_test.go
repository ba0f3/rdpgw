package security

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/access"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/credentials"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/identity"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/protocol"
)

func TestPersistentPAAUsesLiveGroupsAndRejectsRevocation(t *testing.T) {
	s, err := credentials.Open(filepath.Join(t.TempDir(), "credentials.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	oldManager, oldLifetime, oldIP, oldEngine := CredentialManager, PAATokenLifetime, VerifyClientIP, access.Current()
	t.Cleanup(func() {
		CredentialManager = oldManager
		PAATokenLifetime = oldLifetime
		VerifyClientIP = oldIP
		access.Init(oldEngine)
	})
	PAATokenLifetime = 30 * 24 * 60
	VerifyClientIP = false
	groups := []string{"staff"}
	upstreamErr := error(nil)
	resolver := func(ctx context.Context, subject string) (identity.Identity, error) {
		if upstreamErr != nil {
			return nil, upstreamErr
		}
		id := identity.NewUser()
		id.SetUserName("alice-now")
		id.SetGroups(groups)
		id.SetAttribute(identity.AttrSubject, subject)
		id.SetAuthenticated(true)
		return id, nil
	}
	CredentialManager = &CredentialService{Store: s, Resolve: resolver}
	access.Init(access.NewEngine(access.Policy{Drive: true}, []access.Rule{{Groups: []string{"blocked"}, Deny: true}, {Groups: []string{"limited"}, Hosts: []string{"desktop:3389"}, Redirect: access.Overrides{Drive: boolPointer(false)}}, {Groups: []string{"contractors"}, Hosts: []string{"sandbox:3389"}, Redirect: access.Overrides{Drive: boolPointer(false)}}}))
	id := identity.NewUser()
	id.SetUserName("alice")
	id.SetAuthenticated(true)
	id.SetAuthTime(time.Now().Truncate(time.Second))
	id.SetAttribute(identity.AttrSubject, "alice-id")
	if err := CredentialManager.Login(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(context.Background(), identity.CTXKey, id)
	token, err := GeneratePAAToken(ctx, "alice", "desktop:3389")
	if err != nil {
		t.Fatal(err)
	}
	r, err := s.Lookup(token)
	if err != nil || r.ExpiresAt.Sub(id.AuthTime()) != credentials.MaxLifetime {
		t.Fatalf("record=%+v err=%v", r, err)
	}
	tunnel := &protocol.Tunnel{User: identity.NewUser()}
	checkCtx := context.WithValue(context.Background(), protocol.CtxTunnel, tunnel)
	if ok, err := CheckPAACookie(checkCtx, token); !ok || err != nil {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if tunnel.User.UserName() != "alice-now" || !tunnel.RedirectFlags.Drive {
		t.Fatal("current user not installed")
	}
	groups = []string{"limited"}
	if ok, _ := CheckSession(func(context.Context, string) (bool, error) { return true, nil })(checkCtx, "desktop:3389"); ok {
		t.Fatal("channel accepted flags that changed after tunnel authorization")
	}
	if ok, err := CheckPAACookie(checkCtx, token); !ok || err != nil || tunnel.RedirectFlags.Drive {
		t.Fatalf("new handshake did not obtain tightened flags: ok=%v error=%v", ok, err)
	}
	// A delayed channel request must not reuse handshake authorization.
	groups = []string{"blocked"}
	if ok, _ := CheckSession(func(context.Context, string) (bool, error) {
		t.Fatal("stale handshake reached destination check")
		return true, nil
	})(checkCtx, "desktop:3389"); ok {
		t.Fatal("delayed channel accepted stale authorization")
	}
	groups = []string{"contractors"}
	if ok, _ := CheckPAACookie(checkCtx, token); ok {
		t.Fatal("stale group snapshot bypassed current host ACL")
	}
	groups = []string{"blocked"}
	if ok, _ := CheckPAACookie(checkCtx, token); ok {
		t.Fatal("current deny ignored")
	}
	groups = []string{"staff"}
	upstreamErr = errors.New("Keycloak unavailable")
	if ok, _ := CheckPAACookie(checkCtx, token); ok {
		t.Fatal("upstream outage failed open")
	}
	upstreamErr = nil
	if err := s.Revoke(r.ID, r.Subject); err != nil {
		t.Fatal(err)
	}
	if ok, _ := CheckPAACookie(checkCtx, token); ok {
		t.Fatal("revoked bearer accepted")
	}
	if _, err := GeneratePAAToken(ctx, "alice", "desktop:3389"); err != nil {
		t.Fatal("individual revoke blocked other issuance", err)
	}
	if err := s.RevokeUser(r.Subject); err != nil {
		t.Fatal(err)
	}
	if _, err := GeneratePAAToken(ctx, "alice", "desktop:3389"); err == nil {
		t.Fatal("old browser session minted credential after revoke-all")
	}
	if ok, _ := CheckPAACookie(checkCtx, "an-old-jwt"); ok {
		t.Fatal("legacy bypass")
	}
}
