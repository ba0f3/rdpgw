package web

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/access"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/credentials"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/identity"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/protocol"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/security"
)

func TestDownloadCredentialSurvivesRestartAndChecksLiveKeycloak(t *testing.T) {
	previousManager, previousLifetime, previousIP, previousEngine := security.CredentialManager, security.PAATokenLifetime, security.VerifyClientIP, access.Current()
	t.Cleanup(func() {
		security.CredentialManager = previousManager
		security.PAATokenLifetime = previousLifetime
		security.VerifyClientIP = previousIP
		access.Init(previousEngine)
	})
	security.PAATokenLifetime = 43200
	security.VerifyClientIP = false
	access.Init(access.NewEngine(access.Policy{Drive: true, Clipboard: true}, []access.Rule{{Groups: []string{"/blocked"}, Deny: true}}))
	groups := "/staff"
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/realms/test/protocol/openid-connect/token":
			fmt.Fprint(w, `{"access_token":"service-token","token_type":"Bearer","expires_in":60}`)
		case "/admin/realms/test/users/alice":
			fmt.Fprint(w, `{"id":"alice","username":"alice","enabled":true}`)
		case "/admin/realms/test/users/alice/groups":
			fmt.Fprintf(w, `[{"name":"staff","path":%q}]`, groups)
		default:
			http.NotFound(w, r)
		}
	}))
	defer admin.Close()
	resolver, err := security.NewKeycloakResolver(security.KeycloakConfig{Issuer: admin.URL + "/realms/test", ClientID: "service", ClientSecret: "test"})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "credentials.db")
	store, err := credentials.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { store.Close() }()
	security.CredentialManager = &security.CredentialService{Store: store, Resolve: resolver.Resolve}
	InitStore([]byte("testsessionkeytestsessionkey1234"), []byte("testencryptionkeytestencrypt1234"), "cookie", 8192, 120)
	provider := newTestProvider(t, []string{"/staff"})
	o := (&OIDCConfig{OAuth2Config: provider.oauthConfig(), OIDCTokenVerifier: provider.verifier(t)}).New()
	stateReq := httptest.NewRequest("GET", "/connect", nil)
	stateRes := httptest.NewRecorder()
	if err := storeOIDCState(stateRes, stateReq, "test-state", "/connect"); err != nil {
		t.Fatal(err)
	}
	callbackReq := identity.AddToRequestCtx(identity.NewUser(), httptest.NewRequest("GET", "/callback?state=test-state&code=code", nil))
	for _, c := range stateRes.Result().Cookies() {
		callbackReq.AddCookie(c)
	}
	callbackRes := httptest.NewRecorder()
	o.HandleCallback(callbackRes, callbackReq)
	if callbackRes.Code != http.StatusFound {
		t.Fatalf("login status=%d %s", callbackRes.Code, callbackRes.Body.String())
	}
	gwURL, _ := url.Parse("https://gateway.example")
	h := (&Config{Hosts: []string{"desktop:3389"}, HostSelection: "roundrobin", GatewayAddress: gwURL, PAATokenGenerator: security.GeneratePAAToken}).NewHandler()
	downloadReq := httptest.NewRequest("GET", "https://gateway.example/connect", nil)
	// The final callback cookie carries the authenticated identity.
	for _, c := range callbackRes.Result().Cookies() {
		if c.Name == rdpGwSession {
			downloadReq.Header.Set("Cookie", c.Name+"="+c.Value)
		}
	}
	downloadRes := httptest.NewRecorder()
	EnrichContext(o.Authenticated(http.HandlerFunc(h.HandleDownload))).ServeHTTP(downloadRes, downloadReq)
	if downloadRes.Code != http.StatusOK {
		t.Fatalf("download status=%d body=%s", downloadRes.Code, downloadRes.Body.String())
	}
	token := ""
	for _, line := range strings.Split(downloadRes.Body.String(), "\r\n") {
		if strings.HasPrefix(line, "gatewayaccesstoken:s:") {
			token = strings.TrimPrefix(line, "gatewayaccesstoken:s:")
		}
	}
	record, err := store.Lookup(token)
	if err != nil {
		t.Fatal("download missing usable credential", err)
	}
	if record.ExpiresAt.Sub(record.AuthTime) != 30*24*time.Hour {
		t.Fatalf("wrong lifetime %s", record.ExpiresAt.Sub(record.AuthTime))
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = credentials.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	security.CredentialManager = &security.CredentialService{Store: store, Resolve: resolver.Resolve}
	tunnel := &protocol.Tunnel{User: identity.NewUser()}
	ctx := context.WithValue(context.Background(), protocol.CtxTunnel, tunnel)
	if ok, err := security.CheckPAACookie(ctx, token); !ok || err != nil {
		t.Fatalf("restart lost credential: %v", err)
	}
	groups = "/blocked"
	if ok, _ := security.CheckPAACookie(ctx, token); ok {
		t.Fatal("old file ignored current Keycloak group")
	}
	groups = "/staff"
	if err := store.RevokeUser(record.Subject); err != nil {
		t.Fatal(err)
	}
	if ok, _ := security.CheckPAACookie(ctx, token); ok {
		t.Fatal("user revocation ignored after restart")
	}
}
