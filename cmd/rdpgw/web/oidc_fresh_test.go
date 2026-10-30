package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/identity"
	"golang.org/x/oauth2"
)

func TestOIDCLoginRequestsFreshAuthentication(t *testing.T) {
	InitStore([]byte("testsessionkeytestsessionkey1234"), []byte("testencryptionkeytestencrypt1234"), "cookie", 8192, 120)
	o := (&OIDCConfig{OAuth2Config: &oauth2.Config{ClientID: "test", Endpoint: oauth2.Endpoint{AuthURL: "https://keycloak.example/authorize"}}}).New()
	req := identity.AddToRequestCtx(identity.NewUser(), httptest.NewRequest("GET", "https://gateway/connect", nil))
	w := httptest.NewRecorder()
	o.Authenticated(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("anonymous request reached protected handler") })).ServeHTTP(w, req)
	u, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if w.Code != http.StatusFound || q.Get("prompt") != "login" || q.Get("max_age") != "0" || q.Get("nonce") == "" || q.Get("nonce") != q.Get("state") || q.Get("code_challenge_method") != "S256" {
		t.Fatalf("unexpected authorization URL %s", u)
	}
}

func TestOIDCCallbackRejectsOldAuthenticationAndWrongNonce(t *testing.T) {
	for _, tc := range []struct {
		name  string
		age   time.Duration
		nonce string
	}{
		{"old SSO", -time.Hour, "test-state"},
		{"wrong nonce", 0, "other-flow"},
		{"missing auth time", -100 * 365 * 24 * time.Hour, "test-state"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			InitStore([]byte("testsessionkeytestsessionkey1234"), []byte("testencryptionkeytestencrypt1234"), "cookie", 8192, 120)
			provider := newTestProvider(t, []string{"staff"})
			provider.authTime = time.Now().Add(tc.age).Unix()
			provider.nonce = tc.nonce
			o := (&OIDCConfig{OAuth2Config: provider.oauthConfig(), OIDCTokenVerifier: provider.verifier(t)}).New()
			stateRes := httptest.NewRecorder()
			stateReq := httptest.NewRequest("GET", "/connect", nil)
			if err := storeOIDCState(stateRes, stateReq, "test-state", "/connect"); err != nil {
				t.Fatal(err)
			}
			id := identity.NewUser()
			req := identity.AddToRequestCtx(id, httptest.NewRequest("GET", "/callback?state=test-state&code=code", nil))
			for _, cookie := range stateRes.Result().Cookies() {
				req.AddCookie(cookie)
			}
			w := httptest.NewRecorder()
			o.HandleCallback(w, req)
			if w.Code != http.StatusUnauthorized || id.Authenticated() {
				t.Fatalf("stale OIDC authentication accepted status=%d body=%s", w.Code, w.Body.String())
			}
		})
	}
}
