package web

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"golang.org/x/oauth2"
)

func TestMalformedSessionCookieKeepsNewLoginVerifier(t *testing.T) {
	InitStore([]byte("testsessionkeytestsessionkey1234"), []byte("testencryptionkeytestencrypt1234"), "cookie", 8192, 120)
	o := (&OIDCConfig{OAuth2Config: &oauth2.Config{ClientID: "test", Endpoint: oauth2.Endpoint{AuthURL: "https://keycloak.example/auth"}}}).New()
	req := httptest.NewRequest("GET", "https://gateway.example/connect", nil)
	req.AddCookie(&http.Cookie{Name: rdpGwSession, Value: "invalid-cookie"})
	w := httptest.NewRecorder()
	EnrichContext(o.Authenticated(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("anonymous reached handler") }))).ServeHTTP(w, req)
	if w.Code != http.StatusFound {
		t.Fatalf("login status=%d body=%s", w.Code, w.Body.String())
	}
	u, _ := url.Parse(w.Header().Get("Location"))
	callback := httptest.NewRequest("GET", "https://gateway.example/callback", nil)
	for _, c := range w.Result().Cookies() {
		callback.Header.Set("Cookie", c.Name+"="+c.Value)
	}
	s, err := GetSession(callback)
	if err != nil {
		t.Fatal(err)
	}
	verifier, _ := s.Values[oidcVerifierKey].(string)
	hash := sha256.Sum256([]byte(verifier))
	if verifier == "" || u.Query().Get("code_challenge") != base64.RawURLEncoding.EncodeToString(hash[:]) {
		t.Fatal("login challenge does not match persisted verifier after invalid-cookie recovery")
	}
}

func TestOIDCStateCookieUsesSecureDefaultsOnNewRequest(t *testing.T) {
	InitStore([]byte("testsessionkeytestsessionkey1234"), []byte("testencryptionkeytestencrypt1234"), "cookie", 8192, 120)
	w := httptest.NewRecorder()
	if err := storeOIDCState(w, httptest.NewRequest("GET", "https://gateway.example/connect", nil), "state", "/connect"); err != nil {
		t.Fatal(err)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == rdpGwSession && (!c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode) {
			t.Fatal("OIDC state cookie lost security attributes on a new request")
		}
	}
}
