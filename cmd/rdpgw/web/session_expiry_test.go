package web

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/identity"
	"golang.org/x/oauth2"
)

func TestExpiredIdentityCannotBeReplayed(t *testing.T) {
	InitStore(bytes.Repeat([]byte("s"), 32), bytes.Repeat([]byte("e"), 32), "cookie", 8192, 120)
	id := identity.NewUser()
	id.SetUserName("alice")
	id.SetAuthenticated(true)
	id.SetAuthTime(time.Now().Add(-time.Hour))
	req := httptest.NewRequest("GET", "https://gateway/connect", nil)
	w := httptest.NewRecorder()
	if err := SaveSessionIdentity(req, w, id); err != nil {
		t.Fatal(err)
	}
	replay := httptest.NewRequest("GET", "https://gateway/connect", nil)
	for _, cookie := range w.Result().Cookies() {
		replay.AddCookie(cookie)
	}
	got, err := GetSessionIdentity(replay)
	if err != nil {
		t.Fatal(err)
	}
	if got != nil && got.Authenticated() {
		t.Fatal("stale authenticated cookie was accepted")
	}
}

// Retain and explicitly resend a raw cookie after its advertised Max-Age.
// This reproduces the audit's browser-independent replay through middleware.
func TestSessionLifetimeReplayRequiresFreshOIDC(t *testing.T) {
	for _, store := range []string{"cookie", "file"} {
		t.Run(store, func(t *testing.T) {
			InitStore(bytes.Repeat([]byte("s"), 32), bytes.Repeat([]byte("e"), 32), store, 8192, 1)
			id := identity.NewUser()
			id.SetUserName("alice")
			id.SetAuthenticated(true)
			id.SetAuthTime(time.Now())
			req := httptest.NewRequest("GET", "https://gateway.example/connect", nil)
			w := httptest.NewRecorder()
			if err := SaveSessionIdentity(req, w, id); err != nil {
				t.Fatal(err)
			}
			time.Sleep(2100 * time.Millisecond)
			replay := httptest.NewRequest("GET", "https://gateway.example/connect", nil)
			for _, c := range w.Result().Cookies() {
				replay.AddCookie(c)
			}
			o := (&OIDCConfig{OAuth2Config: &oauth2.Config{ClientID: "test", Endpoint: oauth2.Endpoint{AuthURL: "https://keycloak.example/auth"}}}).New()
			reached := false
			out := httptest.NewRecorder()
			EnrichContext(o.Authenticated(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))).ServeHTTP(out, replay)
			if reached || out.Code != http.StatusFound {
				t.Fatalf("expired raw cookie replay reached handler=%v status=%d", reached, out.Code)
			}
		})
	}
}
