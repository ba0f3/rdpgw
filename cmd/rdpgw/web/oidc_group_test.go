package web

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/identity"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"golang.org/x/oauth2"
)

const testKeyID = "rdpgw-test-key"

// testProvider is a minimal OpenID Connect provider. It serves the token
// endpoint and the key set of the provider so that the gateway can verify
// an ID token.
type testProvider struct {
	server *httptest.Server
	key    *rsa.PrivateKey
	// groups are the groups of the user the ID token is issued for.
	groups []string
}

func newTestProvider(t *testing.T, groups []string) *testProvider {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("cannot generate a key: %v", err)
	}

	p := &testProvider{key: key, groups: groups}

	mux := http.NewServeMux()
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		jwks := map[string]interface{}{
			"keys": []map[string]string{
				{
					"kty": "RSA",
					"kid": testKeyID,
					"use": "sig",
					"alg": "RS256",
					"n":   base64URL(key.N.Bytes()),
					"e":   base64URL(bigEndianExponent(key.PublicKey.E)),
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		idToken, err := p.idToken()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "an-access-token",
			"token_type":   "Bearer",
			"expires_in":   300,
			"id_token":     idToken,
		})
	})

	p.server = httptest.NewServer(mux)
	t.Cleanup(p.server.Close)

	return p
}

// idToken returns a signed ID token for the user of the provider.
func (p *testProvider) idToken() (string, error) {
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: p.key, KeyID: testKeyID}},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		return "", err
	}

	now := time.Now()
	claims := jwt.Claims{
		Issuer:   p.server.URL,
		Subject:  "alice",
		Audience: jwt.Audience{"rdpgw-test"},
		Expiry:   jwt.NewNumericDate(now.Add(5 * time.Minute)),
		IssuedAt: jwt.NewNumericDate(now),
	}

	custom := map[string]interface{}{
		"preferred_username": "alice",
		"groups":             p.groups,
	}

	token, err := jwt.Signed(signer).Claims(claims).Claims(custom).Serialize()
	if err != nil {
		return "", err
	}

	return token, nil
}

// verifier returns a verifier for the ID tokens of the provider.
func (p *testProvider) verifier(t *testing.T) *oidc.IDTokenVerifier {
	t.Helper()

	keySet := oidc.NewRemoteKeySet(context.Background(), p.server.URL+"/keys")

	return oidc.NewVerifier(p.server.URL, keySet, &oidc.Config{ClientID: "rdpgw-test"})
}

// oauthConfig returns the oauth2 configuration of the provider.
func (p *testProvider) oauthConfig() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     "rdpgw-test",
		ClientSecret: "secret",
		RedirectURL:  "http://127.0.0.1/callback",
		Endpoint: oauth2.Endpoint{
			TokenURL: p.server.URL + "/token",
		},
		Scopes: []string{oidc.ScopeOpenID},
	}
}

// TestOIDCCallbackGroupAllowList asserts that only the members of an
// allowed group can log in to the gateway.
func TestOIDCCallbackGroupAllowList(t *testing.T) {
	cases := []struct {
		name       string
		groups     []string
		allowed    []string
		wantStatus int
	}{
		{
			name:       "member of an allowed group",
			groups:     []string{"rdpgw-users", "other"},
			allowed:    []string{"rdpgw-users"},
			wantStatus: http.StatusFound,
		},
		{
			name:       "member of no allowed group",
			groups:     []string{"other"},
			allowed:    []string{"rdpgw-users"},
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "user without any group",
			groups:     nil,
			allowed:    []string{"rdpgw-users"},
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "no allow list lets every user in",
			groups:     []string{"other"},
			allowed:    nil,
			wantStatus: http.StatusFound,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sessionKey := []byte("testsessionkeytestsessionkey1234")
			encryptionKey := []byte("testencryptionkeytestencrypt1234")
			InitStore(sessionKey, encryptionKey, "cookie", 8192, 120)

			provider := newTestProvider(t, tc.groups)

			o := (&OIDCConfig{
				OAuth2Config:      provider.oauthConfig(),
				OIDCTokenVerifier: provider.verifier(t),
				AllowedGroups:     tc.allowed,
				GroupsClaim:       "groups",
			}).New()

			// store the state of the authentication flow in the session
			state := "test-state"
			stateReq := httptest.NewRequest("GET", "/connect", nil)
			stateRes := httptest.NewRecorder()
			if err := storeOIDCState(stateRes, stateReq, state, "/"); err != nil {
				t.Fatalf("cannot store the state: %v", err)
			}

			callbackReq := httptest.NewRequest("GET", "/callback?state="+state+"&code=the-code", nil)
			for _, cookie := range stateRes.Result().Cookies() {
				callbackReq.AddCookie(cookie)
			}

			id := identity.NewUser()
			callbackReq = identity.AddToRequestCtx(id, callbackReq)

			callbackRes := httptest.NewRecorder()
			o.HandleCallback(callbackRes, callbackReq)

			if callbackRes.Code != tc.wantStatus {
				t.Fatalf("callback returned status %d, want %d: %s",
					callbackRes.Code, tc.wantStatus, callbackRes.Body.String())
			}

			if tc.wantStatus != http.StatusFound {
				// the user must not be authenticated
				if id.Authenticated() {
					t.Errorf("the user is authenticated although the group is not allowed")
				}
				return
			}

			if !id.Authenticated() {
				t.Errorf("the user is not authenticated")
			}
			if id.UserName() != "alice" {
				t.Errorf("the user name is %q, want alice", id.UserName())
			}
			if len(id.Groups()) != len(tc.groups) {
				t.Errorf("the groups are %v, want %v", id.Groups(), tc.groups)
			}
		})
	}
}

func base64URL(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func bigEndianExponent(e int) []byte {
	exponent := make([]byte, 4)
	exponent[0] = byte(e >> 24)
	exponent[1] = byte(e >> 16)
	exponent[2] = byte(e >> 8)
	exponent[3] = byte(e)
	return exponent
}
