package web

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/security"
)

// tokenClientIP returns the client address that is signed into a gateway
// access token.
func tokenClientIP(t *testing.T, token string) string {
	t.Helper()

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected a JWS in the compact serialization, got %q", token)
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("cannot decode the payload: %v", err)
	}

	claims := struct {
		ClientIP string `json:"clientIp"`
	}{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("cannot decode the claims: %v", err)
	}

	return claims.ClientIP
}

// The address the gateway signs into the gateway access token is the one it
// derived from the request. A client that supplies an address in the
// X-Forwarded-For header cannot influence it.
func TestGatewayAccessTokenIsBoundToTheDerivedAddress(t *testing.T) {
	security.SigningKey = []byte("5aa3a1568fe8421cd7e127d5ace28d2d")

	InitTrustedProxies([]string{"10.0.0.0/8"})
	t.Cleanup(func() { InitTrustedProxies(nil) })

	cases := []struct {
		name string
		xff  string
		want string
	}{
		{
			name: "the proxy overwrote the header",
			xff:  "203.0.113.42",
			want: "203.0.113.42",
		},
		{
			name: "the client prepended an address to the chain",
			xff:  "198.51.100.9, 203.0.113.42",
			want: "10.0.0.1",
		},
		{
			name: "the client spoofed the address of another client",
			xff:  "203.0.113.42",
			want: "203.0.113.42",
		},
		{
			name: "no forwarded header",
			xff:  "",
			want: "10.0.0.1",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var ctx context.Context

			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ctx = r.Context()

				token, err := security.GeneratePAAToken(ctx, "alice", "rdp.example.com")
				if err != nil {
					t.Fatalf("GeneratePAAToken: %v", err)
				}

				if got := tokenClientIP(t, token); got != tc.want {
					t.Errorf("the token is bound to %q, want %q", got, tc.want)
				}
			})

			req := httptest.NewRequest("GET", "/connect", nil)
			req.RemoteAddr = "10.0.0.1:5678"
			if tc.xff != "" {
				req.Header.Set("X-Forwarded-For", tc.xff)
			}

			rr := httptest.NewRecorder()
			EnrichContext(next).ServeHTTP(rr, req)

			if ctx == nil {
				t.Fatal("the middleware did not call the next handler")
			}
		})
	}
}
