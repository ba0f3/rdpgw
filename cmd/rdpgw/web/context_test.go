package web

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/identity"
)

// TestEnrichContextXForwardedForRequiresTrustedProxy asserts that the
// X-Forwarded-For header is only honored when the request arrives from a
// configured trusted proxy. A direct caller can otherwise set XFF to any
// value, taking control of the AttrClientIp attribute that downstream
// session-binding logic compares against.
func TestEnrichContextXForwardedForRequiresTrustedProxy(t *testing.T) {
	cases := []struct {
		name           string
		trustedProxies []string
		remoteAddr     string
		xff            string
		wantClientIp   string
	}{
		{
			name:           "untrusted remote with no XFF uses RemoteAddr",
			trustedProxies: nil,
			remoteAddr:     "198.51.100.7:5678",
			xff:            "",
			wantClientIp:   "198.51.100.7",
		},
		{
			name:           "untrusted remote with XFF still uses RemoteAddr",
			trustedProxies: nil,
			remoteAddr:     "198.51.100.7:5678",
			xff:            "10.20.30.40",
			wantClientIp:   "198.51.100.7",
		},
		{
			name:           "untrusted remote outside allow-list with XFF uses RemoteAddr",
			trustedProxies: []string{"10.0.0.0/8"},
			remoteAddr:     "198.51.100.7:5678",
			xff:            "10.20.30.40",
			wantClientIp:   "198.51.100.7",
		},
		{
			name:           "trusted remote with a single XFF entry uses it",
			trustedProxies: []string{"10.0.0.0/8"},
			remoteAddr:     "10.1.2.3:5678",
			xff:            "203.0.113.42",
			wantClientIp:   "203.0.113.42",
		},
		{
			// A chain with more than one address cannot be attributed
			// to the proxy: a client that prepends an address produces
			// the same chain as a proxy that appends. The proxy has to
			// overwrite the header, the gateway falls back to the
			// address of the socket peer otherwise.
			name:           "a chain with more than one address is ignored",
			trustedProxies: []string{"10.0.0.0/8"},
			remoteAddr:     "10.1.2.3:5678",
			xff:            "203.0.113.42, 10.99.0.1",
			wantClientIp:   "10.1.2.3",
		},
		{
			// The client supplied the first entry itself, the trusted
			// proxy appended the address it saw. The address of the
			// client is not attributable, the header is ignored.
			name:           "spoofed prefix does not win over the appended address",
			trustedProxies: []string{"10.0.0.0/8"},
			remoteAddr:     "10.1.2.3:5678",
			xff:            "198.51.100.9, 203.0.113.42",
			wantClientIp:   "10.1.2.3",
		},
		{
			// The client spoofed the address of another client and put
			// the address of the proxy behind it, the address of the
			// client is not attributable, the header is ignored.
			name:           "spoofed client address does not win",
			trustedProxies: []string{"10.0.0.0/8"},
			remoteAddr:     "10.1.2.3:5678",
			xff:            "203.0.113.42, 198.51.100.9",
			wantClientIp:   "10.1.2.3",
		},
		{
			name:           "trusted remote without XFF uses RemoteAddr",
			trustedProxies: []string{"10.0.0.0/8"},
			remoteAddr:     "10.1.2.3:5678",
			xff:            "",
			wantClientIp:   "10.1.2.3",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			InitTrustedProxies(tc.trustedProxies)
			t.Cleanup(func() { InitTrustedProxies(nil) })

			var captured identity.Identity
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				captured = identity.FromRequestCtx(r)
				w.WriteHeader(http.StatusOK)
			})
			h := EnrichContext(next)

			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = tc.remoteAddr
			if tc.xff != "" {
				req.Header.Set("X-Forwarded-For", tc.xff)
			}

			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)

			if captured == nil {
				t.Fatal("middleware did not store an identity in the request context")
			}
			got, _ := captured.GetAttribute(identity.AttrClientIp).(string)
			if got != tc.wantClientIp {
				t.Errorf("AttrClientIp = %q, want %q (remoteAddr=%q xff=%q trusted=%v)",
					got, tc.wantClientIp, tc.remoteAddr, tc.xff, tc.trustedProxies)
			}
		})
	}
}
