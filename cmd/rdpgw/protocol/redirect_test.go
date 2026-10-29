package protocol

import (
	"testing"

	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/access"
)

// The redirect flags of the session take precedence over the default
// policy of the gateway. They are the policy of the user that the gateway
// enforces, the client cannot widen it.
func TestTunnelAuthUsesSessionRedirectFlags(t *testing.T) {
	client := ClientConfig{
		Name: "test_name",
	}

	gw := &Gateway{
		TokenAuth:     true,
		IdleTimeout:   10,
		RedirectFlags: RedirectFlags{Clipboard: true, Drive: true},
	}

	sessionFlags := RedirectFlags{Drive: true}
	tunnel := &Tunnel{RedirectFlags: &sessionFlags}
	h := NewProcessor(gw, tunnel)

	data := h.tunnelAuthResponse(ERROR_SUCCESS)
	_, _, pkt, err := verifyPacketHeader(data, PKT_TYPE_TUNNEL_AUTH_RESPONSE, TunnelAuthResponseLen)
	if err != nil {
		t.Fatalf("verifyHeader failed: %s", err)
	}

	flags, _, err := client.tunnelAuthResponse(pkt)
	if err != nil {
		t.Fatalf("tunnel auth error %s", err)
	}

	if (flags & HTTP_TUNNEL_REDIR_DISABLE_CLIPBOARD) != HTTP_TUNNEL_REDIR_DISABLE_CLIPBOARD {
		t.Errorf("the clipboard must be disabled for the session, got flags %d", flags)
	}
	if (flags & HTTP_TUNNEL_REDIR_DISABLE_DRIVE) == HTTP_TUNNEL_REDIR_DISABLE_DRIVE {
		t.Errorf("the drive must be allowed for the session, got flags %d", flags)
	}
	if (flags & HTTP_TUNNEL_REDIR_DISABLE_PRINTER) != HTTP_TUNNEL_REDIR_DISABLE_PRINTER {
		t.Errorf("the printer must be disabled for the session, got flags %d", flags)
	}
}

func TestRedirectFlagsFromPolicy(t *testing.T) {
	cases := []struct {
		name   string
		policy access.Policy
		want   RedirectFlags
	}{
		{
			name:   "everything denied",
			policy: access.Policy{},
			want:   RedirectFlags{},
		},
		{
			name:   "clipboard and drive allowed",
			policy: access.Policy{Clipboard: true, Drive: true},
			want:   RedirectFlags{Clipboard: true, Drive: true},
		},
		{
			name:   "disable all",
			policy: access.Policy{DisableAll: true},
			want:   RedirectFlags{DisableAll: true},
		},
		{
			name:   "enable all",
			policy: access.Policy{EnableAll: true},
			want:   RedirectFlags{EnableAll: true},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := RedirectFlagsFromPolicy(tc.policy)
			if got != tc.want {
				t.Errorf("RedirectFlagsFromPolicy() = %+v, want %+v", got, tc.want)
			}
		})
	}
}
