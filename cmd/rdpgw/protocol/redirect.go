package protocol

import (
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/access"
)

// RedirectFlagsFromPolicy converts an access policy into the redirect flags
// that are sent to the client in the tunnel authorization response. The
// flags are the authoritative policy of the gateway: the client has to
// honour them, they cannot be changed by the client or by the contents of
// the .rdp file.
func RedirectFlagsFromPolicy(policy access.Policy) RedirectFlags {
	if policy.DisableAll {
		return RedirectFlags{DisableAll: true}
	}

	if policy.EnableAll {
		return RedirectFlags{EnableAll: true}
	}

	return RedirectFlags{
		Clipboard: policy.Clipboard,
		Drive:     policy.Drive,
		Printer:   policy.Printer,
		Port:      policy.Port,
		Pnp:       policy.Pnp,
	}
}
