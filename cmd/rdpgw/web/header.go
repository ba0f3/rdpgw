package web

import (
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/identity"
)

type Header struct {
	userHeader        string
	userIdHeader      string
	emailHeader       string
	displayNameHeader string
	groupsHeader      string
	trustedProxies    []*net.IPNet
}

type HeaderConfig struct {
	UserHeader        string
	UserIdHeader      string
	EmailHeader       string
	DisplayNameHeader string
	// GroupsHeader is the header that carries the group membership of the
	// user. The value is a comma separated list of group names. It is used
	// by the access policy to apply per group restrictions.
	GroupsHeader string
	// TrustedProxies is the CIDR allow-list of upstream proxies that may
	// stamp the configured user header. The check is applied to the
	// immediate RemoteAddr of the request — operators must configure their
	// proxy to strip duplicate inbound copies of the user header.
	// Empty disables header auth entirely (every request is refused).
	TrustedProxies []string
}

func (c *HeaderConfig) New() *Header {
	nets := make([]*net.IPNet, 0, len(c.TrustedProxies))
	for _, raw := range c.TrustedProxies {
		_, n, err := net.ParseCIDR(raw)
		if err != nil {
			log.Fatalf("header auth: invalid TrustedProxies entry %q: %s", raw, err)
		}
		nets = append(nets, n)
	}
	if len(nets) == 0 {
		log.Printf("header auth: no TrustedProxies configured; every request will be refused")
	}
	return &Header{
		userHeader:        c.UserHeader,
		userIdHeader:      c.UserIdHeader,
		emailHeader:       c.EmailHeader,
		displayNameHeader: c.DisplayNameHeader,
		groupsHeader:      c.GroupsHeader,
		trustedProxies:    nets,
	}
}

func (h *Header) remoteIPTrusted(remoteAddr string) bool {
	if len(h.trustedProxies) == 0 {
		return false
	}
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, n := range h.trustedProxies {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// splitGroups splits the value of a groups header into the individual
// group names. The value is a comma separated list.
func splitGroups(value string) []string {
	parts := strings.Split(value, ",")
	groups := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		groups = append(groups, part)
	}
	return groups
}

// Authenticated middleware that extracts user identity from configurable proxy headers
func (h *Header) Authenticated(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := identity.FromRequestCtx(r)

		// Check if user is already authenticated
		if id.Authenticated() {
			next.ServeHTTP(w, r)
			return
		}

		// The user header is only meaningful when stamped by a trusted
		// upstream. Without that gate any caller on the network can mint
		// an authenticated session.
		if !h.remoteIPTrusted(r.RemoteAddr) {
			log.Printf("header auth: rejecting request from untrusted remote %s", r.RemoteAddr)
			http.Error(w, "Untrusted upstream", http.StatusUnauthorized)
			return
		}

		// Extract username from configured user header
		userName := r.Header.Get(h.userHeader)
		if userName == "" {
			http.Error(w, "No authenticated user from proxy", http.StatusUnauthorized)
			return
		}

		// Set identity for downstream processing
		id.SetUserName(userName)
		id.SetAuthTime(time.Now())

		// Set optional user attributes from headers
		if h.userIdHeader != "" {
			if userId := r.Header.Get(h.userIdHeader); userId != "" {
				id.SetAttribute("user_id", userId)
			}
		}

		if h.emailHeader != "" {
			if email := r.Header.Get(h.emailHeader); email != "" {
				id.SetEmail(email)
			}
		}

		if h.displayNameHeader != "" {
			if displayName := r.Header.Get(h.displayNameHeader); displayName != "" {
				id.SetDisplayName(displayName)
			}
		}

		if h.groupsHeader != "" {
			if groups := r.Header.Get(h.groupsHeader); groups != "" {
				id.SetGroups(splitGroups(groups))
			}
		}

		// The access policy can refuse the user even when the proxy
		// authenticated them. The user is not marked as authenticated
		// before the check, a refused user must not end up with a
		// session.
		if refuseDeniedUser(w, id) {
			return
		}

		id.SetAuthenticated(true)

		// Save the session identity
		if err := SaveSessionIdentity(r, w, id); err != nil {
			http.Error(w, "Failed to save session: "+err.Error(), http.StatusInternalServerError)
			return
		}

		next.ServeHTTP(w, r)
	})
}
