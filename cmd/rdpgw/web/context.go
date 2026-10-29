package web

import (
	"log"
	"net"
	"net/http"
	"strings"

	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/identity"
	"github.com/jcmturner/goidentity/v6"
)

// trustedProxyNets is the CIDR allow-list of upstream proxies whose
// X-Forwarded-For header is honored. Empty (the default) means XFF is
// ignored entirely and the client IP is taken from r.RemoteAddr.
var trustedProxyNets []*net.IPNet

// InitTrustedProxies parses the operator-supplied CIDRs once at startup.
// A bad CIDR is fatal; an empty list disables XFF-derived client-IP
// attribution.
func InitTrustedProxies(cidrs []string) {
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, raw := range cidrs {
		_, n, err := net.ParseCIDR(raw)
		if err != nil {
			log.Fatalf("trustedproxies: invalid CIDR %q: %s", raw, err)
		}
		nets = append(nets, n)
	}
	trustedProxyNets = nets
}

// remoteIsTrustedProxy reports whether the request arrived from one of the
// trusted proxies.
func remoteIsTrustedProxy(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}

	return ipIsTrustedProxy(host)
}

// ipIsTrustedProxy reports whether the address is in the allow-list of the
// trusted proxies.
func ipIsTrustedProxy(host string) bool {
	if len(trustedProxyNets) == 0 {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, n := range trustedProxyNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func EnrichContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := GetSessionIdentity(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if id == nil {
			id = identity.NewUser()
			if err := SaveSessionIdentity(r, w, id); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}

		log.Printf("Identity SessionId: %s, UserName: %s: Authenticated: %t",
			id.SessionId(), id.UserName(), id.Authenticated())

		id.SetAttribute(identity.AttrRemoteAddr, r.RemoteAddr)

		remoteHost, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			remoteHost = r.RemoteAddr
		}

		clientIp := remoteHost
		var proxies []string
		if remoteIsTrustedProxy(r.RemoteAddr) {
			if h := r.Header.Get("X-Forwarded-For"); h != "" {
				ips := strings.Split(h, ",")
				for i := range ips {
					ips[i] = strings.TrimSpace(ips[i])
				}

				// The chain is ordered from the client to the proxies:
				// the addresses on the right are the ones the trusted
				// proxies appended and are more trustworthy than the ones
				// a client could have supplied itself. The client address
				// is therefore the right most address that is not a
				// trusted proxy. Taking the first one would let a client
				// spoof the address the gateway binds the credentials of
				// the session to.
				for i := len(ips) - 1; i >= 0; i-- {
					if ips[i] == "" {
						continue
					}
					if ipIsTrustedProxy(ips[i]) {
						continue
					}
					clientIp = ips[i]
					proxies = ips[i+1:]
					break
				}
			}
		}
		id.SetAttribute(identity.AttrClientIp, clientIp)
		id.SetAttribute(identity.AttrProxies, proxies)

		next.ServeHTTP(w, identity.AddToRequestCtx(id, r))
	})
}

func TransposeSPNEGOContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gid := goidentity.FromHTTPRequestContext(r)
		if gid != nil {
			id := identity.FromRequestCtx(r)
			id.SetUserName(gid.UserName())
			id.SetAuthenticated(gid.Authenticated())
			id.SetDomain(gid.Domain())
			id.SetAuthTime(gid.AuthTime())
			// the group membership of a previous login does not apply to
			// this user
			id.SetGroups(nil)
			r = identity.AddToRequestCtx(id, r)
		}
		next.ServeHTTP(w, r)
	})
}
