// Package access implements the gateway access control policy.
//
// The policy answers two questions for every authenticated user:
//
//   - which client side resources (clipboard, drives, printers, serial
//     ports, plug and play devices, ...) may be redirected into the remote
//     session
//   - which remote hosts the user may connect to
//
// The policy is enforced by the gateway itself and not by the client. The
// resolved redirect policy is signed into the gateway access token and
// replayed in the tunnel authorization response, the generated .rdp file is
// rewritten to match it and the redirect settings can never be overridden
// through the URL.
//
// The default policy is the ceiling: a rule can only narrow it, never widen
// it. That keeps the global configuration in control of what is possible in
// the deployment while still allowing per user or per group restrictions.
package access

import (
	"net"
	"strings"
	"sync"

	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/identity"
)

// HostTemplate is the placeholder that is replaced with the user name in
// host entries.
const HostTemplate = "{{ preferred_username }}"

// Policy is the set of client side resources a user is allowed to redirect
// into a remote session. A false value denies the redirection.
type Policy struct {
	Clipboard bool `json:"clipboard"`
	Drive     bool `json:"drive"`
	Printer   bool `json:"printer"`
	Port      bool `json:"port"`
	Pnp       bool `json:"pnp"`
	SmartCard bool `json:"smartcard"`
	WebAuthn  bool `json:"webauthn"`
	Location  bool `json:"location"`

	// DisableAll forces the client to disable every redirection. It is only
	// used for the global default policy; a rule that narrows the policy
	// drops it in favour of the per resource flags.
	DisableAll bool `json:"disableAll,omitempty"`

	// EnableAll forces the client to enable every redirection. Like
	// DisableAll it is only used for the global default policy.
	EnableAll bool `json:"enableAll,omitempty"`
}

// Overrides is a sparse policy. A nil field means "inherit the default
// policy", a non nil field narrows it.
type Overrides struct {
	Clipboard *bool `json:"clipboard,omitempty"`
	Drive     *bool `json:"drive,omitempty"`
	Printer   *bool `json:"printer,omitempty"`
	Port      *bool `json:"port,omitempty"`
	Pnp       *bool `json:"pnp,omitempty"`
	SmartCard *bool `json:"smartcard,omitempty"`
	WebAuthn  *bool `json:"webauthn,omitempty"`
	Location  *bool `json:"location,omitempty"`
}

// Rule narrows the access policy for the users or groups it matches.
type Rule struct {
	// Name is an optional operator supplied identifier. It is used in log
	// messages to explain which rule was applied.
	Name string

	// Users lists the user names the rule applies to.
	Users []string

	// Groups lists the group names the rule applies to.
	Groups []string

	// Redirect narrows the default redirect policy for the matching users.
	Redirect Overrides

	// Hosts restricts the matching users to the listed hosts. An empty list
	// means the rule does not restrict the hosts at all. The single entry
	// "*" allows any host.
	Hosts []string

	// Deny refuses the matching users access to the gateway. It is the
	// way to keep a user or a group out completely: the redirect policy of
	// a denied user is empty and none of the hosts are reachable.
	Deny bool
}

// Engine evaluates the access policy for the gateway.
type Engine struct {
	defaultPolicy Policy
	rules         []Rule
}

// NewEngine returns an engine with the given default policy and the access
// rules. The default policy is the ceiling: rules can only narrow it.
func NewEngine(defaultPolicy Policy, rules []Rule) *Engine {
	return &Engine{
		defaultPolicy: defaultPolicy,
		rules:         append([]Rule{}, rules...),
	}
}

// PolicyFor returns the effective redirect policy for the identity.
func (e *Engine) PolicyFor(id identity.Identity) Policy {
	policy := e.defaultPolicy

	rule := e.RuleFor(id)
	if rule == nil {
		return policy
	}

	// A denied user has no permissions at all.
	if rule.Deny {
		return Policy{}
	}

	// The "all" switches cannot be expressed per resource. A rule that
	// narrows the policy therefore drops them and the per resource flags
	// are used instead.
	policy.DisableAll = false
	policy.EnableAll = false

	policy.Clipboard = narrow(policy.Clipboard, rule.Redirect.Clipboard)
	policy.Drive = narrow(policy.Drive, rule.Redirect.Drive)
	policy.Printer = narrow(policy.Printer, rule.Redirect.Printer)
	policy.Port = narrow(policy.Port, rule.Redirect.Port)
	policy.Pnp = narrow(policy.Pnp, rule.Redirect.Pnp)
	policy.SmartCard = narrow(policy.SmartCard, rule.Redirect.SmartCard)
	policy.WebAuthn = narrow(policy.WebAuthn, rule.Redirect.WebAuthn)
	policy.Location = narrow(policy.Location, rule.Redirect.Location)

	return policy
}

// narrow applies an override to the default value. The default is the
// ceiling: an override can only deny, never grant.
func narrow(defaultValue bool, override *bool) bool {
	if override == nil {
		return defaultValue
	}
	return defaultValue && *override
}

// RuleFor returns the first rule that matches the identity. Rules are
// evaluated in order and the first match wins.
func (e *Engine) RuleFor(id identity.Identity) *Rule {
	if id == nil {
		return nil
	}

	user := id.UserName()
	groups := id.Groups()

	for i := range e.rules {
		if e.rules[i].matches(user, groups) {
			return &e.rules[i]
		}
	}

	return nil
}

// matches reports whether the rule applies to the user or to one of the
// groups the user is a member of.
func (r *Rule) matches(user string, groups []string) bool {
	for _, u := range r.Users {
		u = strings.TrimSpace(u)
		if u == "" || user == "" {
			continue
		}
		if strings.EqualFold(u, user) {
			return true
		}
	}

	for _, g := range r.Groups {
		g = strings.TrimSpace(g)
		if g == "" {
			continue
		}
		for _, member := range groups {
			if strings.EqualFold(g, strings.TrimSpace(member)) {
				return true
			}
		}
	}

	return false
}

// HostAllowed reports whether the identity may connect to the host. The
// global host selection rules are enforced elsewhere; this only applies the
// per user and per group ACL.
func (e *Engine) HostAllowed(id identity.Identity, host string) bool {
	rule := e.RuleFor(id)
	if rule == nil {
		return true
	}

	if rule.Deny {
		return false
	}

	if len(rule.Hosts) == 0 {
		return true
	}

	return rule.allowsHost(host, e.userName(id))
}

// AllowedHosts returns the hosts the identity may connect to out of the
// given list. When no rule restricts the user all hosts are returned.
func (e *Engine) AllowedHosts(id identity.Identity, hosts []string) []string {
	rule := e.RuleFor(id)
	if rule == nil {
		return append([]string{}, hosts...)
	}

	if rule.Deny {
		return []string{}
	}

	if len(rule.Hosts) == 0 {
		return append([]string{}, hosts...)
	}

	allowed := make([]string, 0, len(hosts))
	for _, host := range hosts {
		if rule.allowsHost(host, e.userName(id)) {
			allowed = append(allowed, host)
		}
	}

	return allowed
}

// userName returns the user name of the identity, if any.
func (e *Engine) userName(id identity.Identity) string {
	if id == nil {
		return ""
	}
	return id.UserName()
}

// allowsHost reports whether the host is in the list of hosts the rule
// allows. The special value "*" allows any host.
func (r *Rule) allowsHost(host string, user string) bool {
	host = expandHost(host, user)

	for _, allowed := range r.Hosts {
		allowed = expandHost(strings.TrimSpace(allowed), user)
		if allowed == "*" {
			return true
		}
		if hostMatches(allowed, host) {
			return true
		}
	}

	return false
}

// expandHost replaces the user name placeholder in a host entry.
func expandHost(host string, user string) string {
	if user == "" {
		return host
	}
	return strings.Replace(host, HostTemplate, user, 1)
}

// hostMatches compares two host entries. The comparison is case
// insensitive and ignores the port when one of the two entries carries one,
// so that "10.0.0.1" matches a connection to "10.0.0.1:3389".
func hostMatches(allowed string, host string) bool {
	if strings.EqualFold(allowed, host) {
		return true
	}

	allowedHost, _, allowedErr := net.SplitHostPort(allowed)
	hostHost, _, hostErr := net.SplitHostPort(host)
	if allowedErr != nil || hostErr != nil {
		return false
	}

	return strings.EqualFold(allowedHost, hostHost)
}

var (
	engineMu sync.RWMutex
	engine   = NewEngine(Policy{}, nil)
)

// Init installs the access policy engine. It is called once during startup
// with the configuration of the gateway.
func Init(e *Engine) {
	engineMu.Lock()
	defer engineMu.Unlock()

	if e == nil {
		e = NewEngine(Policy{}, nil)
	}
	engine = e
}

// Current returns the installed access policy engine.
func Current() *Engine {
	engineMu.RLock()
	defer engineMu.RUnlock()
	return engine
}
