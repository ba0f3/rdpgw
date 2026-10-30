// Package access implements the gateway access control policy.
//
// The policy answers two questions for every authenticated user:
//
//   - which client side resources (clipboard, drives, printers, serial
//     ports, plug and play devices, cameras, USB devices, ...) may be
//     redirected into the remote session
//   - which remote hosts the user may connect to
//
// The policy is enforced by the gateway itself and not by the client. The
// resolved redirect policy is signed into the gateway access token and
// replayed in the tunnel authorization response, the generated .rdp file
// is rewritten to match it and the redirect settings can never be
// overridden through the URL.
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
	Camera    bool `json:"camera"`
	Usb       bool `json:"usb"`

	// DisableAll forces the client to disable every redirection. It is only
	// used for the global default policy; a rule that narrows the policy
	// drops it in favour of the per resource flags.
	DisableAll bool `json:"disableAll,omitempty"`

	// EnableAll forces the client to enable every redirection. Like
	// DisableAll it is only used for the global default policy.
	EnableAll bool `json:"enableAll,omitempty"`
}

// Narrow returns the policy that allows only the resources that both this
// policy and the other one allow. It is used to keep the policy of the
// gateway the ceiling of the policy that is signed into a gateway access
// token: a token that was issued under a looser policy does not widen the
// policy of the gateway.
func (p Policy) Narrow(other Policy) Policy {
	if p.DisableAll || other.DisableAll {
		return Policy{DisableAll: true}
	}

	narrowed := Policy{
		Clipboard: p.Clipboard && other.Clipboard,
		Drive:     p.Drive && other.Drive,
		Printer:   p.Printer && other.Printer,
		Port:      p.Port && other.Port,
		Pnp:       p.Pnp && other.Pnp,
		SmartCard: p.SmartCard && other.SmartCard,
		WebAuthn:  p.WebAuthn && other.WebAuthn,
		Location:  p.Location && other.Location,
		Camera:    p.Camera && other.Camera,
		Usb:       p.Usb && other.Usb,
	}

	if p.EnableAll && other.EnableAll {
		narrowed.EnableAll = true
	}

	return narrowed
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
	Camera    *bool `json:"camera,omitempty"`
	Usb       *bool `json:"usb,omitempty"`
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
	// way to keep a user or a group out completely: the user cannot log
	// in, the redirect policy of a denied user is empty and none of the
	// hosts are reachable.
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
	policy.Camera = narrow(policy.Camera, rule.Redirect.Camera)
	policy.Usb = narrow(policy.Usb, rule.Redirect.Usb)

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

// RuleFor returns the rule that applies to the identity. A rule that denies
// the user wins over every other rule, the first rule that matches the
// user applies otherwise.
func (e *Engine) RuleFor(id identity.Identity) *Rule {
	if id == nil {
		return nil
	}

	user := id.UserName()
	groups := id.Groups()

	for i := range e.rules {
		if e.rules[i].Deny && e.rules[i].matches(user, groups) {
			return &e.rules[i]
		}
	}

	for i := range e.rules {
		if e.rules[i].matches(user, groups) {
			return &e.rules[i]
		}
	}

	return nil
}

// Denied reports whether the access policy refuses the user. A denied user
// cannot log in and cannot reach any host.
func (e *Engine) Denied(id identity.Identity) bool {
	rule := e.RuleFor(id)
	return rule != nil && rule.Deny
}

// matches reports whether the rule applies to the user or to one of the
// groups the user is a member of.
//
// A rule that selects a group also applies to the users whose group
// membership the gateway does not know: the gateway cannot tell whether
// they are a member of the group, and a rule that selects a group must not
// fail open for them. A rule that selects a user by name needs no group
// membership and is not affected.
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

	if len(r.Groups) == 0 {
		return false
	}

	if len(groups) == 0 {
		// The group membership is unknown.
		return len(r.Users) == 0
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
// insensitive. The port of the requested host is ignored when the allowed
// entry does not carry one, so that "10.0.0.1" matches a connection to
// "10.0.0.1:3389". An allowed entry that carries a port pins the endpoint.
func hostMatches(allowed string, host string) bool {
	if strings.EqualFold(allowed, host) {
		return true
	}

	allowedHost, allowedPort, allowedErr := net.SplitHostPort(allowed)
	hostHost, hostPort, hostErr := net.SplitHostPort(host)

	switch {
	case allowedErr == nil && hostErr == nil:
		// both carry a port, the endpoint has to match
		return strings.EqualFold(allowedHost, hostHost) && allowedPort == hostPort
	case allowedErr != nil && hostErr == nil:
		// only the requested host carries a port, it is ignored
		return strings.EqualFold(allowed, hostHost)
	}

	return false
}

// HasGroupRules reports whether the engine holds rules that select users by
// their group membership. Such rules only apply to the users whose group
// membership is known to the gateway.
func (e *Engine) HasGroupRules() bool {
	for i := range e.rules {
		if len(e.rules[i].Groups) > 0 {
			return true
		}
	}

	return false
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
