package access

import (
	"testing"

	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/identity"
)

func boolPtr(b bool) *bool {
	return &b
}

func testUser(name string, groups ...string) *identity.User {
	u := identity.NewUser()
	u.SetUserName(name)
	u.SetGroups(groups)
	return u
}

func TestPolicyForWithoutRules(t *testing.T) {
	engine := NewEngine(Policy{Clipboard: true, Drive: true}, nil)

	policy := engine.PolicyFor(testUser("alice"))
	if !policy.Clipboard || !policy.Drive {
		t.Fatalf("policy = %+v, want clipboard and drive to be allowed", policy)
	}
	if policy.Printer {
		t.Fatalf("policy = %+v, want printer to be denied", policy)
	}
}

func TestPolicyForRuleNarrowsDefault(t *testing.T) {
	engine := NewEngine(
		Policy{Clipboard: true, Drive: true, Printer: true},
		[]Rule{
			{
				Name:     "no clipboard",
				Users:    []string{"alice"},
				Redirect: Overrides{Clipboard: boolPtr(false)},
			},
		},
	)

	policy := engine.PolicyFor(testUser("alice"))
	if policy.Clipboard {
		t.Errorf("policy = %+v, want the clipboard to be denied for alice", policy)
	}
	if !policy.Drive || !policy.Printer {
		t.Errorf("policy = %+v, want the other resources to be inherited", policy)
	}

	// A user that does not match the rule keeps the default policy.
	policy = engine.PolicyFor(testUser("bob"))
	if !policy.Clipboard {
		t.Errorf("policy = %+v, want the clipboard to be allowed for bob", policy)
	}
}

// A rule may only narrow the policy, it can never widen it. The global
// capabilities are the ceiling of the deployment.
func TestPolicyForRuleCannotWidenDefault(t *testing.T) {
	engine := NewEngine(
		Policy{Clipboard: false, Drive: true},
		[]Rule{
			{
				Users:    []string{"alice"},
				Redirect: Overrides{Clipboard: boolPtr(true), Drive: boolPtr(true)},
			},
		},
	)

	policy := engine.PolicyFor(testUser("alice"))
	if policy.Clipboard {
		t.Errorf("policy = %+v, want the clipboard to stay denied", policy)
	}
	if !policy.Drive {
		t.Errorf("policy = %+v, want the drive to be allowed", policy)
	}
}

func TestPolicyForGroupRule(t *testing.T) {
	engine := NewEngine(
		Policy{Drive: true},
		[]Rule{
			{
				Groups:   []string{"contractors"},
				Redirect: Overrides{Drive: boolPtr(false)},
			},
		},
	)

	if engine.PolicyFor(testUser("alice", "contractors")).Drive {
		t.Errorf("a member of the contractors group must not be allowed to redirect drives")
	}

	if !engine.PolicyFor(testUser("alice", "employees")).Drive {
		t.Errorf("a member of the employees group must be allowed to redirect drives")
	}
}

// The first rule that matches the user wins.
func TestPolicyForFirstRuleWins(t *testing.T) {
	engine := NewEngine(
		Policy{Drive: true},
		[]Rule{
			{
				Name:     "first",
				Groups:   []string{"staff"},
				Redirect: Overrides{Drive: boolPtr(false)},
			},
			{
				Name:     "second",
				Groups:   []string{"staff"},
				Redirect: Overrides{Drive: boolPtr(true)},
			},
		},
	)

	if engine.PolicyFor(testUser("alice", "staff")).Drive {
		t.Errorf("the first matching rule must win")
	}
}

// A rule that narrows the policy drops the "all" switches of the default
// policy, they cannot be expressed per resource.
func TestPolicyForRuleDropsAllSwitches(t *testing.T) {
	engine := NewEngine(
		Policy{EnableAll: true, Clipboard: true, Drive: true},
		[]Rule{
			{
				Users:    []string{"alice"},
				Redirect: Overrides{Clipboard: boolPtr(false)},
			},
		},
	)

	policy := engine.PolicyFor(testUser("alice"))
	if policy.EnableAll || policy.DisableAll {
		t.Errorf("policy = %+v, want the all switches to be dropped", policy)
	}
	if policy.Clipboard {
		t.Errorf("policy = %+v, want the clipboard to be denied", policy)
	}
	if !policy.Drive {
		t.Errorf("policy = %+v, want the drive to be allowed", policy)
	}
}

func TestHostAllowed(t *testing.T) {
	engine := NewEngine(
		Policy{},
		[]Rule{
			{
				Users: []string{"alice"},
				Hosts: []string{"10.0.0.1", "10.0.0.2:3389"},
			},
		},
	)

	if !engine.HostAllowed(testUser("alice"), "10.0.0.1") {
		t.Errorf("alice must be allowed to connect to 10.0.0.1")
	}

	// the port is ignored when the rule lists the host without one
	if !engine.HostAllowed(testUser("alice"), "10.0.0.2:3389") {
		t.Errorf("alice must be allowed to connect to 10.0.0.2:3389")
	}

	if engine.HostAllowed(testUser("alice"), "10.0.0.3") {
		t.Errorf("alice must not be allowed to connect to 10.0.0.3")
	}

	// a user that does not match the rule is not restricted
	if !engine.HostAllowed(testUser("bob"), "10.0.0.3") {
		t.Errorf("bob must not be restricted by the rule of alice")
	}
}

func TestHostAllowedWildcard(t *testing.T) {
	engine := NewEngine(
		Policy{},
		[]Rule{
			{
				Groups: []string{"admins"},
				Hosts:  []string{"*"},
			},
		},
	)

	if !engine.HostAllowed(testUser("alice", "admins"), "10.0.0.99") {
		t.Errorf("the wildcard must allow any host")
	}
}

func TestHostAllowedUserTemplate(t *testing.T) {
	engine := NewEngine(
		Policy{},
		[]Rule{
			{
				Users: []string{"alice"},
				Hosts: []string{"host-" + HostTemplate},
			},
		},
	)

	if !engine.HostAllowed(testUser("alice"), "host-alice") {
		t.Errorf("the host template must be expanded with the user name")
	}

	// the rule only applies to alice, it does not restrict other users
	if !engine.HostAllowed(testUser("bob"), "host-alice") {
		t.Errorf("the rule of alice must not restrict bob")
	}
}

func TestAllowedHosts(t *testing.T) {
	engine := NewEngine(
		Policy{},
		[]Rule{
			{
				Users: []string{"alice"},
				Hosts: []string{"10.0.0.2"},
			},
		},
	)

	hosts := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}

	allowed := engine.AllowedHosts(testUser("alice"), hosts)
	if len(allowed) != 1 || allowed[0] != "10.0.0.2" {
		t.Errorf("allowed = %v, want [10.0.0.2]", allowed)
	}

	allowed = engine.AllowedHosts(testUser("bob"), hosts)
	if len(allowed) != len(hosts) {
		t.Errorf("allowed = %v, want all hosts", allowed)
	}
}

// A rule can refuse a user or a group access to the gateway completely.
func TestDenyRule(t *testing.T) {
	engine := NewEngine(
		Policy{Clipboard: true, Drive: true},
		[]Rule{
			{
				Groups: []string{"blocked"},
				Deny:   true,
			},
		},
	)

	denied := testUser("mallory", "blocked")
	allowed := testUser("alice", "staff")

	policy := engine.PolicyFor(denied)
	if policy.Clipboard || policy.Drive {
		t.Errorf("policy = %+v, want a denied user to have no permissions", policy)
	}

	if engine.HostAllowed(denied, "10.0.0.1") {
		t.Errorf("a denied user must not be allowed to connect to a host")
	}

	if len(engine.AllowedHosts(denied, []string{"10.0.0.1"})) != 0 {
		t.Errorf("a denied user must not have any host")
	}

	if !engine.HostAllowed(allowed, "10.0.0.1") {
		t.Errorf("a user that is not denied must be allowed to connect")
	}
}

func TestPolicyNarrow(t *testing.T) {
	cases := []struct {
		name     string
		policy   Policy
		other    Policy
		expected Policy
	}{
		{
			name:     "the intersection of two policies",
			policy:   Policy{Clipboard: true, Drive: true},
			other:    Policy{Clipboard: true},
			expected: Policy{Clipboard: true},
		},
		{
			name:     "disable all wins",
			policy:   Policy{Clipboard: true},
			other:    Policy{DisableAll: true},
			expected: Policy{DisableAll: true},
		},
		{
			name:     "enable all and a per resource policy",
			policy:   Policy{EnableAll: true, Clipboard: true, Drive: true},
			other:    Policy{Clipboard: true},
			expected: Policy{Clipboard: true},
		},
		{
			name:     "enable all twice",
			policy:   Policy{EnableAll: true, Clipboard: true, Drive: true},
			other:    Policy{EnableAll: true, Clipboard: true, Drive: true},
			expected: Policy{EnableAll: true, Clipboard: true, Drive: true},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.policy.Narrow(tc.other)
			if got != tc.expected {
				t.Errorf("Narrow() = %+v, want %+v", got, tc.expected)
			}
		})
	}
}

// The port of the requested host is ignored when the allowed entry does not
// carry one.
func TestHostMatchesWithoutPort(t *testing.T) {
	cases := []struct {
		allowed string
		host    string
		want    bool
	}{
		{allowed: "10.0.0.1", host: "10.0.0.1:3389", want: true},
		{allowed: "10.0.0.1", host: "10.0.0.1", want: true},
		{allowed: "10.0.0.1:3389", host: "10.0.0.1:3389", want: true},
		{allowed: "10.0.0.1:3389", host: "10.0.0.1:3390", want: false},
		{allowed: "10.0.0.1", host: "10.0.0.2:3389", want: false},
		{allowed: "10.0.0.1", host: "10.0.0.2", want: false},
	}

	for _, tc := range cases {
		t.Run(tc.allowed+" "+tc.host, func(t *testing.T) {
			if got := hostMatches(tc.allowed, tc.host); got != tc.want {
				t.Errorf("hostMatches(%q, %q) = %v, want %v", tc.allowed, tc.host, got, tc.want)
			}
		})
	}
}

func TestHasGroupRules(t *testing.T) {
	engine := NewEngine(Policy{}, nil)
	if engine.HasGroupRules() {
		t.Errorf("an engine without rules has no group rules")
	}

	engine = NewEngine(Policy{}, []Rule{{Groups: []string{"staff"}}})
	if !engine.HasGroupRules() {
		t.Errorf("an engine with a group rule has group rules")
	}
}

func TestRuleForWithoutIdentity(t *testing.T) {
	engine := NewEngine(
		Policy{},
		[]Rule{
			{
				Users: []string{"alice"},
				Hosts: []string{"10.0.0.1"},
			},
		},
	)

	if engine.RuleFor(nil) != nil {
		t.Errorf("a missing identity must not match a rule")
	}

	if !engine.HostAllowed(nil, "10.0.0.9") {
		t.Errorf("a missing identity must not be restricted")
	}
}
