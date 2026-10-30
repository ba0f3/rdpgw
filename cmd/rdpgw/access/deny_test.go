package access

import (
	"testing"

	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/identity"
)

// A rule that selects a group applies to the users whose group membership
// the gateway does not know. The gateway cannot tell whether they are a
// member of the group, a rule that selects a group must not fail open for
// them.
func TestGroupRuleAppliesWithoutKnownMembership(t *testing.T) {
	engine := NewEngine(
		Policy{Drive: true},
		[]Rule{
			{
				Name:   "contractors",
				Groups: []string{"contractors"},
				Hosts:  []string{"10.0.0.9"},
			},
		},
	)

	// the membership is known and the user is not a member
	other := testUser("alice", "staff")
	if engine.HostAllowed(other, "10.0.0.1") != true {
		t.Errorf("a user that is not a member must not be restricted")
	}

	// the membership is unknown, the rule applies
	unknown := testUser("bob")
	if engine.HostAllowed(unknown, "10.0.0.1") {
		t.Errorf("a user without a known group membership must be restricted by the group rule")
	}
	if !engine.HostAllowed(unknown, "10.0.0.9") {
		t.Errorf("the host of the group rule must be allowed")
	}
}

// A rule that denies a group keeps the users out whose group membership the
// gateway does not know.
func TestDenyRuleAppliesWithoutKnownMembership(t *testing.T) {
	engine := NewEngine(
		Policy{Drive: true},
		[]Rule{
			{
				Name:   "blocked",
				Groups: []string{"blocked"},
				Deny:   true,
			},
		},
	)

	unknown := testUser("bob")
	if !engine.Denied(unknown) {
		t.Errorf("a user without a known group membership must be denied")
	}
	if engine.HostAllowed(unknown, "10.0.0.1") {
		t.Errorf("a denied user must not reach a host")
	}
	if engine.PolicyFor(unknown).Drive {
		t.Errorf("a denied user must not have any permission")
	}

	// a user that is a member of another group is not denied
	if engine.Denied(testUser("alice", "staff")) {
		t.Errorf("a user of another group must not be denied")
	}
}

// A rule that denies the user wins over every other rule.
func TestDenyRuleWins(t *testing.T) {
	engine := NewEngine(
		Policy{Drive: true},
		[]Rule{
			{
				Name:     "staff",
				Groups:   []string{"staff"},
				Redirect: Overrides{Drive: boolPtr(false)},
			},
			{
				Name:  "blocked",
				Users: []string{"mallory"},
				Deny:  true,
			},
		},
	)

	if !engine.Denied(testUser("mallory", "staff")) {
		t.Errorf("the deny rule must win over the other rules")
	}

	if engine.Denied(testUser("alice", "staff")) {
		t.Errorf("a user that is not denied must not be denied")
	}
}

// A rule that selects a user by name does not need a group membership.
func TestUserRuleDoesNotNeedGroupMembership(t *testing.T) {
	engine := NewEngine(
		Policy{},
		[]Rule{
			{
				Name:   "alice",
				Users:  []string{"alice"},
				Groups: []string{"staff"},
				Hosts:  []string{"10.0.0.9"},
			},
		},
	)

	// alice matches by name
	if !engine.HostAllowed(testUser("alice"), "10.0.0.9") {
		t.Errorf("alice must be allowed to connect to her host")
	}

	// bob does not match by name and the membership is unknown, the rule
	// does not apply to him
	if !engine.HostAllowed(testUser("bob"), "10.0.0.1") {
		t.Errorf("the rule of alice must not restrict bob")
	}
}

// A denied user has no hosts at all.
func TestDeniedUserHasNoHosts(t *testing.T) {
	engine := NewEngine(
		Policy{},
		[]Rule{
			{
				Users: []string{"mallory"},
				Deny:  true,
			},
		},
	)

	hosts := engine.AllowedHosts(testUser("mallory"), []string{"10.0.0.1", "10.0.0.2"})
	if len(hosts) != 0 {
		t.Errorf("a denied user must not have any host, got %v", hosts)
	}
}

// The camera and the USB devices are resources of their own.
func TestPolicyCameraAndUsbAreIndependent(t *testing.T) {
	engine := NewEngine(
		Policy{Pnp: true, Usb: true},
		[]Rule{
			{
				Users:    []string{"alice"},
				Redirect: Overrides{Usb: boolPtr(false)},
			},
		},
	)

	policy := engine.PolicyFor(testUser("alice"))
	if policy.Usb {
		t.Errorf("the rule must deny the usb devices of alice")
	}
	if !policy.Pnp {
		t.Errorf("the rule must not deny the device redirection of alice")
	}
	if !policy.Camera == false {
		t.Errorf("the camera is denied by the default policy")
	}
}

// The policy of the gateway is the ceiling of the policy of the token.
func TestPolicyNarrowCameraAndUsb(t *testing.T) {
	token := Policy{Usb: true, Camera: true}
	current := Policy{Usb: true}

	narrowed := token.Narrow(current)
	if !narrowed.Usb {
		t.Errorf("the usb devices are allowed by both policies")
	}
	if narrowed.Camera {
		t.Errorf("the camera must be denied by the current policy")
	}
}

var _ = identity.NewUser
