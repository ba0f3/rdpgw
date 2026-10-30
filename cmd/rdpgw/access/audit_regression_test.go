package access

import "testing"

func TestUnknownGroupsCannotSelectPrivilegedAllow(t *testing.T) {
	e := NewEngine(Policy{Drive: true}, []Rule{
		{Groups: []string{"admins"}, Hosts: []string{"production:3389"}},
		{Groups: []string{"contractors"}, Hosts: []string{"sandbox:3389"}},
	})
	id := testUser("bob")
	if e.HostAllowed(id, "production:3389") || e.PolicyFor(id).Drive || !e.Denied(id) {
		t.Fatal("unknown membership must fail closed rather than select privileged allow")
	}
}

func TestUnknownGroupsCannotSkipMixedDeny(t *testing.T) {
	e := NewEngine(Policy{Drive: true}, []Rule{{Users: []string{"alice"}, Groups: []string{"blocked"}, Deny: true}})
	if !e.Denied(testUser("bob")) {
		t.Fatal("unknown groups bypassed mixed-selector deny")
	}
}
