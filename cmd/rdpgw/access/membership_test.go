package access

import "testing"

func TestVerifiedEmptyMembershipDoesNotMatchGroupRule(t *testing.T) {
	e := NewEngine(Policy{Drive: true}, []Rule{{Groups: []string{"admins"}, Hosts: []string{"production:3389"}}, {Groups: []string{"blocked"}, Deny: true}})
	id := testUser("alice")
	id.SetGroups([]string{})
	if e.Denied(id) || e.RuleFor(id) != nil {
		t.Fatal("verified empty groups must not match group selectors")
	}
}
