package access

import "testing"

func TestDisableAllCannotBeClearedByMatchingRule(t *testing.T) {
	e := NewEngine(Policy{DisableAll: true, Drive: true, Clipboard: true}, []Rule{{Users: []string{"alice"}, Redirect: Overrides{Drive: boolPtr(true)}}})
	if p := e.PolicyFor(testUser("alice")); !p.DisableAll {
		t.Fatalf("rule widened global DisableAll: %+v", p)
	}
}
