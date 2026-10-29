package identity

import (
	"log"
	"testing"
)

func TestGroupMembership(t *testing.T) {
	u := NewUser()
	u.SetUserName("ANAME")
	u.SetGroups([]string{"admins", "staff", "", "  "})

	groups := u.Groups()
	if len(groups) != 2 {
		t.Fatalf("expected 2 groups, got %v", groups)
	}
	if groups[0] != "admins" || groups[1] != "staff" {
		t.Fatalf("expected the groups to be sorted, got %v", groups)
	}

	// the group membership survives a round trip through the session store
	c := NewUser()
	data, err := u.Marshal()
	if err != nil {
		t.Fatalf("Cannot marshal %s", err)
	}
	if err := c.Unmarshal(data); err != nil {
		t.Fatalf("Error while unmarshalling: %s", err)
	}

	if len(c.Groups()) != 2 {
		t.Fatalf("expected 2 groups after unmarshalling, got %v", c.Groups())
	}
}

func TestMarshalling(t *testing.T) {
	u := NewUser()
	u.SetUserName("ANAME")
	u.SetAuthenticated(true)
	u.SetDomain("DOMAIN")

	c := NewUser()
	data, err := u.Marshal()
	if err != nil {
		log.Fatalf("Cannot marshal %s", err)
	}

	err = c.Unmarshal(data)
	if err != nil {
		t.Fatalf("Error while unmarshalling: %s", err)
	}

	if u.UserName() != c.UserName() || u.Authenticated() != c.Authenticated() || u.Domain() != c.Domain() {
		t.Fatalf("identities not equal: %+v != %+v", u, c)
	}
}
