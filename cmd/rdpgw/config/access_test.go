package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeConfig(t *testing.T, content string) string {
	t.Helper()

	dir := t.TempDir()
	name := filepath.Join(dir, "rdpgw.yaml")

	if err := os.WriteFile(name, []byte(content), 0600); err != nil {
		t.Fatalf("cannot write config file: %v", err)
	}

	return name
}

func TestLoadAccessRules(t *testing.T) {
	name := writeConfig(t, `
Caps:
  EnableClipboard: true
  EnableDrive: true

Access:
  Rules:
    - Name: contractors
      Users:
        - alice@example.com
      Groups:
        - contractors
      Redirect:
        EnableClipboard: false
        EnableDrive: false
      Hosts:
        - 10.0.0.1
        - 10.0.0.2:3389
`)

	conf := Load(name)

	if len(conf.Access.Rules) != 1 {
		t.Fatalf("expected 1 access rule, got %d", len(conf.Access.Rules))
	}

	rule := conf.Access.Rules[0]
	if rule.Name != "contractors" {
		t.Errorf("rule name = %q, want contractors", rule.Name)
	}
	if len(rule.Users) != 1 || rule.Users[0] != "alice@example.com" {
		t.Errorf("rule users = %v, want [alice@example.com]", rule.Users)
	}
	if len(rule.Groups) != 1 || rule.Groups[0] != "contractors" {
		t.Errorf("rule groups = %v, want [contractors]", rule.Groups)
	}
	if len(rule.Hosts) != 2 {
		t.Errorf("rule hosts = %v, want 2 entries", rule.Hosts)
	}
	if rule.Redirect == nil {
		t.Fatal("rule redirect is not set")
	}
	if rule.Redirect.EnableClipboard == nil || *rule.Redirect.EnableClipboard {
		t.Errorf("rule redirect enableclipboard = %v, want false", rule.Redirect.EnableClipboard)
	}
	if rule.Redirect.EnableDrive == nil || *rule.Redirect.EnableDrive {
		t.Errorf("rule redirect enabledrive = %v, want false", rule.Redirect.EnableDrive)
	}
	// settings that are not mentioned are inherited
	if rule.Redirect.EnablePrinter != nil {
		t.Errorf("rule redirect enableprinter = %v, want nil", rule.Redirect.EnablePrinter)
	}
}

func TestAccessRulesConversion(t *testing.T) {
	deny := false
	allow := true

	c := AccessConfig{
		Rules: []AccessRule{
			{
				Name:  "contractors",
				Users: []string{"alice"},
				Redirect: &AccessRedirect{
					EnableClipboard: &deny,
				},
				Hosts: []string{"10.0.0.1"},
			},
			{
				Name:   "admins",
				Groups: []string{"admins"},
				Redirect: &AccessRedirect{
					EnableDrive: &allow,
				},
			},
		},
	}

	rules, err := c.AccessRules()
	if err != nil {
		t.Fatalf("AccessRules returned an error: %v", err)
	}

	if len(rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rules))
	}

	if rules[0].Redirect.Clipboard == nil || *rules[0].Redirect.Clipboard {
		t.Errorf("rule 0 clipboard = %v, want false", rules[0].Redirect.Clipboard)
	}
	if rules[0].Redirect.Drive != nil {
		t.Errorf("rule 0 drive = %v, want nil", rules[0].Redirect.Drive)
	}
	if rules[1].Redirect.Drive == nil || !*rules[1].Redirect.Drive {
		t.Errorf("rule 1 drive = %v, want true", rules[1].Redirect.Drive)
	}
}

func TestAccessRulesWithoutSelector(t *testing.T) {
	c := AccessConfig{
		Rules: []AccessRule{
			{
				Name: "empty",
			},
		},
	}

	if _, err := c.AccessRules(); err == nil {
		t.Fatal("a rule without a user or a group must be rejected")
	}
}

func TestDefaultPolicy(t *testing.T) {
	caps := RDGCapsConfig{
		EnableClipboard: true,
		EnableDrive:     true,
		EnablePrinter:   true,
		EnablePort:      true,
		EnablePnp:       true,
	}

	policy := caps.DefaultPolicy()
	if !policy.Clipboard || !policy.Drive || !policy.Printer || !policy.Port || !policy.Pnp {
		t.Errorf("policy = %+v, want all resources to be allowed", policy)
	}
	if policy.DisableAll || policy.EnableAll {
		t.Errorf("policy = %+v, want no all switches", policy)
	}

	// the resources that have no configuration are denied by default
	if policy.SmartCard || policy.WebAuthn || policy.Location {
		t.Errorf("policy = %+v, want the new resources to be denied by default", policy)
	}
}

func TestDefaultPolicyDisableRedirect(t *testing.T) {
	caps := RDGCapsConfig{
		EnableClipboard: true,
		EnableDrive:     true,
		DisableRedirect: true,
	}

	policy := caps.DefaultPolicy()
	if !policy.DisableAll {
		t.Errorf("policy = %+v, want all redirections to be disabled", policy)
	}
	if policy.Clipboard || policy.Drive {
		t.Errorf("policy = %+v, want no resource to be allowed", policy)
	}
}

func TestDefaultPolicyRedirectAll(t *testing.T) {
	caps := RDGCapsConfig{
		RedirectAll: true,
	}

	policy := caps.DefaultPolicy()
	if !policy.EnableAll {
		t.Errorf("policy = %+v, want all redirections to be enabled", policy)
	}
	if !policy.Clipboard || !policy.Drive {
		t.Errorf("policy = %+v, want all resources to be allowed", policy)
	}
}

func TestLoadLifetimes(t *testing.T) {
	name := writeConfig(t, `
Server:
  SessionLifetime: 3600
Security:
  PAATokenLifetime: 120
  UserTokenLifetime: 60
  QueryTokenLifetime: 30
`)

	conf := Load(name)

	if conf.Server.SessionLifetime != 3600 {
		t.Errorf("session lifetime = %d, want 3600", conf.Server.SessionLifetime)
	}
	if conf.Security.PAATokenLifetime != 120 {
		t.Errorf("paa token lifetime = %d, want 120", conf.Security.PAATokenLifetime)
	}
	if conf.Security.UserTokenLifetime != 60 {
		t.Errorf("user token lifetime = %d, want 60", conf.Security.UserTokenLifetime)
	}
	if conf.Security.QueryTokenLifetime != 30 {
		t.Errorf("query token lifetime = %d, want 30", conf.Security.QueryTokenLifetime)
	}
}

func TestLoadDefaultLifetimes(t *testing.T) {
	name := writeConfig(t, "Server:\n  Port: 443\n")

	conf := Load(name)

	if conf.Server.SessionLifetime != 120 {
		t.Errorf("session lifetime = %d, want the default of 120", conf.Server.SessionLifetime)
	}
	if conf.Security.PAATokenLifetime != 5 {
		t.Errorf("paa token lifetime = %d, want the default of 5", conf.Security.PAATokenLifetime)
	}
	if conf.Security.UserTokenLifetime != 5 {
		t.Errorf("user token lifetime = %d, want the default of 5", conf.Security.UserTokenLifetime)
	}
	if conf.Security.QueryTokenLifetime != 5 {
		t.Errorf("query token lifetime = %d, want the default of 5", conf.Security.QueryTokenLifetime)
	}
}

func TestLoadOpenIDGroups(t *testing.T) {
	name := writeConfig(t, `
OpenId:
  ProviderUrl: https://idp.example.com
  ClientId: rdpgw
  Groups:
    - rdpgw-users
    - admins
  GroupsClaim: roles
  Scopes:
    - openid
    - profile
    - groups
`)

	conf := Load(name)

	if len(conf.OpenId.Groups) != 2 {
		t.Fatalf("groups = %v, want 2 entries", conf.OpenId.Groups)
	}
	if conf.OpenId.GroupsClaim != "roles" {
		t.Errorf("groups claim = %q, want roles", conf.OpenId.GroupsClaim)
	}
	if len(conf.OpenId.Scopes) != 3 {
		t.Errorf("scopes = %v, want 3 entries", conf.OpenId.Scopes)
	}
}

func TestLoadDefaultGroupsClaim(t *testing.T) {
	name := writeConfig(t, "Server:\n  Port: 443\n")

	conf := Load(name)

	if conf.OpenId.GroupsClaim != "groups" {
		t.Errorf("groups claim = %q, want the default of groups", conf.OpenId.GroupsClaim)
	}
}
