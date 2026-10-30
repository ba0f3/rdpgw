package config

import (
	"fmt"

	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/access"
)

// DefaultPolicy returns the global redirect policy. It is the ceiling of
// the access policy: the rules in the access section can only narrow it.
//
// The disableredirect and redirectall switches are mutually exclusive, the
// disable switch wins, which is the same order the gateway uses when it
// builds the redirect flags of the tunnel authorization response.
func (c RDGCapsConfig) DefaultPolicy() access.Policy {
	policy := access.Policy{
		Clipboard: c.EnableClipboard,
		Drive:     c.EnableDrive,
		Printer:   c.EnablePrinter,
		Port:      c.EnablePort,
		Pnp:       c.EnablePnp,
		SmartCard: c.EnableSmartCard,
		WebAuthn:  c.EnableWebAuthn,
		Location:  c.EnableLocation,
		Camera:    c.EnableCamera,
		Usb:       c.EnableUsb,
	}

	if c.DisableRedirect {
		return access.Policy{DisableAll: true}
	}

	if c.RedirectAll {
		return access.Policy{
			Clipboard: true,
			Drive:     true,
			Printer:   true,
			Port:      true,
			Pnp:       true,
			SmartCard: true,
			WebAuthn:  true,
			Location:  true,
			Camera:    true,
			Usb:       true,
			EnableAll: true,
		}
	}

	return policy
}

// AccessRules converts the configured access rules into the runtime rules of
// the access package.
func (c AccessConfig) AccessRules() ([]access.Rule, error) {
	rules := make([]access.Rule, 0, len(c.Rules))

	for i, rule := range c.Rules {
		if len(rule.Users) == 0 && len(rule.Groups) == 0 {
			return nil, fmt.Errorf("access rule %d (%s) does not select any user or group", i, rule.Name)
		}

		converted := access.Rule{
			Name:   rule.Name,
			Users:  rule.Users,
			Groups: rule.Groups,
			Hosts:  rule.Hosts,
			Deny:   rule.Deny,
		}

		if rule.Redirect != nil {
			converted.Redirect = access.Overrides{
				Clipboard: rule.Redirect.EnableClipboard,
				Drive:     rule.Redirect.EnableDrive,
				Printer:   rule.Redirect.EnablePrinter,
				Port:      rule.Redirect.EnablePort,
				Pnp:       rule.Redirect.EnablePnp,
				SmartCard: rule.Redirect.EnableSmartCard,
				WebAuthn:  rule.Redirect.EnableWebAuthn,
				Location:  rule.Redirect.EnableLocation,
				Camera:    rule.Redirect.EnableCamera,
				Usb:       rule.Redirect.EnableUsb,
			}
		}

		rules = append(rules, converted)
	}

	return rules, nil
}
