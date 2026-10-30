package rdp

import (
	"strings"
	"testing"

	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/access"
)

func TestApplyRedirectPolicyDenied(t *testing.T) {
	b := NewBuilder()
	b.ApplyRedirectPolicy(access.Policy{})

	s := b.String()

	for _, want := range []string{
		"redirectclipboard:i:0" + CRLF,
		"redirectprinters:i:0" + CRLF,
		"redirectcomports:i:0" + CRLF,
		"redirectsmartcards:i:0" + CRLF,
		"redirectwebauthn:i:0" + CRLF,
		"redirectlocation:i:0" + CRLF,
		"drivestoredirect:s:" + CRLF,
		"devicestoredirect:s:" + CRLF,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("rendered file does not contain %q, got:\n%s", want, s)
		}
	}
}

func TestApplyRedirectPolicyAllowed(t *testing.T) {
	b := NewBuilder()
	b.ApplyRedirectPolicy(access.Policy{
		Clipboard: true,
		Drive:     true,
		Printer:   true,
		Port:      true,
		Pnp:       true,
		Camera:    true,
		Usb:       true,
	})

	s := b.String()

	for _, want := range []string{
		"redirectclipboard:i:1" + CRLF,
		"redirectprinters:i:1" + CRLF,
		"redirectcomports:i:1" + CRLF,
		"drivestoredirect:s:*" + CRLF,
		"devicestoredirect:s:*" + CRLF,
		"camerastoredirect:s:*" + CRLF,
		"usbdevicestoredirect:s:*" + CRLF,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("rendered file does not contain %q, got:\n%s", want, s)
		}
	}
}

// The camera and the USB devices of the client are their own resources,
// the device redirection does not imply them.
func TestApplyRedirectPolicyCameraAndUsbAreIndependent(t *testing.T) {
	b := NewBuilder()
	b.ApplyRedirectPolicy(access.Policy{
		Pnp:    true,
		Usb:    true,
		Camera: false,
	})

	s := b.String()

	deviceList := ""
	for _, line := range strings.Split(s, CRLF) {
		if strings.HasPrefix(line, "devicestoredirect:s:") {
			deviceList = strings.TrimPrefix(line, "devicestoredirect:s:")
		}
	}

	if deviceList != "usb" {
		t.Errorf("the device list is %q, want usb", deviceList)
	}
	if !strings.Contains(s, "camerastoredirect:s:"+CRLF) {
		t.Errorf("the camera is not disabled, got:\n%s", s)
	}
	if !strings.Contains(s, "usbdevicestoredirect:s:*"+CRLF) {
		t.Errorf("the usb devices are not allowed, got:\n%s", s)
	}
}

// The device redirection without a device type does not redirect anything.
func TestApplyRedirectPolicyPnpWithoutTypes(t *testing.T) {
	b := NewBuilder()
	b.ApplyRedirectPolicy(access.Policy{Pnp: true})

	s := b.String()

	if !strings.Contains(s, "devicestoredirect:s:"+CRLF) {
		t.Errorf("the device list is not empty, got:\n%s", s)
	}
	if !strings.Contains(s, "camerastoredirect:s:"+CRLF) {
		t.Errorf("the camera is not disabled, got:\n%s", s)
	}
	if !strings.Contains(s, "usbdevicestoredirect:s:"+CRLF) {
		t.Errorf("the usb devices are not disabled, got:\n%s", s)
	}
}

// The redirect settings are controlled by the access policy of the gateway
// and can never be overridden through the URL.
func TestApplyOverridesRejectsPolicyControlledKeys(t *testing.T) {
	for _, key := range []string{
		"redirectclipboard",
		"redirectprinters",
		"drivestoredirect",
		"devicestoredirect",
		"redirectcomports",
		"redirectlocation",
		"redirectsmartcards",
		"redirectwebauthn",
		"camerastoredirect",
		"usbdevicestoredirect",
	} {
		b := NewBuilder()
		err := b.ApplyOverrides(
			map[string][]string{key: {"1"}},
			[]string{key},
		)
		if err == nil {
			t.Errorf("ApplyOverrides accepted the policy controlled key %q", key)
		}
	}
}
