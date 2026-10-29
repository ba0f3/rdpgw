package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/access"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/identity"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/rdp"
)

// installPolicy installs an access policy for the duration of the test.
func installPolicy(t *testing.T, policy access.Policy, rules []access.Rule) {
	t.Helper()

	previous := access.Current()
	access.Init(access.NewEngine(policy, rules))
	t.Cleanup(func() {
		access.Init(previous)
	})
}

func boolValue(b bool) *bool {
	return &b
}

// A user may only connect to the hosts the access policy allows.
func TestGetHostRespectsAccessPolicy(t *testing.T) {
	installPolicy(t, access.Policy{}, []access.Rule{
		{
			Users: []string{"restricted"},
			Hosts: []string{"10.0.0.1:3389"},
		},
	})

	c := Config{
		HostSelection: "unsigned",
		Hosts:         hosts,
	}
	h := c.NewHandler()

	id := identity.NewUser()
	id.SetUserName("restricted")
	id.SetAuthenticated(true)

	u := &url.URL{Host: "example.com"}
	vals := u.Query()
	vals.Set("host", "10.0.0.1:3389")
	u.RawQuery = vals.Encode()

	ctx := identity.AddToRequestCtx(id, &http.Request{}).Context()
	if _, err := h.getHost(ctx, u); err != nil {
		t.Errorf("getHost rejected an allowed host: %v", err)
	}

	vals.Set("host", "remote.host.com")
	u.RawQuery = vals.Encode()

	if _, err := h.getHost(ctx, u); err == nil {
		t.Errorf("getHost accepted a host that is not allowed for the user")
	}
}

// A user that does not match a rule is not restricted by it.
func TestGetHostWithoutMatchingRule(t *testing.T) {
	installPolicy(t, access.Policy{}, []access.Rule{
		{
			Users: []string{"restricted"},
			Hosts: []string{"10.0.0.1:3389"},
		},
	})

	c := Config{
		HostSelection: "unsigned",
		Hosts:         hosts,
	}
	h := c.NewHandler()

	id := identity.NewUser()
	id.SetUserName("other")
	id.SetAuthenticated(true)

	u := &url.URL{Host: "example.com"}
	vals := u.Query()
	vals.Set("host", "remote.host.com")
	u.RawQuery = vals.Encode()

	ctx := identity.AddToRequestCtx(id, &http.Request{}).Context()
	if _, err := h.getHost(ctx, u); err != nil {
		t.Errorf("getHost rejected a host for a user without a matching rule: %v", err)
	}
}

// A denied user cannot reach any host.
func TestGetHostDeniedUser(t *testing.T) {
	installPolicy(t, access.Policy{}, []access.Rule{
		{
			Users: []string{"blocked"},
			Deny:  true,
		},
	})

	c := Config{
		HostSelection: "unsigned",
		Hosts:         hosts,
	}
	h := c.NewHandler()

	id := identity.NewUser()
	id.SetUserName("blocked")
	id.SetAuthenticated(true)

	u := &url.URL{Host: "example.com"}
	vals := u.Query()
	vals.Set("host", "10.0.0.1:3389")
	u.RawQuery = vals.Encode()

	ctx := identity.AddToRequestCtx(id, &http.Request{}).Context()
	if _, err := h.getHost(ctx, u); err == nil {
		t.Errorf("getHost accepted a host for a denied user")
	}
}

// The redirect settings of the .rdp file follow the access policy of the
// user.
func TestHandleDownloadAppliesRedirectPolicy(t *testing.T) {
	installPolicy(t, access.Policy{Drive: true}, []access.Rule{
		{
			Users: []string{"restricted"},
			Redirect: access.Overrides{
				Clipboard: boolValue(false),
				Drive:     boolValue(true),
			},
		},
	})

	req, err := http.NewRequest("GET", "/connect", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	id := identity.NewUser()
	id.SetUserName("restricted")
	id.SetAuthenticated(true)

	req = identity.AddToRequestCtx(id, req)

	u, _ := url.Parse(gateway)
	c := Config{
		HostSelection:     "roundrobin",
		Hosts:             hosts,
		PAATokenGenerator: paaTokenMock,
		GatewayAddress:    u,
	}
	h := c.NewHandler()

	http.HandlerFunc(h.HandleDownload).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusOK)
	}

	body := rr.Body.String()
	data := rdpToMap(strings.Split(body, rdp.CRLF))

	if data["redirectclipboard"] != "0" {
		t.Errorf("redirectclipboard = %q, want 0", data["redirectclipboard"])
	}
	if data["redirectprinters"] != "0" {
		t.Errorf("redirectprinters = %q, want 0", data["redirectprinters"])
	}
	if data["drivestoredirect"] != "*" {
		t.Errorf("drivestoredirect = %q, want *", data["drivestoredirect"])
	}
	if data["devicestoredirect"] != "" {
		t.Errorf("devicestoredirect = %q, want an empty value", data["devicestoredirect"])
	}

	// the settings are written explicitly, even when they carry the value
	// the client uses by default
	if !strings.Contains(body, "redirectlocation:i:0"+rdp.CRLF) {
		t.Errorf("the redirect settings are not written explicitly:\n%s", body)
	}
}

// The .rdp template of the operator cannot widen the policy of the gateway.
func TestHandleDownloadTemplateCannotWidenPolicy(t *testing.T) {
	installPolicy(t, access.Policy{}, nil)

	template := filepath.Join(t.TempDir(), "default.rdp")
	content := "redirectclipboard:i:1\r\nredirectprinters:i:1\r\ndrivestoredirect:s:*\r\n"
	if err := os.WriteFile(template, []byte(content), 0600); err != nil {
		t.Fatalf("cannot write the template: %v", err)
	}

	req, err := http.NewRequest("GET", "/connect", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	id := identity.NewUser()
	id.SetUserName(testuser)
	id.SetAuthenticated(true)

	req = identity.AddToRequestCtx(id, req)

	u, _ := url.Parse(gateway)
	c := Config{
		HostSelection:     "roundrobin",
		Hosts:             hosts,
		PAATokenGenerator: paaTokenMock,
		GatewayAddress:    u,
		TemplateFile:      template,
	}
	h := c.NewHandler()

	http.HandlerFunc(h.HandleDownload).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusOK)
	}

	body := rr.Body.String()
	data := rdpToMap(strings.Split(body, rdp.CRLF))

	if data["redirectclipboard"] != "0" {
		t.Errorf("redirectclipboard = %q, want 0", data["redirectclipboard"])
	}
	if data["redirectprinters"] != "0" {
		t.Errorf("redirectprinters = %q, want 0", data["redirectprinters"])
	}
	if data["drivestoredirect"] != "" {
		t.Errorf("drivestoredirect = %q, want an empty value", data["drivestoredirect"])
	}
}

// The redirect settings of the gateway cannot be overridden through the
// URL, not even when the operator allow-lists them.
func TestHandleDownloadRejectsRedirectOverride(t *testing.T) {
	installPolicy(t, access.Policy{}, nil)

	req, err := http.NewRequest("GET", "/connect?redirectclipboard=1", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	id := identity.NewUser()
	id.SetUserName(testuser)
	id.SetAuthenticated(true)

	req = identity.AddToRequestCtx(id, req)

	u, _ := url.Parse(gateway)
	c := Config{
		HostSelection:     "roundrobin",
		Hosts:             hosts,
		PAATokenGenerator: paaTokenMock,
		GatewayAddress:    u,
		RdpOpts: RdpOpts{
			OverridableRdpKeys: []string{"redirectclipboard", "drivestoredirect"},
		},
	}
	h := c.NewHandler()

	http.HandlerFunc(h.HandleDownload).ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusBadRequest)
	}
}

// The list of hosts only contains the hosts the user may connect to.
func TestHandleHostListRespectsAccessPolicy(t *testing.T) {
	installPolicy(t, access.Policy{}, []access.Rule{
		{
			Users: []string{"restricted"},
			Hosts: []string{"10.0.0.1:3389"},
		},
	})

	h := &Handler{
		hostSelection: "unsigned",
		hosts:         hosts,
	}

	req := httptest.NewRequest("GET", "/api/v1/hosts", nil)
	rr := httptest.NewRecorder()

	id := identity.NewUser()
	id.SetUserName("restricted")
	id.SetAuthenticated(true)
	req = identity.AddToRequestCtx(id, req)

	h.HandleHostList(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("handler returned wrong status code: got %v want %v", rr.Code, http.StatusOK)
	}

	body := rr.Body.String()
	if strings.Contains(body, "remote.host.com") {
		t.Errorf("the host list contains a host the user is not allowed to connect to: %s", body)
	}
	if !strings.Contains(body, "10.0.0.1:3389") {
		t.Errorf("the host list does not contain the host the user is allowed to connect to: %s", body)
	}
}
