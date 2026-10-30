package security

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/identity"
)

func TestKeycloakResolvesCurrentUserAndAllGroupPages(t *testing.T) {
	enabled := true
	group := "/staff"
	status := http.StatusOK
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/realms/test/protocol/openid-connect/token":
			r.ParseForm()
			if r.Form.Get("grant_type") != "client_credentials" {
				t.Error("incorrect grant")
			}
			fmt.Fprint(w, `{"access_token":"service-token","token_type":"Bearer","expires_in":60}`)
		case "/admin/realms/test/users/alice-id":
			calls++
			if r.Header.Get("Authorization") != "Bearer service-token" {
				t.Error("missing service authorization")
			}
			w.WriteHeader(status)
			json.NewEncoder(w).Encode(map[string]interface{}{"id": "alice-id", "username": "alice-now", "enabled": enabled})
		case "/admin/realms/test/users/alice-id/groups":
			if r.URL.Query().Get("first") == "0" {
				items := make([]map[string]string, 100)
				for i := range items {
					items[i] = map[string]string{"name": "staff", "path": group}
				}
				json.NewEncoder(w).Encode(items)
			} else {
				fmt.Fprint(w, `[{"name":"last-page","path":"/last-page"}]`)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	resolver, err := NewKeycloakResolver(KeycloakConfig{Issuer: srv.URL + "/realms/test", ClientID: "service", ClientSecret: "secret", GroupFormat: "path"})
	if err != nil {
		t.Fatal(err)
	}
	id, err := resolver.Resolve(context.Background(), "alice-id")
	if err != nil || id.UserName() != "alice-now" || len(id.Groups()) != 2 || id.GetAttribute(identity.AttrGroupsKnown) != true {
		t.Fatalf("identity=%v error=%v", id, err)
	}
	group = "/contractors"
	id, err = resolver.Resolve(context.Background(), "alice-id")
	if err != nil || id.Groups()[0] != "/contractors" || calls != 2 {
		t.Fatalf("stale identity=%v error=%v calls=%d", id, err, calls)
	}
	enabled = false
	if _, err := resolver.Resolve(context.Background(), "alice-id"); err == nil {
		t.Fatal("disabled user accepted")
	}
	enabled = true
	for _, code := range []int{http.StatusNotFound, http.StatusForbidden, http.StatusInternalServerError} {
		status = code
		if _, err := resolver.Resolve(context.Background(), "alice-id"); err == nil {
			t.Fatalf("status %d accepted", code)
		}
	}
}

func TestKeycloakRejectsInvalidIssuerAndGroupFormat(t *testing.T) {
	for _, config := range []KeycloakConfig{
		{Issuer: "https://idp.example/not-a-realm", ClientID: "service", ClientSecret: "secret"},
		{Issuer: "http://idp.example/realms/test", ClientID: "service", ClientSecret: "secret"},
		{Issuer: "https://idp.example/realms/test", ClientID: "service", ClientSecret: "secret", GroupFormat: "invalid"},
	} {
		if _, err := NewKeycloakResolver(config); err == nil {
			t.Fatalf("accepted %+v", config)
		}
	}
}
