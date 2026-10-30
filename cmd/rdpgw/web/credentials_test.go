package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/credentials"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/identity"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/security"
	"github.com/gorilla/mux"
)

func TestCredentialAPIPermissionsAndCSRF(t *testing.T) {
	s, err := credentials.Open(filepath.Join(t.TempDir(), "credentials.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	groups := []string{"staff"}
	service := &security.CredentialService{Store: s, Resolve: func(ctx context.Context, subject string) (identity.Identity, error) {
		id := identity.NewUser()
		id.SetUserName(subject)
		id.SetGroups(groups)
		id.SetAttribute(identity.AttrSubject, subject)
		id.SetAuthenticated(true)
		return id, nil
	}}
	id := identity.NewUser()
	id.SetUserName("alice")
	id.SetAttribute(identity.AttrSubject, "alice-id")
	id.SetAuthenticated(true)
	id.SetAuthTime(time.Now())
	if err := service.Login(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	token, err := s.Issue(credentials.Record{Subject: "bob-id", UserName: "bob", Host: "desktop:3389", AuthTime: now, ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	record, err := s.Lookup(token)
	if err != nil {
		t.Fatal(err)
	}
	api := &CredentialAPI{Service: service, AdminGroups: []string{"admins"}, Origin: "https://gateway.example"}
	invoke := func(method, path string, vars map[string]string, csrf bool) int {
		req := identity.AddToRequestCtx(id, httptest.NewRequest(method, "https://gateway.example"+path, nil))
		req = mux.SetURLVars(req, vars)
		if csrf {
			req.Header.Set("Origin", "https://gateway.example")
			req.Header.Set("X-RDPGW-CSRF", "1")
		}
		w := httptest.NewRecorder()
		api.ServeHTTP(w, req)
		return w.Code
	}
	if got := invoke(http.MethodDelete, "/api/v1/credentials/"+record.ID, map[string]string{"id": record.ID}, true); got != http.StatusNotFound {
		t.Fatalf("cross-user delete status=%d", got)
	}
	groups = []string{"admins"}
	if got := invoke(http.MethodDelete, "/api/v1/credentials/"+record.ID, map[string]string{"id": record.ID}, false); got != http.StatusForbidden {
		t.Fatalf("missing CSRF status=%d", got)
	}
	if got := invoke(http.MethodGet, "/api/v1/credentials?user=bob-id", nil, false); got != http.StatusOK {
		t.Fatalf("admin list status=%d", got)
	}
	if got := invoke(http.MethodDelete, "/api/v1/credentials/"+record.ID, map[string]string{"id": record.ID}, true); got != http.StatusNoContent {
		t.Fatalf("admin revoke status=%d", got)
	}
	if _, err := s.Lookup(token); err == nil {
		t.Fatal("API did not revoke")
	}
	groups = []string{"staff"}
	if got := invoke(http.MethodDelete, "/api/v1/users/bob-id/credentials", map[string]string{"subject": "bob-id"}, true); got != http.StatusForbidden {
		t.Fatalf("former admin retained authorization status=%d", got)
	}
	if got := invoke(http.MethodDelete, "/api/v1/users/me/credentials", map[string]string{"subject": "me"}, true); got != http.StatusNoContent {
		t.Fatalf("self revoke-all status=%d", got)
	}
	if err := service.Refresh(context.Background(), id); err == nil {
		t.Fatal("old session can issue after API revoke-all")
	}
}
