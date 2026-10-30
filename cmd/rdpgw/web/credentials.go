package web

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/identity"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/security"
	"github.com/gorilla/mux"
)

type CredentialAPI struct {
	Service     *security.CredentialService
	AdminGroups []string
	Origin      string
}

// ServeHTTP is wrapped in OIDC authentication by the router and independently
// refreshes authorization so admin powers never come from stale session groups.
func (a *CredentialAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	id := identity.FromRequestCtx(r)
	if err := a.Service.Refresh(r.Context(), id); err != nil {
		http.Error(w, "current authentication required", http.StatusUnauthorized)
		return
	}
	subject, _ := id.GetAttribute(identity.AttrSubject).(string)
	admin := false
	for _, allowed := range a.AdminGroups {
		for _, group := range id.Groups() {
			if strings.TrimSpace(allowed) != "" && strings.EqualFold(strings.TrimSpace(allowed), group) {
				admin = true
			}
		}
	}
	vars := mux.Vars(r)
	switch r.Method {
	case http.MethodGet:
		owner := r.URL.Query().Get("user")
		if owner == "" {
			owner = subject
		}
		if owner != subject && !admin {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		records, err := a.Service.Store.List(owner)
		if err != nil {
			http.Error(w, "credential storage unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(records)
	case http.MethodDelete:
		// A custom header prevents cross-origin form requests. Origin is
		// compared to the configured public gateway, never a forwarded Host.
		if r.Header.Get("X-RDPGW-CSRF") != "1" || r.Header.Get("Origin") != a.Origin {
			http.Error(w, "invalid request origin", http.StatusForbidden)
			return
		}
		if target := vars["subject"]; target != "" {
			if target == "me" {
				target = subject
			}
			if target != subject && !admin {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			if err := a.Service.Store.RevokeUser(target); err != nil {
				http.Error(w, "credential storage unavailable", http.StatusServiceUnavailable)
				return
			}
			log.Printf("Credential revoke-all actor=%q subject=%q", id.UserName(), target)
		} else if credentialID := vars["id"]; credentialID != "" {
			owner := subject
			if admin {
				owner = ""
			}
			if err := a.Service.Store.Revoke(credentialID, owner); err != nil {
				http.Error(w, "credential unavailable", http.StatusNotFound)
				return
			}
			log.Printf("Credential revoked actor=%q credential=%q", id.UserName(), credentialID)
		} else {
			http.Error(w, "missing credential", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", "GET, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
