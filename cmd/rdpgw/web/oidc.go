package web

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/identity"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/security"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	CacheExpiration = time.Minute * 2
	CleanupInterval = time.Minute * 5
	oidcStateKey    = "OIDCSTATE"
	oidcStartedKey  = "OIDCSTARTED"
	oidcVerifierKey = "OIDCVERIFIER"
)

type OIDC struct {
	oAuth2Config      *oauth2.Config
	oidcTokenVerifier *oidc.IDTokenVerifier
	// allowedGroups is the list of groups a user must be a member of to
	// log in. An empty list allows every user the provider authenticates.
	allowedGroups []string
	// groupsClaim is the name of the ID token claim that carries the group
	// membership of the user.
	groupsClaim string
}

type OIDCConfig struct {
	OAuth2Config      *oauth2.Config
	OIDCTokenVerifier *oidc.IDTokenVerifier
	// AllowedGroups is the list of groups a user must be a member of to log
	// in to the gateway. An empty list allows every authenticated user.
	AllowedGroups []string
	// GroupsClaim is the name of the ID token claim that carries the group
	// membership of the user. It defaults to "groups".
	GroupsClaim string
}

func (c *OIDCConfig) New() *OIDC {
	groupsClaim := c.GroupsClaim
	if groupsClaim == "" {
		groupsClaim = "groups"
	}

	return &OIDC{
		oAuth2Config:      c.OAuth2Config,
		oidcTokenVerifier: c.OIDCTokenVerifier,
		allowedGroups:     c.AllowedGroups,
		groupsClaim:       groupsClaim,
	}
}

// storeOIDCState stores the OIDC state and redirect URL in the session
func storeOIDCState(w http.ResponseWriter, r *http.Request, state string, redirectURL string) error {
	if !strings.HasPrefix(redirectURL, "/") || strings.HasPrefix(redirectURL, "//") {
		redirectURL = "/"
	}
	session, err := GetSession(r)
	if err != nil {
		return err
	}

	// Store state data directly as a concatenated string: state + "|" + redirectURL
	stateValue := state + "|" + redirectURL
	session.Values[oidcStateKey] = stateValue
	session.Values[oidcStartedKey] = time.Now().Unix()
	session.Values[oidcVerifierKey] = oauth2.GenerateVerifier()
	session.Options.MaxAge = int(CacheExpiration.Seconds())

	return sessionStore.Save(r, w, session)
}

// getOIDCState retrieves the redirect URL for the given state from the session
func getOIDCState(r *http.Request, state string) (string, bool) {
	if state == "" {
		return "", false
	}
	session, err := GetSession(r)
	if err != nil {
		log.Printf("Error getting session for OIDC state: %v", err)
		return "", false
	}

	stateData, exists := session.Values[oidcStateKey]
	if !exists {
		log.Printf("No OIDC state data found in session")
		return "", false
	}

	stateValue, ok := stateData.(string)
	if !ok {
		log.Printf("Invalid OIDC state data format in session")
		return "", false
	}
	started, ok := session.Values[oidcStartedKey].(int64)
	if !ok || started > time.Now().Unix()+1 || time.Now().Unix()-started > int64(CacheExpiration.Seconds()) {
		return "", false
	}

	// Parse state data: state + "|" + redirectURL
	expectedPrefix := state + "|"
	if !strings.HasPrefix(stateValue, expectedPrefix) {
		log.Printf("OIDC state '%s' not found in session", state)
		return "", false
	}

	redirectURL := stateValue[len(expectedPrefix):]
	return redirectURL, true
}

func (h *OIDC) HandleCallback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	url, found := getOIDCState(r, state)
	if !found {
		log.Printf("OIDC HandleCallback: unknown state '%s'", state)
		http.Error(w, "unknown state", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	session, err := GetSession(r)
	if err != nil {
		http.Error(w, "invalid login session", http.StatusBadRequest)
		return
	}
	started, ok := session.Values[oidcStartedKey].(int64)
	verifier, hasVerifier := session.Values[oidcVerifierKey].(string)
	if !ok || !hasVerifier || verifier == "" {
		http.Error(w, "invalid login session", http.StatusBadRequest)
		return
	}
	delete(session.Values, oidcStateKey)
	delete(session.Values, oidcStartedKey)
	delete(session.Values, oidcVerifierKey)
	if err := sessionStore.Save(r, w, session); err != nil {
		http.Error(w, "cannot consume login state", http.StatusInternalServerError)
		return
	}
	oauth2Token, err := h.oAuth2Config.Exchange(ctx, r.URL.Query().Get("code"), oauth2.VerifierOption(verifier))
	if err != nil {
		http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "No id_token field in oauth2 token.", http.StatusInternalServerError)
		return
	}
	idToken, err := h.oidcTokenVerifier.Verify(ctx, rawIDToken)
	if err != nil {
		http.Error(w, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	resp := struct {
		OAuth2Token   *oauth2.Token
		IDTokenClaims *json.RawMessage // ID Token payload is just JSON.
	}{oauth2Token, new(json.RawMessage)}

	if err := idToken.Claims(&resp.IDTokenClaims); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var data map[string]interface{}
	if err := json.Unmarshal(*resp.IDTokenClaims, &data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// A fresh login requires evidence from the signed ID token. Request
	// parameters alone do not prove the provider actually reauthenticated.
	authTime, ok := data["auth_time"].(float64)
	if !ok || authTime != float64(int64(authTime)) || int64(authTime) < started-1 || int64(authTime) > time.Now().Unix()+60 || idToken.Nonce != state {
		http.Error(w, "fresh identity-provider authentication required", http.StatusUnauthorized)
		return
	}

	id := identity.FromRequestCtx(r)

	userName := findUsernameInClaims(data)
	if userName == "" {
		http.Error(w, "no oidc claim for username found", http.StatusInternalServerError)
		return
	}

	// The group membership of the user is taken from the ID token. It is
	// used by the access policy and by the group allow-list below.
	groups := findGroupsInClaims(data, h.groupsClaim)

	if !h.groupAllowed(groups) {
		log.Printf("OIDC HandleCallback: user %s is not a member of an allowed group", userName)
		http.Error(w, "user is not a member of an allowed group", http.StatusForbidden)
		return
	}

	id.SetUserName(userName)
	id.SetGroups(groups)
	id.SetAttribute(identity.AttrSubject, idToken.Subject)

	// The access policy can refuse the user even when the provider
	// authenticated them. The user is not marked as authenticated before
	// the check, a refused user must not end up with a session.
	if refuseDeniedUser(w, id) {
		return
	}

	id.SetAuthenticated(true)
	id.SetAuthTime(time.Unix(int64(authTime), 0))
	if security.CredentialManager != nil {
		if err := security.CredentialManager.Login(ctx, id); err != nil {
			id.SetAuthenticated(false)
			http.Error(w, "current Keycloak authorization denied", http.StatusForbidden)
			return
		}
	}

	if err := SaveSessionIdentity(r, w, id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, url, http.StatusFound)
}

// groupAllowed reports whether the user is a member of one of the groups
// that are allowed to log in. When no groups are configured every user the
// provider authenticated is allowed.
func (h *OIDC) groupAllowed(groups []string) bool {
	if len(h.allowedGroups) == 0 {
		return true
	}

	for _, allowed := range h.allowedGroups {
		allowed = strings.TrimSpace(allowed)
		if allowed == "" {
			continue
		}
		for _, group := range groups {
			if strings.EqualFold(allowed, strings.TrimSpace(group)) {
				return true
			}
		}
	}

	return false
}

func findUsernameInClaims(data map[string]interface{}) string {
	candidates := []string{"preferred_username", "unique_name", "upn", "username"}
	for _, claim := range candidates {
		userName, found := data[claim].(string)
		if found {
			return userName
		}
	}

	return ""
}

// findGroupsInClaims returns the groups the user is a member of. The claim
// can hold a single group as a string or a list of groups. Claim names that
// are not present yield no groups.
func findGroupsInClaims(data map[string]interface{}, claim string) []string {
	if claim == "" {
		claim = "groups"
	}

	raw, found := data[claim]
	if !found {
		return nil
	}

	switch value := raw.(type) {
	case string:
		return []string{value}
	case []string:
		return value
	case []interface{}:
		groups := make([]string, 0, len(value))
		for _, item := range value {
			if group, ok := item.(string); ok {
				groups = append(groups, group)
			}
		}
		return groups
	}

	return nil
}

func (h *OIDC) Authenticated(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := identity.FromRequestCtx(r)
		if id.Authenticated() && security.CredentialManager != nil {
			if err := security.CredentialManager.Refresh(r.Context(), id); err != nil {
				id.SetAuthenticated(false)
			}
		}

		if !id.Authenticated() {
			seed := make([]byte, 16)
			_, err := rand.Read(seed)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			state := hex.EncodeToString(seed)

			log.Printf("OIDC Authenticated: storing state '%s' for redirect to '%s'", state, r.RequestURI)
			err = storeOIDCState(w, r, state, r.RequestURI)
			if err != nil {
				log.Printf("OIDC Authenticated: failed to store state: %v", err)
				http.Error(w, "Failed to store OIDC state", http.StatusInternalServerError)
				return
			}

			session, err := GetSession(r)
			if err != nil {
				http.Error(w, "cannot read login session", http.StatusInternalServerError)
				return
			}
			verifier, _ := session.Values[oidcVerifierKey].(string)
			http.Redirect(w, r, h.oAuth2Config.AuthCodeURL(state,
				oauth2.SetAuthURLParam("prompt", "login"), oauth2.SetAuthURLParam("max_age", "0"),
				oauth2.SetAuthURLParam("nonce", state), oauth2.S256ChallengeOption(verifier)), http.StatusFound)
			return
		}

		// replace the identity with the one from the sessions
		next.ServeHTTP(w, r)
	})
}
