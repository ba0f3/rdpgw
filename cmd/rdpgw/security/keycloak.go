package security

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/identity"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

type KeycloakConfig struct {
	Issuer        string
	ClientID      string
	ClientSecret  string
	GroupFormat   string
	AllowedGroups []string
}

type KeycloakResolver struct {
	adminURL      string
	groupFormat   string
	allowedGroups []string
	client        *http.Client
	oauth         clientcredentials.Config
}

func NewKeycloakResolver(c KeycloakConfig) (*KeycloakResolver, error) {
	u, err := url.Parse(strings.TrimRight(c.Issuer, "/"))
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("invalid Keycloak issuer")
	}
	if u.Scheme != "https" {
		ip := net.ParseIP(u.Hostname())
		if u.Scheme != "http" || (u.Hostname() != "localhost" && (ip == nil || !ip.IsLoopback())) {
			return nil, errors.New("Keycloak requires HTTPS except on loopback")
		}
	}
	base, realm, found := strings.Cut(u.Path, "/realms/")
	if !found || realm == "" || strings.Contains(realm, "/") || realm == "." || realm == ".." {
		return nil, errors.New("Keycloak issuer must end in /realms/{realm}")
	}
	if c.ClientID == "" || c.ClientSecret == "" {
		return nil, errors.New("Keycloak service client credentials are required")
	}
	if c.GroupFormat == "" {
		c.GroupFormat = "path"
	}
	if c.GroupFormat != "path" && c.GroupFormat != "name" {
		return nil, errors.New("Keycloak group format must be path or name")
	}
	admin := *u
	admin.Path = base + "/admin/realms/" + realm
	admin.RawPath = ""
	return &KeycloakResolver{
		adminURL: admin.String(), groupFormat: c.GroupFormat, allowedGroups: c.AllowedGroups,
		client: &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		oauth:  clientcredentials.Config{ClientID: c.ClientID, ClientSecret: c.ClientSecret, TokenURL: u.String() + "/protocol/openid-connect/token", AuthStyle: oauth2.AuthStyleInParams},
	}, nil
}

// Resolve never caches a user or group membership. A failed lookup denies
// access rather than falling back to the credential's original claims.
func (k *KeycloakResolver) Resolve(ctx context.Context, subject string) (identity.Identity, error) {
	if subject == "" || strings.ContainsAny(subject, "/\\") || subject == "." || subject == ".." {
		return nil, errors.New("invalid Keycloak subject")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	ctx = context.WithValue(ctx, oauth2.HTTPClient, k.client)
	token, err := k.oauth.Token(ctx)
	if err != nil {
		return nil, errors.New("cannot authenticate Keycloak authorization lookup")
	}
	endpoint := k.adminURL + "/users/" + url.PathEscape(subject)
	var user struct {
		ID              string   `json:"id"`
		Username        string   `json:"username"`
		Enabled         bool     `json:"enabled"`
		RequiredActions []string `json:"requiredActions"`
	}
	if err := k.get(ctx, token.AccessToken, endpoint, &user); err != nil {
		return nil, err
	}
	if user.ID != subject || !user.Enabled || user.Username == "" || len(user.RequiredActions) > 0 {
		return nil, errors.New("Keycloak user is unavailable or requires authentication")
	}
	groups := []string{}
	for first := 0; ; first += 100 {
		if first >= 10000 {
			return nil, errors.New("Keycloak group membership exceeds lookup limit")
		}
		var page []struct {
			Name string `json:"name"`
			Path string `json:"path"`
		}
		err := k.get(ctx, token.AccessToken, endpoint+"/groups?first="+strconv.Itoa(first)+"&max=100", &page)
		if err != nil {
			return nil, err
		}
		if page == nil {
			return nil, errors.New("Keycloak returned unknown group membership")
		}
		for _, group := range page {
			value := group.Path
			if k.groupFormat == "name" {
				value = group.Name
			}
			if strings.TrimSpace(value) == "" {
				return nil, errors.New("Keycloak returned invalid group membership")
			}
			groups = append(groups, value)
		}
		if len(page) < 100 {
			break
		}
	}
	if len(k.allowedGroups) > 0 && !groupMatches(k.allowedGroups, groups) {
		return nil, errors.New("user no longer belongs to an allowed Keycloak group")
	}
	id := identity.NewUser()
	id.SetUserName(user.Username)
	id.SetAttribute(identity.AttrSubject, subject)
	id.SetGroups(groups)
	id.SetAuthenticated(true)
	return id, nil
}

func (k *KeycloakResolver) get(ctx context.Context, token, endpoint string, target interface{}) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := k.client.Do(req)
	if err != nil {
		return errors.New("Keycloak authorization lookup failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Keycloak authorization lookup returned HTTP %d", resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(target)
}

func groupMatches(allowed, groups []string) bool {
	for _, a := range allowed {
		for _, g := range groups {
			if strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(g)) && strings.TrimSpace(a) != "" {
				return true
			}
		}
	}
	return false
}
