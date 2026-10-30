package security

import (
	"context"
	"errors"
	"time"

	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/access"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/credentials"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/identity"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/protocol"
)

// CredentialManager is installed at startup only in persistent Keycloak mode.
// When installed, stateless JWT credentials are never accepted.
var CredentialManager *CredentialService

type CredentialService struct {
	Store   *credentials.Store
	Resolve func(context.Context, string) (identity.Identity, error)
}

// Login captures the revocation generation after a fresh OIDC authentication.
func (c *CredentialService) Login(ctx context.Context, id identity.Identity) error {
	subject, _ := id.GetAttribute(identity.AttrSubject).(string)
	if subject == "" {
		return errors.New("OIDC subject is required")
	}
	g, err := c.Store.Generation(subject)
	if err != nil {
		return err
	}
	id.SetAttribute(identity.AttrCredentialGeneration, g)
	return c.Refresh(ctx, id)
}

// Refresh checks both current Keycloak membership and the browser session's
// generation. Revoke-all requires a new real login before further issuance.
func (c *CredentialService) Refresh(ctx context.Context, id identity.Identity) error {
	if PAATokenLifetime < 1 || PAATokenLifetime > 30*24*60 {
		return credentials.ErrInvalid
	}
	if id == nil || !id.Authenticated() || id.AuthTime().IsZero() || !time.Now().Before(id.AuthTime().Add(time.Duration(PAATokenLifetime)*time.Minute)) {
		return credentials.ErrInvalid
	}
	subject, _ := id.GetAttribute(identity.AttrSubject).(string)
	issuedGeneration, ok := id.GetAttribute(identity.AttrCredentialGeneration).(uint64)
	if subject == "" || !ok {
		return credentials.ErrInvalid
	}
	g, err := c.Store.Generation(subject)
	if err != nil {
		return err
	}
	if g != issuedGeneration {
		return credentials.ErrInvalid
	}
	current, err := c.Resolve(ctx, subject)
	if err != nil {
		return err
	}
	if current == nil || !current.Authenticated() || current.GetAttribute(identity.AttrSubject) != subject || current.UserName() == "" {
		return credentials.ErrInvalid
	}
	id.SetUserName(current.UserName())
	id.SetGroups(current.Groups())
	if access.Current().Denied(id) {
		return errors.New("current access policy denies user")
	}
	return nil
}

func (c *CredentialService) Issue(ctx context.Context, server string) (string, error) {
	id := identity.FromCtx(ctx)
	if err := c.Refresh(ctx, id); err != nil {
		return "", err
	}
	if !access.Current().HostAllowed(id, server) {
		return "", errors.New("current access policy denies destination")
	}
	if PAATokenLifetime < 1 || PAATokenLifetime > 30*24*60 {
		return "", errors.New("credential lifetime must be between 1 minute and 30 days")
	}
	ip, _ := id.GetAttribute(identity.AttrClientIp).(string)
	subject, _ := id.GetAttribute(identity.AttrSubject).(string)
	g := id.GetAttribute(identity.AttrCredentialGeneration).(uint64)
	return c.Store.Issue(credentials.Record{
		Subject: subject, UserName: id.UserName(), Generation: g, Host: server, ClientIP: ip,
		Policy: access.Current().PolicyFor(id), AuthTime: id.AuthTime(), ExpiresAt: id.AuthTime().Add(time.Duration(PAATokenLifetime) * time.Minute),
	})
}

func (c *CredentialService) Check(ctx context.Context, token string) (bool, error) {
	r, err := c.Store.Lookup(token)
	if err != nil {
		return false, err
	}
	return c.install(ctx, r)
}

func (c *CredentialService) Recheck(ctx context.Context) (bool, error) {
	tunnel := getTunnel(ctx)
	if tunnel == nil || tunnel.CredentialID == "" || tunnel.RedirectFlags == nil {
		return false, credentials.ErrInvalid
	}
	advertised := *tunnel.RedirectFlags
	r, err := c.Store.Get(tunnel.CredentialID)
	if err != nil {
		return false, err
	}
	if ok, err := c.install(ctx, r); !ok || err != nil {
		return false, err
	}
	if *tunnel.RedirectFlags != advertised {
		return false, errors.New("redirection policy changed; a new gateway handshake is required")
	}
	return true, nil
}

func (c *CredentialService) install(ctx context.Context, r credentials.Record) (bool, error) {
	tunnel := getTunnel(ctx)
	if tunnel == nil || tunnel.User == nil {
		return false, errors.New("no tunnel identity")
	}
	if VerifyClientIP {
		id := identity.FromCtx(ctx)
		if id == nil || r.ClientIP == "" || id.GetAttribute(identity.AttrClientIp) != r.ClientIP {
			return false, credentials.ErrInvalid
		}
	}
	current, err := c.Resolve(ctx, r.Subject)
	if err != nil {
		return false, err
	}
	if current == nil || !current.Authenticated() || current.GetAttribute(identity.AttrSubject) != r.Subject || current.UserName() == "" ||
		!access.Current().HostAllowed(current, r.Host) {
		return false, credentials.ErrInvalid
	}
	// Recheck after the network lookup so concurrent revocation during the
	// lookup cannot authorize the connection with a previously loaded record.
	if _, err := c.Store.Get(r.ID); err != nil {
		return false, err
	}
	tunnel.User.SetUserName(current.UserName())
	tunnel.User.SetGroups(current.Groups())
	tunnel.User.SetAttribute(identity.AttrSubject, r.Subject)
	tunnel.User.SetAuthenticated(true)
	tunnel.User.SetAuthTime(r.AuthTime)
	tunnel.User.SetExpiry(r.ExpiresAt)
	tunnel.TargetServer, tunnel.RemoteAddr, tunnel.CredentialID = r.Host, r.ClientIP, r.ID
	flags := protocol.RedirectFlagsFromPolicy(r.Policy.Narrow(access.Current().PolicyFor(current)))
	tunnel.RedirectFlags = &flags
	return true, nil
}
