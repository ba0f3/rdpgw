# OpenID Connect Authentication

![OpenID Connect](images/flow-openid.svg)

RDPGW supports OpenID Connect authentication for integration with identity providers like Keycloak, Okta, Google, Azure, Apple, or Facebook.

## Configuration

To use OpenID Connect, ensure you have properly configured your OpenID Connect provider with a client ID and secret. The client ID and secret authenticate the gateway to the OpenID Connect provider. The provider authenticates the user and provides the gateway with a token, which generates a PAA token for RDP host connections.

```yaml
Server:
  Authentication:
    - openid
OpenId:
  ProviderUrl: https://<provider_url>
  ClientId: <your_client_id>
  ClientSecret: <your_client_secret>
Caps:
  TokenAuth: true
```

## Authentication Flow

1. User navigates to `https://your-gateway/connect`
2. Gateway redirects to OpenID Connect provider for authentication
3. User authenticates with the provider (supports MFA)
4. Provider redirects back to gateway with authentication token
5. Gateway validates token and generates RDP file with temporary credentials
6. User downloads RDP file and connects using remote desktop client

## Fresh authentication and persistent credentials

Each login requests `prompt=login`, `max_age=0`, a nonce and PKCE S256. The
callback requires a matching nonce and a fresh `auth_time` in the signed ID token.
The provider must support these OpenID Connect controls. Browser expiry is
enforced by the server even when a client retains its raw cookie.

For 30-day `.rdp` files, individual and user-wide revocation, restart persistence
and current Keycloak group checks, use
[persistent Keycloak credentials](persistent-credentials.md). The short-lived
JWT mode retains a snapshot of groups until its credentials expire.

## Multi-Factor Authentication (MFA)

RDPGW provides multi-factor authentication out of the box with OpenID Connect integration. Configure MFA in your identity provider to enhance security.

## Restricting the login to a group

The gateway can restrict the login to the members of one or more groups. A
user that is not a member of one of the listed groups is refused with `403
Forbidden` and no session is created.

```yaml
OpenId:
  ProviderUrl: https://<provider_url>
  ClientId: <your_client_id>
  ClientSecret: <your_client_secret>
  # only the members of these groups may log in
  Groups:
    - rdpgw-users
    - admins
  # the claim that carries the group membership of the user, "groups" by default
  GroupsClaim: groups
```

The group membership is read from the ID token. The provider has to put the
groups of the user in that claim, and the gateway has to ask for the scope
that makes the provider do so. The scopes are configurable because not every
provider knows the same scope:

```yaml
OpenId:
  # the default is "openid profile email"
  Scopes:
    - openid
    - profile
    - email
    - groups
```

For Keycloak the `groups` scope is available as an optional client scope. Add
it to the client of the gateway and the group membership shows up in the
`groups` claim of the ID token. Providers that reject an unknown scope (Azure
AD for example) must not have the `groups` scope added.

The group membership that the gateway reads is also the group membership that
the rules of the `access` section match on, see the
[Access Control Documentation](access-control.md).

## Provider Examples

### Keycloak
```yaml
OpenId:
  ProviderUrl: https://keycloak.example.com/auth/realms/your-realm
  ClientId: rdpgw
  ClientSecret: your-keycloak-secret
```

### Azure AD
```yaml
OpenId:
  ProviderUrl: https://login.microsoftonline.com/{tenant-id}/v2.0
  ClientId: your-azure-app-id
  ClientSecret: your-azure-secret
```

### Google
```yaml
OpenId:
  ProviderUrl: https://accounts.google.com
  ClientId: your-google-client-id.googleusercontent.com
  ClientSecret: your-google-secret
```

## Security Considerations

- Always use HTTPS for production deployments
- Store client secrets securely and rotate them regularly
- Configure appropriate scopes and claims in your provider
- Enable MFA in your identity provider for enhanced security
- Set appropriate session timeouts in both gateway and provider
- Restrict the login to a group when the provider supports it

## Troubleshooting

- Ensure `ProviderUrl` is accessible from the gateway
- Verify redirect URI is configured in your provider (usually `https://your-gateway/callback`)
- Check that required scopes (openid, profile, email) are configured
- Validate that the provider's certificate is trusted by the gateway
