# Configure 30-day RDP credentials with Keycloak

Use persistent credential mode to keep downloaded `.rdp` files usable for up to
30 days, revoke individual credentials, and check current Keycloak permissions
on every connection. The default short-lived JWT mode remains available for
other authentication providers.

This mode requires an RDP client with WebSocket gateway transport. The legacy
`RDG_OUT_DATA` and `RDG_IN_DATA` pair cannot establish ownership before PAA
authentication in the current OpenID-only design and is refused with HTTP 426.
Verify your client version in a lab before rollout. A reverse proxy must
preserve WebSocket upgrade headers.

## Configure Keycloak and storage

1. Configure the gateway's OIDC client with the exact HTTPS callback URL
   `https://gateway.example/callback`. Enable the authorization code flow and
   PKCE S256. Configure a groups mapper on the ID token.
2. Create a separate confidential service client with service accounts enabled.
   Grant permission to read users and group membership through the
   [Keycloak Admin REST API](https://www.keycloak.org/docs-api/latest/rest-api/index.html).
   The `realm-management` role `view-users` is suitable where standard realm
   management roles are used. Verify both user and group endpoints return 200.
3. Match `AdminGroupFormat` to the ID token groups mapper. Use `path` for full
   paths such as `/rdpgw-users`, or `name` for names such as `rdpgw-users`.
   Use the same format in `OpenId.Groups`, `Access.Rules.Groups` and
   `CredentialAdminGroups`. Prefer paths when group names are not unique.
4. Mount a persistent, writable local volume at `/var/lib/rdpgw`. Give only the
   gateway account access to this directory. Run one gateway process per
   database. bbolt transactions serialize issuance and revocation, and a second
   process fails to acquire the database lock.
5. Apply the following configuration, supplying secrets through your existing
   secret injection mechanism.

```yaml
Server:
  GatewayAddress: https://gateway.example
  Authentication: [openid]
  Hosts: [desktop.internal:3389]
  HostSelection: roundrobin
  SessionLifetime: 120

OpenId:
  ProviderUrl: https://keycloak.example/realms/company
  ClientId: rdpgw
  # Supply ClientSecret through RDPGW_OPENID__CLIENTSECRET.
  AdminClientId: rdpgw-authorization-reader
  # Supply AdminClientSecret through RDPGW_OPENID__ADMINCLIENTSECRET.
  AdminGroupFormat: path
  Groups: [/rdpgw-users]
  GroupsClaim: groups
  CredentialAdminGroups: [/rdpgw-credential-admins]

Caps:
  TokenAuth: true
  EnableClipboard: false
  EnableDrive: false

Security:
  CredentialStore: /var/lib/rdpgw/credentials.db
  PAATokenLifetime: 43200 # minutes, 30 days; default in persistent mode
  EnableUserToken: false
  VerifyClientIp: true
```

Persistent mode requires OpenID as the only authentication method and
`Caps.TokenAuth:true`. HTTPS is required for Keycloak except for loopback lab
endpoints. The legacy destination username token is disabled in this mode;
authenticate to Windows or xrdp separately. A hostname in `Hosts` includes its
port. `HostSelection:any` additionally applies the configured IP and port
restrictions immediately before the TCP connection.

Keep the database on the persistent volume across restarts and image updates.
The file contains credential hashes and metadata, not bearer values. Protect
database access and backups because a writer can change authorization state.
Use a consistent backup with the gateway stopped or a bbolt transaction-aware
backup. Restoring an older database also restores its earlier revocation state.
The database is bound to its exact OIDC issuer URL and cannot be reused for a
different realm. Deleting or losing the database invalidates existing files.

The RDP bearer does not depend on the JWT or browser session keys, so rotating
those keys or restarting the process does not invalidate a recorded credential.
Keep browser session keys stable if browser sessions must survive a restart too.
Existing JWT `.rdp` files are rejected when persistent mode is enabled. Users
must authenticate and download new files once during migration.

## Download and renew files

Open `/connect`, complete Keycloak authentication, and download the file. The
credential expires at `auth_time + PAATokenLifetime`, with a maximum of 30 days.
Downloading another file from the same browser session does not extend that
authentication deadline. Browser sessions still expire after `SessionLifetime`.

An expired file is rejected by the gateway. Open `/connect` again to obtain a
new file. The gateway sends `prompt=login`, `max_age=0`, a nonce and PKCE, then
checks the nonce and fresh `auth_time` in the signed ID token. These are the
fresh-authentication controls defined by
[OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html).
Configure Keycloak authentication flows and any upstream identity broker to
require the intended password or MFA interaction for that request.

On each connection the gateway reads the current Keycloak user and every page
of group membership. Disabled, deleted or required-action users, denied groups,
removed allowed-group membership, storage failures and Keycloak lookup errors
block new connections. Lookup time is bounded to 10 seconds. The gateway checks
the record again at channel creation so a client cannot delay channel creation
to reuse authorization checked only at the initial handshake. A policy change
that changes advertised redirect flags during a handshake causes channel creation
to fail; reconnect to obtain the updated flags. Local ACL changes
take effect after loading the new gateway configuration; configuration hot
reload is not provided.

`VerifyClientIp:true` binds a file to its issuing client IP. Configure trusted
proxies correctly. A user whose IP changes must download a new file, or the
operator can choose `false` for roaming clients.

## List and revoke credentials

Use an authenticated browser session against the following endpoints. IDs in
these responses are public SHA-256 identifiers and are not usable as bearers.

| Method | Endpoint | Permission |
|---|---|---|
| GET | `/api/v1/credentials` | Own credentials |
| GET | `/api/v1/credentials?user=KEYCLOAK_SUBJECT` | Own subject or current credential admin |
| DELETE | `/api/v1/credentials/CREDENTIAL_ID` | Owner or current credential admin |
| DELETE | `/api/v1/users/me/credentials` | Revoke all own credentials |
| DELETE | `/api/v1/users/KEYCLOAK_SUBJECT/credentials` | Same subject or current credential admin |

`KEYCLOAK_SUBJECT` is the immutable user ID from the realm, not a username or
email. The credential listing includes `subject`, `user`, `host`, `authTime`,
`issuedAt`, `expiresAt`, and `revoked`. Check `expiresAt` separately from
`revoked` when displaying expired records.

Run this in the gateway page's browser console to list and revoke a selected
credential. Replace the ID with one from the listing.

```javascript
await fetch('/api/v1/credentials').then(r => r.json());
await fetch('/api/v1/credentials/CREDENTIAL_ID', {
  method: 'DELETE',
  headers: { 'X-RDPGW-CSRF': '1' }
});
```

Browsers supply `Origin` on DELETE. CLI clients must supply both
`Origin: https://gateway.example` and `X-RDPGW-CSRF: 1`, with their authenticated
session cookie. A successful revoke returns 204. Cross-user access without
current admin membership is refused. Admin group membership is read live.

User-wide revocation advances a stored generation atomically. Existing files
and old browser sessions cannot issue replacements using that generation.
A fresh Keycloak authentication permits new issuance. Individual revocation
leaves other credentials and the browser session usable. Revocation and expiry
block subsequent connections; they do not terminate a desktop already connected.
Terminate such sessions on the destination host when immediate disconnection is
required.

## Verify the deployment

Run `GO=/path/to/go bash scripts/verify-audit.sh` for repository checks. In a lab,
download a file, restart the gateway, and confirm the same file connects. Revoke
that credential and confirm it fails while another credential still connects.
Revoke all credentials for the user and confirm all old files fail, including
after another restart. Confirm an old browser session cannot issue replacements.

Remove the user's allowed group, add a deny group, disable the user and stop
Keycloak in separate checks. Each change must block a new connection. Use a
shorter `PAATokenLifetime` in a lab to exercise expiry, retain the raw session
cookie past `SessionLifetime`, and confirm a real Keycloak authentication is
required before a new download succeeds.

Clipboard and drive restrictions require separate
[destination host enforcement](redirection-enforcement.md). Gateway tests do
not prove that a client cannot transfer files through an established RDP session.
