# Access control

The gateway enforces an access policy for every authenticated user. The policy
has three parts:

1. the **redirect policy** — which client side resources may be redirected
   into the remote session
2. the **host ACL** — which remote hosts the user may connect to
3. the **group allow-list** — which users may log in at all (OpenID Connect)

Host ACLs are enforced by the gateway. Redirection limits are advertised to
clients and require enforcement on destination hosts when clients are untrusted.
See [destination host enforcement](redirection-enforcement.md).

## The redirect policy

### Where it is applied

The tunnel authorization response carries session redirection flags. The
credential binds the initial policy to its user and host. The generated `.rdp`
file contains matching settings. These controls guide cooperating clients;
the gateway does not filter clipboard or drive data inside the RDP payload.

Redirect settings cannot be overridden through `/connect` query parameters,
even if listed in `client.rdpoverridablekeys`. Such requests return 400.

### The ceiling and the rules

The `caps` section of the configuration holds the global policy. It is the
**ceiling** of the deployment: the rules in the `access` section can only
narrow it, they can never widen it. A rule that enables a resource the
global policy denies has no effect.

The ceiling holds for the whole life of a session. The policy that is
signed into the gateway access token is narrowed by the policy that is
configured when the client connects: a token that was issued under a looser
policy does not widen the policy of the gateway. In legacy JWT mode a token
without a redirect claim advertises `DisableAll`. Persistent mode rejects
legacy JWT credentials and requires an active stored record.

```yaml
Caps:
  # the global policy, the ceiling of the deployment
  EnableClipboard: false
  EnableDrive: false
  EnablePrinter: false
  EnablePort: false
  EnablePnp: false
  EnableSmartCard: false
  EnableWebAuthn: false
  EnableLocation: false
  EnableCamera: false
  EnableUsb: false
```

| Setting | Resource | Gateway advertisement |
|---------|----------|-----------------------|
| `EnableClipboard` | Clipboard | Tunnel flag and RDP property |
| `EnableDrive` | Drives and folders | Tunnel flag and RDP property |
| `EnablePrinter` | Printers | Tunnel flag and RDP property |
| `EnablePort` | Serial and COM ports | Tunnel flag and RDP property |
| `EnablePnp` | MTP/PTP devices | Tunnel flag and RDP property |
| `EnableSmartCard` | Smartcards | RDP property |
| `EnableWebAuthn` | WebAuthn prompts | RDP property |
| `EnableLocation` | Location | RDP property |
| `EnableCamera` | Cameras | RDP property |
| `EnableUsb` | USB devices | RDP property |

Every row requires destination enforcement against a client that ignores the
advertisement. File signatures do not control what client software executes.
`devicestoredirect` uses `*` or an empty selector for MTP/PTP, controlled by
`EnablePnp`. Camera, USB, smartcard and serial redirection have separate keys.

`caps.disableredirect` disables every redirection at once, `caps.redirectall`
enables every redirection at once. They are mutually exclusive, the disable
switch wins.

### Per user and per group rules

The `access` section holds the rules. The rules are evaluated in order and
the **first rule that matches the user applies**. A rule with `deny: true`
wins over every other rule: a denied user cannot log in, cannot download an
`.rdp` file and cannot reach any host.

```yaml
Access:
  Rules:
    - Name: contractors
      # a rule matches a user that is listed in Users or that is a member
      # of one of the Groups
      Users:
        - contractor@example.com
      Groups:
        - contractors
      # the redirect settings of the rule narrow the global policy.
      # Settings that are not mentioned are inherited.
      Redirect:
        EnableClipboard: false
        EnableDrive: false
      # the hosts the matching users may connect to. An empty list does
      # not restrict the hosts, the single entry "*" allows any host.
      Hosts:
        - 10.0.0.10
        - 10.0.0.11:3389
      # deny: true refuses the matching users access to the gateway
      # completely
      # Deny: false
```

A rule without `Users` and without `Groups` is refused when the gateway
starts, a rule like that would match every user.

A rule with `deny: true` refuses the matching users access to the gateway
completely: they cannot log in and none of the hosts is reachable for them.
It is the way to keep a user or a group out.

An unknown group membership never matches a group allow. A group deny also
denies unknown membership, including rules that have both `Users` and `Groups`.
If group rules exist and no explicit user allow matches, unknown membership
is denied. A verified empty group list matches no group selector. Native
authentication methods without group information should use explicit user
rules or obtain verified membership before group authorization.

The host list of a rule may contain the `{{ preferred_username }}`
placeholder, it is replaced with the name of the user.

## The host ACL

The host ACL restricts the remote hosts a user may connect to. It is applied
in three places:

* when the `.rdp` file is downloaded, the host that is selected (or that the
  user requested) is checked against the ACL
* when the client connects, the host that is requested in the tunnel is
  checked against the ACL
* the list of hosts in the web interface only shows the hosts the user may
  connect to

The ACL is applied on top of the host selection mode of the gateway
(`roundrobin`, `signed`, `unsigned` or `any`). It never widens what the host
selection mode allows, it only narrows it.

The host in the `hosts` list of a rule is compared case insensitively. The
port of the requested host is ignored when the rule does not carry one, so
`10.0.0.1` matches a connection to `10.0.0.1:3389`. A rule that carries a
port pins the endpoint, `10.0.0.1:3389` does not match a connection to
`10.0.0.1:3390`.

## The client address behind a proxy

The gateway binds the credentials of a session to the address of the client.
Behind a reverse proxy that address comes from the `X-Forwarded-For` header,
which the gateway only honors when the request arrives from one of the
`server.trustedproxies`.

The proxy has to **overwrite** the header with the address of the client:

```nginx
proxy_set_header X-Forwarded-For $remote_addr;
```

A header with more than one address is ignored: a client that prepends an
address to it produces the same chain as a proxy that appends to it, so the
gateway cannot tell which part of the chain the proxy wrote. The gateway
falls back to the address of the socket peer in that case and logs it.

List the addresses of the proxies in `server.trustedproxies`, not a range
that contains the clients as well: a client that reaches the gateway from an
address in that range can supply the header itself.

## The group allow-list

With OpenID Connect the gateway can restrict the login to the members of one
or more groups.

```yaml
OpenId:
  ProviderUrl: https://idp.example.com/realms/main
  ClientId: rdpgw
  ClientSecret: your-secret
  # only the members of these groups may log in
  Groups:
    - rdpgw-users
  # the claim that carries the group membership, "groups" by default
  GroupsClaim: groups
  # the scopes that are requested from the provider. The default is
  # "openid profile email".
  Scopes:
    - openid
    - profile
    - email
    - groups
```

A user that is not a member of one of the listed groups is refused with
`403 Forbidden` and no session is created.

The gateway does not add the `groups` scope by itself, because not every
provider knows that scope (Azure AD for example rejects it). Add the scope
that your provider uses for the group membership, for Keycloak that is
`groups`. The provider has to be configured to put the groups of the user in
the claim, for Keycloak that is a client scope with a groups mapper.

In legacy JWT mode, ID token groups are a snapshot at browser login and are
copied into downloaded credentials. Keep both lifetimes short in that mode.
For current membership on every connection, use
[persistent Keycloak credentials](persistent-credentials.md). That mode reads
the current user and groups through the Keycloak Admin API before authorization
and refuses stale, revoked, disabled or unavailable identities.

With header authentication the groups are taken from a header:

```yaml
Header:
  UserHeader: X-Forwarded-User
  GroupsHeader: X-Forwarded-Groups
  TrustedProxies:
    - 10.0.0.0/8
```

The value of the header is a comma separated list of group names.

## The lifetime of the credentials

The `.rdp` file carries a gateway access token. Its lifetime determines how
long the file stays usable. The browser session has a separate server-enforced
expiry. An expired browser session starts a fresh OIDC authentication.

For 30-day files with individual and user-wide revocation, follow
[the persistent credential configuration](persistent-credentials.md). Lifetimes
over one day require that mode. Its deadline is measured from the provider's
verified authentication time, so repeated downloads do not extend it.

```yaml
Security:
  # the lifetime of the gateway access token in minutes, the default is 5
  PAATokenLifetime: 60
  # the lifetime of the user token in minutes, the default is 5
  UserTokenLifetime: 60
  # the lifetime of the host selection query token in minutes, the default is 5
  QueryTokenLifetime: 5

Server:
  # the lifetime of the browser session in seconds, the default is 120
  SessionLifetime: 300
```

`server.maxsessionlength` is not a lifetime, it is the maximum size in bytes
of a session in the filesystem session store.

A longer lifetime of the gateway access token widens the window in which a
stolen `.rdp` file can be used. The gateway still verifies the IP address of
the client (`security.verifyclientip`) and the host of the token, so a token
that is used from another host is refused.
