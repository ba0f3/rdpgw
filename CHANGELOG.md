# Changelog

All user-visible changes to rdpgw will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- The dev container image no longer ships a baked-in TLS key/cert.
  The runtime image carries `openssl` and the entrypoint generates an
  ephemeral self-signed cert at first start if none is mounted at the
  configured path; each container instance gets its own key. The
  entrypoint also runs entirely as UID 1001 (no more `USER 0`).
- rdpgw refuses to start when any of `Server.SessionKey`,
  `Server.SessionEncryptionKey`, `Security.PAATokenSigningKey`,
  `Security.PAATokenEncryptionKey`, `Security.UserTokenSigningKey`,
  `Security.UserTokenEncryptionKey`, or `Security.QueryTokenSigningKey`
  matches a published placeholder value from `README.md` / the dev
  compose files. See [UPGRADING.md](UPGRADING.md) for the full list.
- `rdpgw-auth` now creates its socket with mode `0660` and accepts only
  connections whose peer UID is on an allow-list (default: the daemon's
  own UID). Operators running rdpgw and rdpgw-auth as different users
  must list the gateway's UID via `--allow-uid` or share a group via
  `--allow-gid`. See [UPGRADING.md](UPGRADING.md).
- `X-Forwarded-For` is now honored only when the request arrives from
  a `Server.TrustedProxies` CIDR. The default `Server.TrustedProxies`
  is empty, so by default the request's `RemoteAddr` (host portion) is
  the source of `AttrClientIp`. See [UPGRADING.md](UPGRADING.md) if
  your deployment relies on a fronting proxy stamping XFF.
- `server.hostselection: any` now refuses destinations that resolve to
  loopback, RFC1918, link-local, IPv6 ULA, unspecified, or multicast
  addresses, and only forwards to ports in `Server.AllowedDestinationPorts`
  (default `[3389]`). Operators that need the old behavior can opt back in
  with `Server.AllowPrivateDestinations: true` and an extended port list.
  See [UPGRADING.md](UPGRADING.md) for migration notes. The other
  host-selection modes (`roundrobin`, `signed`, `unsigned`) already used
  the operator-curated `Server.Hosts` list and are unaffected.
- The redirect policy of the gateway is enforced as a policy of the gateway
  and not as a default of the client. The resolved policy is signed into
  the gateway access token and replayed in the tunnel authorization
  response, and the generated `.rdp` file is rewritten to match it. The
  redirect settings of the `.rdp` file can no longer be overridden through
  the `/connect` URL query parameters, not even when they are listed in
  `Client.RdpOverridableKeys`. See [UPGRADING.md](UPGRADING.md).
- The `.rdp` file now always carries the redirect settings of the policy,
  even when they carry the value the client uses by default.

### Added

- Access control policy. The `Access` section holds per user and per group
  rules that narrow the redirect policy of the gateway and restrict the
  remote hosts a user may connect to. The rules are evaluated in order, the
  first rule that matches the user applies. The global policy in `Caps` is
  the ceiling of the deployment, a rule can only narrow it. A rule with
  `deny: true` keeps the matching users out completely. See
  [docs/access-control.md](docs/access-control.md).
- `OpenId.Groups` (`[]string`) restricts the login to the members of the
  listed groups. A user that is not a member of one of them is refused with
  `403 Forbidden`. `OpenId.GroupsClaim` (default `groups`) selects the claim
  that carries the group membership, `OpenId.Scopes` (default
  `openid profile email`) selects the scopes that are requested from the
  provider.
- `Header.GroupsHeader` carries the group membership of the user for header
  authentication. The value is a comma separated list of group names.
- `Caps.EnableSmartCard`, `Caps.EnableWebAuthn` and `Caps.EnableLocation`
  (`bool`, default `false`) add the smartcard, WebAuthn and location
  redirection to the redirect policy of the gateway.
- `Security.PAATokenLifetime`, `Security.UserTokenLifetime` and
  `Security.QueryTokenLifetime` (`int`, minutes, default `5`) make the
  lifetime of the credentials the gateway hands out configurable.
- `Server.SessionLifetime` (`int`, seconds, default `120`) makes the
  lifetime of the browser session configurable.
- `rdpgw-auth --allow-uid` and `--allow-gid` flags (repeatable).
- `Server.TrustedProxies` (`[]string`, CIDR, default empty).
- `Server.AllowedDestinationPorts` (`[]int`, default `[3389]`).
- `Server.AllowPrivateDestinations` (`bool`, default `false`).
