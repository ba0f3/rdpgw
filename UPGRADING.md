# Upgrading

## Unreleased

### The redirect policy is enforced by the gateway

The redirect settings of a session are a policy of the gateway now and not a
default of the client. Three things changed:

* The resolved policy is signed into the gateway access token and replayed
  in the tunnel authorization response. The restriction stays bound to the
  user the `.rdp` file was issued for.
* The generated `.rdp` file is rewritten so that its redirect settings match
  the policy. The file now always carries `redirectclipboard`,
  `redirectprinters`, `redirectcomports`, `redirectsmartcards`,
  `redirectwebauthn`, `redirectlocation`, `drivestoredirect`,
  `devicestoredirect`, `camerastoredirect` and `usbdevicestoredirect`.
* The redirect settings can no longer be overridden through the
  `/connect` URL query parameters. A request that tries to do so is
  rejected with `400 Bad Request`, also when the key is listed in
  `Client.RdpOverridableKeys`. Remove the redirect keys from that list,
  they have no effect anymore.

The smartcard, WebAuthn and location redirection are part of the policy now
and are denied by default. The RDP gateway protocol has no flag for them,
they are enforced by the `.rdp` file only. Set `Caps.EnableSmartCard`,
`Caps.EnableWebAuthn` or `Caps.EnableLocation` to `true` to allow them.

Because those three settings live in the `.rdp` file only, they are advisory
when the file travels through an untrusted channel. Configure
`Client.SigningCert` and `Client.SigningKey` to sign the file if that
matters for your deployment. The signature does not cover
`redirectlocation`, `redirectwebauthn`, `camerastoredirect` and
`usbdevicestoredirect`, keep those in mind.

### `X-Forwarded-For` has to be overwritten by the proxy

The gateway only trusts a `X-Forwarded-For` header that holds exactly one
address. A chain with more than one address is ignored, because a client
that prepends an address to the header produces the same chain as a proxy
that appends to it: the gateway cannot tell which part of the chain the
proxy wrote.

The proxy has to overwrite the header with the address of the client:

```nginx
proxy_set_header X-Forwarded-For $remote_addr;
```

`$proxy_add_x_forwarded_for` appends to a header the client could have
supplied, the gateway ignores the result of it and falls back to the
address of the socket peer. List the addresses of the proxies in
`Server.TrustedProxies`, not a range that contains the clients as well.

### The device redirection of the client is listed per device type

The camera and the USB devices of the client are their own resources now:
`Caps.EnableCamera` and `Caps.EnableUsb` allow them, the device
redirection (`Caps.EnablePnp`) does not imply them. The `devicestoredirect`
setting of the `.rdp` file lists the device types that are allowed
(`port`, `smartcard`, `usb`, `camera`).

Operators that had `Caps.EnablePnp: true` and want the devices of the
client to be redirected have to enable the types they need.

### A rule that selects a group does not fail open

A rule that selects a group also applies to the users whose group
membership the gateway does not know (the authentication methods that
cannot deliver a group membership, and the users whose provider did not
send the groups claim). The gateway cannot tell whether they are a member
of the group, and a rule that selects a group must not fail open for them.

### A rule with `deny: true` denies the login

A rule with `deny: true` refused the hosts of a user before, the user
could still log in and download an `.rdp` file. The rule refuses the login
now, in every authentication method.

### The lifetime of the credentials is configurable

The gateway access token that is embedded in the `.rdp` file expires after
five minutes. That lifetime is now configurable:

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

A longer lifetime of the gateway access token widens the window in which a
stolen `.rdp` file can be used. The gateway keeps verifying the IP address
of the client (`Security.VerifyClientIp`) and the host of the token.

Note that `Server.MaxSessionLength` is not a lifetime, it is the maximum
size in bytes of a session in the filesystem session store.

### Container image no longer bakes a TLS cert and runs as UID 1001

Two changes to `dev/docker/Dockerfile` and the dev image's entrypoint:

* The build step that ran `openssl genrsa` / `openssl x509` and shipped
  the resulting key/cert in the image is gone. The runtime image now
  contains `openssl` and the entrypoint mints an ephemeral self-signed
  cert at first start when no cert is mounted at the configured path.
  Each container instance gets its own key.
* The entrypoint runs as UID 1001 throughout. The previous `USER 0`
  block, the dead `createusers.txt` loop in `run.sh`, and the
  `chmod u+s` on `rdpgw-auth` (which set the bit on a file owned by
  1001 and was therefore a no-op anyway) have been removed.

If you mount your own cert (recommended for any non-dev deployment),
make sure `RDPGW_SERVER__CERT_FILE` and `RDPGW_SERVER__KEY_FILE` point
to the mounted paths. Otherwise the entrypoint generates a fresh
self-signed pair at the configured locations on first start.

If your deployment relies on `rdpgw-auth` running with elevated
privileges from the same image, run it from a separate container or
use Linux capabilities -- see
[docs/pam-authentication.md](docs/pam-authentication.md) for the
privilege-separation model.

### Refuse to start when known placeholder secrets are configured

These literal values appearing in `Server.SessionKey`,
`Server.SessionEncryptionKey`, `Security.PAATokenSigningKey`,
`Security.PAATokenEncryptionKey`, `Security.UserTokenSigningKey`,
`Security.UserTokenEncryptionKey`, or `Security.QueryTokenSigningKey`
will now cause rdpgw to refuse to start:

```
thisisasessionkeyreplacethisjetzt
thisisasessionkeyreplacethisjetz
thisisasessionkeyreplacethisnunu!
thisisasessionkeyreplacethisnunu
thisisasessionencryptionkey12345
```

These are the published example values from `README.md` and the dev
compose files. Replace them with unique 32-character strings.

### `rdpgw-auth` only accepts connections from the daemon's own UID by default

The auth daemon previously created its socket world-writable
(`Umask(0)`) and accepted any local UID that could `connect(2)` to it.
Two changes:

* The socket is now created with mode `0660` (no access for `other`).
* The daemon reads `SO_PEERCRED` on every accepted connection and
  rejects callers whose UID is not on the allow-list. The default
  allow-list is the daemon's own UID.

If `rdpgw` and `rdpgw-auth` run as the same user, no action is
required. Otherwise, list the gateway's UID (or a shared GID):

```
./rdpgw-auth -s /tmp/rdpgw-auth.sock --allow-uid 1001
./rdpgw-auth -s /tmp/rdpgw-auth.sock --allow-gid 1100
```

`--allow-uid` and `--allow-gid` are repeatable.

### `X-Forwarded-For` is no longer trusted by default

Previously rdpgw read the first `X-Forwarded-For` entry into the
request identity unconditionally. The resulting client IP attribute is
later compared against the value embedded in the gateway access
cookie, so any caller reaching rdpgw directly could set
`X-Forwarded-For` to any value and steer that binding.

After upgrading, `X-Forwarded-For` is honored only when the request
arrives from a `Server.TrustedProxies` CIDR. Otherwise the client IP
comes from `r.RemoteAddr`. The default `Server.TrustedProxies` is
empty, so by default `X-Forwarded-For` is ignored entirely.

If your deployment fronts rdpgw with a reverse proxy or load balancer
on a known subnet, list it:

```yaml
Server:
  TrustedProxies:
    - 10.0.0.0/8        # the proxy's egress subnet
```

If no proxy fronts rdpgw, leave `TrustedProxies` empty -- the
request's `RemoteAddr` is the right source for client identity in
that case.

The chain of `X-Forwarded-For` is now evaluated from the right: the
client address is the right most address of the chain that is not a
trusted proxy itself. The addresses on the right are the ones the
trusted proxies appended and are more trustworthy than the ones a
client could have supplied itself. Taking the first address of the
chain let a client pick the address the gateway binds the credentials
of a session to, which made a stolen `.rdp` file usable from another
network.

Proxies that forward the header should therefore set it to the address
they see instead of appending to a value the client supplied:

```nginx
proxy_set_header X-Forwarded-For $remote_addr;
```

A proxy that appends (`$proxy_add_x_forwarded_for`) still works, the
address the proxy appended is the one the gateway uses.

### `hostselection: any` now refuses non-routable destinations and non-RDP ports by default

Previously, when `server.hostselection: any` was set, rdpgw forwarded
to whatever `?host=` value the request carried with no check on the
target. The gateway would happily relay TCP traffic to loopback,
RFC1918, link-local, or arbitrary high-numbered ports on public hosts.

After upgrading, `any` mode rejects any destination that resolves to a
loopback / RFC1918 / link-local / IPv6 ULA / unspecified / multicast
address, and any port that is not in `AllowedDestinationPorts`. The
default port allow-list is `[3389]`.

If your deployment legitimately reaches private destinations or extra
ports through `any` mode, opt back in:

```yaml
Server:
  HostSelection: any
  AllowedDestinationPorts:
    - 3389
    - 5985        # add what you actually need
  AllowPrivateDestinations: true
```

The other host-selection modes (`roundrobin`, `signed`, `unsigned`)
already use the operator-curated `Server.Hosts` allow-list and are
unaffected by this change.

# Upgrading from 1.X to 2.0

In 2.0 the options for configuring client side RDP settings have been removed in favor of template file.
The template file is a RDP file that is used as a template for the connection. The template file is parsed 
and a few settings are replaced to ensure the client can connect to the server and the correct domain is used.

The format of the template file is as follows:

```
# <setting>:<type i or s>:<value>
domain:s:testdomain
connection type:i:2
```

The filename is set under `client > defaults`.
