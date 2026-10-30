# Audit remediation and persistent credentials implementation plan

**Goal:** Fix the supplied audit findings and support revocable RDP credentials lasting up to 30 days with current Keycloak authorization.

**Architecture:** Opt-in persistent credential mode uses opaque random bearer values, SHA-256 lookup keys and bbolt transactions. Credential records bind immutable Keycloak subject, host, client IP, original authentication time, expiry and initial redirect policy. Live Keycloak Admin API user/group checks precede acceptance. Existing short-lived JWT mode remains available for other authentication providers; lifetimes over one day require persistent mode.

**Approaches:** Extending stateless JWT expiry cannot support revocation or live membership. Signed JWT plus persistent records works but adds key lifecycle requirements. Opaque credentials with persistent records provide the required lifecycle without signing-key dependence; this is the implementation choice.

**Scope:** F2–F6 and RDP grammar are code fixes. F1 requires enforcement on destination session hosts because the gateway relays encrypted RDP; document that boundary and host acceptance checks. No production host policy is changed in this checkout.

**Constraints:** Maximum credential age is 30 days from real OIDC authentication, not download time. Never fall back to snapshots on Keycloak/storage errors. State is on a persistent local volume, one gateway process per database. Persistent mode requires WebSocket gateway transport; anonymous legacy HTTP pairing remains refused. Revocation blocks subsequent connections, not an already open desktop session. Revoke-all advances a user generation so old web sessions cannot mint replacements.

## Tasks

- [x] Add failing regressions for unknown groups, malformed framing, server session expiry and configuration decode. Fix each shared boundary and exact RDP keys.
- [x] Add transactional credential storage with tests for reopen, expiry, hashing, individual/user revocation and issuance generations.
- [x] Add Keycloak live identity resolver with HTTP tests for groups pagination, disabled/deleted users and upstream errors.
- [x] Wire persistent PAA issuance/validation, fresh OIDC login evidence and authenticated revocation APIs. Test actual download-to-connection lifecycle and permissions changes.
- [x] Move destination resolution/validation/dialing into one shared policy and wire gateway dial hook. Test prohibited ports/IPs, approved-IP dialing and curated private hosts.
- [x] Document configuration, API use, deployment persistence, migration and destination-host enforcement. Add a repeatable verification script.
- [x] Run focused tests, full repository suite, race tests and vet; obtain one independent read-only review and fix confirmed issues.

## Review focus

Legacy credentials must not bypass persistent-mode revocation. Live identity must preserve the immutable subject while using current username/groups. Expired cookies should start OIDC normally, without a 500 loop. Replayed callbacks must not accept old auth_time or wrong nonce. Database errors and Keycloak outages must deny new connections.

## Verification and deployment boundary

The repository verification script runs the full test suite, gateway race tests,
vet and whitespace checks. Regression tests cover F2–F6, exact RDP keys,
DisableAll precedence, signed known-empty group membership, raw-cookie replay,
malformed-cookie PKCE recovery, database reopen and revocations, live Keycloak
HTTP responses, supported WebSocket handshakes and policy changes before dial.
A delayed channel is rejected if its advertised redirect flags have changed.

The built gateway was started twice against a local OIDC discovery fixture with
the persistent configuration. Both starts opened the database and the credential
API requested fresh OIDC. Real Keycloak, Windows/xrdp host policy and native client
compatibility still require lab acceptance. F1 is a destination enforcement
requirement, not a gateway payload-filtering fix.
