# ADR 0004: Passkeys and WebAuthn ceremonies

- Status: Accepted
- Date: 2026-07-28
- Scope: the first high-risk plugin PR after core management and SQL adapters

## Context

Better Auth exposes passkey registration, authentication, listing, renaming,
and deletion as a built-in plugin. A Go implementation must preserve that HTTP
shape while enforcing the WebAuthn relying-party contract independently of a
particular database adapter.

WebAuthn ceremonies are security protocols, not ordinary CRUD requests. The
server must bind each response to the exact relying-party ID, configured
origins, ceremony type, user, challenge, and expiry. Challenges and credential
counters must also remain safe under replay and concurrent requests.

## Decisions

### Package and endpoint surface

The feature is an opt-in `passkey` package that returns a normal
`betterauth.Plugin`. It contributes the logical `passkey` model and these
Better Auth-shaped routes:

| Method | Route | Contract |
| --- | --- | --- |
| GET | `/passkey/generate-register-options` | Requires a fresh session by default and creates registration options. |
| POST | `/passkey/verify-registration` | Requires the same fresh user session by default and atomically consumes the registration challenge. |
| GET | `/passkey/generate-authenticate-options` | Creates user-bound options when signed in, or discoverable options otherwise. |
| POST | `/passkey/verify-authentication` | Atomically consumes the authentication challenge, verifies the assertion, guards the signature counter, and issues a rotated core session. |
| GET | `/passkey/list-user-passkeys` | Lists Better Auth-compatible public credential metadata for the current user. |
| POST | `/passkey/update-passkey` | Renames an owned credential. |
| POST | `/passkey/delete-passkey` | Deletes an owned credential. |

Registration and credential-management mutations use session, freshness where
appropriate, trusted-origin, and CSRF enforcement. Authentication relies on the
single-use server challenge plus WebAuthn origin/RP verification because no
pre-existing authenticated CSRF secret is required.

Better Auth's passkey-first registration mode is available only through an
explicit `AllowWithoutSession` option with a required application user resolver.
If a browser session is present, freshness and CSRF are still enforced.
Registration/authentication extension resolvers and post-verification callbacks
are request-scoped ports. A callback cannot rebind an authenticated
registration to a different account.

### Relying-party and verification policy

`RPID`, `RPDisplayName`, and exact `Origins` are immutable plugin
configuration. The plugin validates them during server construction. Origins
must be HTTPS except loopback development, contain no wildcard, credentials,
query, or fragment, and must be valid for the configured RP ID. Cross-origin
iframe ceremonies are disabled.

User verification defaults to `required`. Applications may explicitly choose
`preferred` for Better Auth interoperability, but cannot disable user presence
or configured-origin verification. Attestation defaults to `none`, resident
keys default to `preferred`, and challenges expire after five minutes.

This deliberately strengthens Better Auth's current default verification
policy, which accepts a successful ceremony without requiring the user-
verification flag.

### Challenge storage and cookies

The browser receives a cryptographically random opaque challenge handle in a
host-only `__Host-` cookie with `Secure`, `HttpOnly`, `Path=/`, and `SameSite`
Lax or Strict attributes. Persistence contains only `SHA-256(handle)` in the
core `verification` model. The server-side metadata contains the complete
WebAuthn session data and ceremony binding.

Verification uses `ConsumeOne` with the hash, ceremony type, and unexpired
predicate before cryptographic validation. A challenge therefore has exactly
one verification attempt and cannot cross registration/authentication flows.

### Credential records

The plugin preserves Better Auth's public fields (`name`, `publicKey`,
`userId`, `credentialID`, `counter`, `deviceType`, `backedUp`, `transports`,
`createdAt`, and `aaguid`). It additionally stores:

- an opaque random `userHandle`, required to validate discoverable credentials;
- the full validated WebAuthn credential record needed for future assertion
  verification and attestation metadata evolution;
- an `updatedAt` timestamp.

Credential IDs are globally unique. Public keys and user handles use unpadded
base64url encoding. Secret session/challenge tokens are never stored raw.

Every successful authentication writes back the authenticator counter and
backup-state changes using a guarded update. A non-zero counter that fails to
advance is rejected as a possible cloned authenticator. Authenticators that
always report zero remain usable as permitted by WebAuthn.

### Plugin session issuance

`HookContext` gains a request-scoped `IssueSession` capability. It accepts a
validated user ID, rotates the request's existing session when present, creates
a new session otherwise, and returns the public session/user records plus
secure session and CSRF cookies. The raw bearer value is confined to cookie
construction.

The capability is installed by the server and cannot be supplied by a plugin.
It is intentionally generic because passkeys, SSO, and two-factor completion
all need the same fixation-safe transition into a core session.

## Consequences

- Passkeys remain a plugin and do not couple core authentication to WebAuthn.
- MongoDB, PostgreSQL, SQLite, memory, and future adapters receive the same
  logical schema and atomic-operation requirements.
- Existing Better Auth clients can use the same server endpoint sequence.
- Applications choosing Better Auth's weaker `preferred` user-verification
  behavior must do so explicitly.
- Passkey credentials created by this implementation carry an extra opaque user
  handle required for standards-compliant discoverable login.
- Two-factor authentication, organizations, SSO, and SCIM remain out of scope
  and continue as separate security-reviewed PRs.
