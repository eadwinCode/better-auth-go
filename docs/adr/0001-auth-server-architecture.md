# ADR 0001: Native Go Authentication Server Architecture

- Status: Accepted
- Date: 2026-07-28
- Decision owners: better-auth-go maintainers
- Module: `github.com/eadwinCode/better-auth-go`

## Context

`better-auth-go` is an embeddable authentication server library for Go
applications. It owns authentication state and HTTP endpoints. It is not an HTTP
client SDK and does not require a Node or Bun service.

Applications must be able to mount a standard `net/http` handler under
`/api/auth/` or a configured base path. The first storage implementation is
MongoDB, but domain and service code must not depend on MongoDB types.

The initial release must support:

- email/password sign-up and sign-in;
- sign-out, session retrieval, refresh, rotation, and revocation;
- Google OAuth authorization-code flow with PKCE;
- password reset and email verification;
- authorization-controlled admin impersonation with durable audits;
- secure browser-cookie operation with origin and CSRF protection;
- deterministic tests through injected clocks and token sources;
- user-created events suitable for idempotent downstream provisioning.

## Decision

### Package boundaries

The public root package, `betterauth`, exposes versioned configuration,
interfaces, domain records, structured errors, and `Server.Handler()`.

Internal behavior is split by responsibility:

- HTTP transport: routing, bounded JSON decoding, cookies, origin/CSRF checks,
  response mapping, and request metadata;
- application services: use-case orchestration and transaction boundaries;
- security primitives: Argon2id, opaque token generation and hashing, constant
  time comparisons, PKCE, and validation;
- ports: database adapter, mail delivery, events, rate limiting, authorization,
  audit, clock, token source, and OAuth provider;
- adapters: MongoDB is implemented in a separate importable package.

No request-specific credential, token, or principal is stored in global state or
on a mutable shared client.

### Public API and compatibility

The module follows semantic versioning. Public contracts begin at API version
`v1`; endpoint URLs include `/v1/`. The root Go package remains import-compatible
within a major module version.

Native Go records and Argon2id password hashes are canonical. Better Auth scrypt
compatibility is optional and is provided through a configurable
`PasswordVerifier`/rehash bridge. Successful verification of a legacy hash may
return an Argon2id replacement for atomic persistence.

### HTTP surface

Given the default base path `/api/auth`, version-one endpoints are:

- `POST /v1/sign-up/email`
- `POST /v1/sign-in/email`
- `POST /v1/sign-out`
- `GET /v1/session`
- `POST /v1/session/refresh`
- `POST /v1/session/revoke`
- `GET /v1/oauth/google`
- `GET /v1/oauth/google/callback`
- `POST /v1/password/forgot`
- `POST /v1/password/reset`
- `POST /v1/email/verification/send`
- `POST /v1/email/verification/confirm`
- `POST /v1/admin/impersonate`

Unknown routes return structured `404` errors. Unsupported methods return
structured `405` errors.

### Session security

Session tokens contain at least 256 bits of cryptographic entropy. The raw token
is returned only in a host-only cookie; persistence stores a SHA-256 token hash.
The cookie is `HttpOnly`, `Secure`, host-only (no `Domain`), and configurable
between `SameSite=Lax` and `SameSite=Strict`. `SameSite=None` is rejected.

Sign-in, password reset, privilege changes, impersonation, and refresh rotate
sessions to prevent fixation. Refresh is single-use at the persisted-session
level: adapters atomically replace the old hash with the new hash. Expired,
revoked, or superseded sessions fail closed.

Impersonation sessions are capped at one hour regardless of normal session
duration. They retain actor and subject identifiers and always emit a durable
audit event in the same adapter operation that creates the session.

### Password security

New passwords use Argon2id with configurable parameters and conservative
defaults:

- memory: 64 MiB;
- iterations: 3;
- parallelism: 2;
- salt: 16 random bytes;
- key: 32 bytes.

Configuration validates minimums and rejects unsafe parameters. Encoded hashes
use the standard PHC string format. Verification parses with strict length and
parameter bounds before allocating memory. Password length is bounded in bytes.

### OAuth security

The Google flow uses authorization code plus S256 PKCE. State and verifier are
cryptographically random, single-use, hash-at-rest, and short-lived. The
callback's destination is selected from an exact configured allowlist; arbitrary
redirect URLs are rejected.

OAuth token and user-info calls use bounded clients, contexts, response-size
limits, and explicit status validation. Only a verified Google email may create
or link an account. Linking by email is atomic and rejects conflicting provider
identities. Provider errors are mapped to stable public errors without reflecting
provider-controlled strings.

### One-time tokens and mail

Password-reset and email-verification tokens are opaque random values. Only
their SHA-256 hashes are stored. They have explicit purposes, expirations, and
single-use atomic consumption. Mail delivery is an injected port. Public
"forgot password" and verification-send responses are generic whether an
account exists.

### Request security and abuse controls

State-changing cookie-authenticated requests require both:

- an allowed `Origin` (or a same-origin policy where configured); and
- a double-submit CSRF token using a host-only secure cookie and a request
  header.

OAuth callbacks use single-use state instead of the general CSRF token.

Every body is read through `http.MaxBytesReader` and strict JSON decoding.
Rate-limit hooks receive stable action names, remote IP, and normalized account
keys. Hook errors fail closed. Authentication failures use generic messages and
stable error codes to resist account enumeration.

Trusted origins and callback destinations are normalized URLs and validated at
startup. Wildcards, credentials, fragments, insecure production origins, cookie
domains, missing secrets/ports, and unusable durations cause constructor errors.

### Persistence and consistency

The adapter contract uses application domain types and atomic use-case methods,
not a generic query API. Atomic methods cover:

- user + credential + initial session creation;
- session rotation;
- one-time token consumption plus password/email update;
- OAuth account linking plus session creation;
- impersonation session plus audit event.

This keeps consistency guarantees explicit and implementable across MongoDB and
future SQL adapters. MongoDB deployments use transactions for multi-document
operations and require a replica set or sharded cluster when those methods are
used.

Adapters must enforce unique indexes for normalized email, session hash,
provider/account identity, and one-time token hash. TTL indexes are cleanup
mechanisms only; application code always checks expiry.

### Events and auditing

Domain events use stable event IDs and include a schema version. `user.created`
is persisted to an outbox by the adapter in the same transaction as the user.
Applications can consume it idempotently to provision a personal team.

Security audit events are append-only records with actor, subject, action,
request metadata, timestamp, and structured details. Impersonation audit writes
are mandatory and fail closed.

### Error model

Public errors contain:

- stable machine code;
- safe human message;
- HTTP status;
- optional retry-after duration;
- correlation/request ID when supplied.

Internal causes are never serialized. Provider and adapter failures are wrapped
for logging while clients receive a stable `internal_error`.

## Consequences

The library remains framework- and adapter-independent, deterministic under
test, and directly mountable in existing Go servers. The application-facing
adapter contract is larger than a CRUD repository, but it makes security-critical
atomicity reviewable and portable.

MongoDB transactions add an operational requirement. This is accepted because
silently weakening atomicity for account linking, token consumption, or
impersonation would violate the security contract.

Cross-site cookie authentication is intentionally not supported in v1. Apps that
need it should use a same-site deployment or a future explicit token-based mode.

## Rejected alternatives

- HTTP client SDK: does not own authentication state or satisfy the server
  requirement.
- Node/Bun sidecar: adds a separate runtime and makes Go applications depend on
  an external auth server.
- Signed but plaintext session cookies: revocation and rotation are harder to
  enforce; opaque server-side sessions are the v1 contract.
- Generic CRUD adapter: cannot express the atomic security invariants.
- Permanent byte-for-byte Better Auth schema compatibility: would constrain the
  native model; compatibility belongs in optional migration bridges.
- Email-only OAuth linking without verified-email and conflict checks: enables
  account takeover.

## Security review checklist

- Secrets and raw tokens never appear in logs, events, or persistence.
- All raw token comparisons are performed on fixed-size hashes.
- Every session issuance path rotates or creates a fresh token.
- Every one-time token consume operation is atomic.
- OAuth state is single-use and PKCE is S256.
- Redirect destinations are exact allowlist matches.
- Cookie settings are host-only, secure, HttpOnly, and not SameSite=None.
- State-changing cookie routes enforce trusted origin and CSRF.
- Impersonation is authorization-gated, capped at one hour, and durably audited.
- Configuration validation fails closed.

