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

The compatibility reference is Better Auth TypeScript v1.6 and its `main`
contracts as audited on 2026-07-28. The Go library should follow Better Auth's
HTTP names, core schema, provider IDs, adapter vocabulary, hook model, and plugin
extension model where those concepts are runtime-independent. Exact TypeScript
types, JavaScript callback conventions, and insecure legacy behavior are not
compatibility requirements.

The initial release must support:

- email/password sign-up and sign-in;
- sign-out, session retrieval, refresh, rotation, and revocation;
- the complete Better Auth built-in social-provider catalog plus generic
  OAuth2/OIDC, using authorization-code flow and PKCE where supported;
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

The module follows semantic versioning. The root Go package remains
import-compatible within a major module version. HTTP routes follow Better Auth
route names directly under the configured base path rather than inserting a Go
specific `/v1` path segment. `APIVersion` versions response/schema contracts,
not route paths.

Native Go records and Argon2id password hashes are canonical. Better Auth scrypt
compatibility is optional and is provided through a configurable
`PasswordVerifier`/rehash bridge. Successful verification of a legacy hash may
return an Argon2id replacement for atomic persistence.

### HTTP surface

Given the default base path `/api/auth`, the initial compatibility surface
includes:

- `POST /sign-up/email`
- `POST /sign-in/email`
- `POST /sign-in/social`
- `GET|POST /callback/{provider}`
- `POST /sign-out`
- `GET /get-session`
- `POST /refresh-session`
- `POST /revoke-session`
- `POST /revoke-sessions`
- `POST /forget-password`
- `POST /reset-password`
- `POST /send-verification-email`
- `GET /verify-email`
- `POST /admin/impersonate-user`
- `POST /admin/stop-impersonating`

Unknown routes return structured `404` errors. Unsupported methods return
structured `405` errors.

Endpoint request/response shapes are tracked in
`docs/compatibility/better-auth-v1.6.md`. Compatibility aliases may be retained
for an announced deprecation window, but new Go-only endpoint names are not
introduced without an ADR.

### Adapter and schema architecture

The public `DatabaseAdapter` mirrors Better Auth's low-level adapter vocabulary:

- `Create`, `FindOne`, `FindMany`, `Count`;
- `Update`, `UpdateMany`, `Delete`, `DeleteMany`;
- atomic `ConsumeOne`;
- atomic guarded `IncrementOne`;
- `Transaction`.

Operations receive a model name, schema-neutral data, field predicates, optional
projection, sort, pagination, and join descriptions. Predicate operators map to
Better Auth's `eq`, `ne`, `lt`, `lte`, `gt`, `gte`, `in`, `not_in`,
`contains`, `starts_with`, and `ends_with`, with explicit connector and
case-sensitivity semantics.

Adapters declare capabilities including JSON, date, boolean, array, numeric ID,
UUID, join, and transaction support, plus input/output key mappings. A factory
normalizes schema names, field names, values, predicates, IDs, and fallbacks
before core services see the adapter.

The core schema registry contains `user`, `session`, `account`, and
`verification`; plugins may add models and fields. Applications may rename
models and fields. A typed internal store translates domain operations into the
generic adapter contract. Security-sensitive multi-record use cases still
require transactions; adapters that cannot provide the required guarantee fail
configuration for those enabled features rather than silently degrading.

MongoDB implements native `findOneAndDelete` for `ConsumeOne`, native guarded
`findOneAndUpdate` for `IncrementOne`, transactions, and `_id` key mappings.
Future SQL/ORM adapters implement the same conformance suite.

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

The social flow uses a provider registry keyed by Better Auth provider IDs. The
registry exposes all current built-ins:

`apple`, `atlassian`, `cognito`, `discord`, `dropbox`, `facebook`, `figma`,
`github`, `gitlab`, `google`, `huggingface`, `kakao`, `kick`, `line`, `linear`,
`linkedin`, `microsoft`, `naver`, `notion`, `paybin`, `paypal`, `polar`,
`railway`, `reddit`, `roblox`, `salesforce`, `slack`, `spotify`, `tiktok`,
`twitch`, `twitter`, `vercel`, `vk`, `wechat`, and `zoom`.

Generic OAuth2/OIDC configuration supports additional providers. Built-in
presets supply endpoints, default scopes, PKCE behavior, token authentication,
profile mapping, verified-email semantics, and any provider-specific exchange
rules. Providers that require ID-token verification must validate signature,
issuer, audience, expiry, and nonce with a bounded cached JWKS client.

Authorization-code flows use S256 PKCE whenever the provider supports it. State,
nonce, and verifier are cryptographically random, single-use, hash-at-rest, and
short-lived. The callback's destination is selected from an exact configured
allowlist; arbitrary redirect URLs are rejected.

OAuth token, user-info, discovery, and JWKS calls use bounded clients, contexts,
response-size limits, explicit content/status validation, SSRF-safe configured
URLs, and redirect policies. Account identity is anchored by the stable
`(providerID, providerAccountID)` pair. Automatic linking by email requires a
provider assertion that the email is verified plus local linking policy;
providers without a trustworthy verification claim require local verification.
Linking is atomic and rejects conflicting provider identities. Provider errors
are mapped to stable public errors without reflecting provider-controlled
strings.

Provider access and refresh tokens are encrypted at rest through an injected key
ring when persistence is enabled; they are never returned by normal session
responses or logged.

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

The internal store composes generic adapter operations into atomic use cases:

- user + credential + initial session creation;
- session rotation;
- one-time token consumption plus password/email update;
- OAuth account linking plus session creation;
- impersonation session plus audit event.

This keeps public adapter portability and security consistency guarantees.
MongoDB deployments use transactions for multi-document operations and require a
replica set or sharded cluster when those methods are used.

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
- A domain-only adapter with one method per use case: secure but diverges from
  Better Auth's extensible database/plugin model and makes third-party adapters
  unnecessarily large.
- Generic CRUD without atomic consume, guarded increments, or transactions:
  cannot express the security invariants.
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
