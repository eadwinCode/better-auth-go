# ADR 0007: Enterprise SSO

- Status: Accepted
- Date: 2026-07-28
- Better Auth reference: `@better-auth/sso` v1.6.25

## Context

`better-auth-go` needs an embeddable enterprise SSO plugin compatible with the
Better Auth v1.6 route and persistence vocabulary. The plugin must support OIDC,
OAuth 2.0, and SAML 2.0 providers without turning the core server into a
provider-specific service or weakening the library's existing session, origin,
adapter, and hook boundaries.

SSO provider configuration is security-critical. A user who can register or
replace a provider can control the identity assertions accepted for its domain.
OIDC discovery and SAML metadata also cause server-side network requests, while
callback and RelayState values can become open redirects. These operations need
stronger authorization and validation than ordinary social sign-in.

## Decision

### Package and dependency boundary

The feature is an opt-in `plugin/sso` package with plugin ID `sso`. It depends
on the organization plugin descriptor when organization-scoped providers are
enabled, but it does not depend on SCIM. Provider and organization policy are
injected through narrow concurrency-safe ports so applications can add stricter
authorization without replacing the built-in checks.

### Better Auth v1.6 HTTP contract

The plugin owns these routes relative to the configured auth base path:

- `GET /sso/saml2/sp/metadata`
- `POST /sso/register`
- `POST /sign-in/sso`
- `GET /sso/callback/:providerId`
- `GET /sso/callback`
- `GET|POST /sso/saml2/callback/:providerId`
- `GET|POST /sso/saml2/sp/acs/:providerId`
- `GET|POST /sso/saml2/sp/slo/:providerId`
- `POST /sso/saml2/logout/:providerId`
- `GET /sso/providers`
- `GET /sso/get-provider`
- `POST /sso/update-provider`
- `POST /sso/delete-provider`
- optional domain verification request and verification routes.

Mutating management routes require a session, a fresh-session check, trusted
origin enforcement, and CSRF. Organization-scoped management also requires an
owner/admin-equivalent authorization result from the configured organization
authorizer. A caller-provided organization ID never changes the authorization
target after the provider has been loaded.

### Schema

The plugin contributes `ssoProvider` with:

- `id`, `issuer`, `providerId`, `domain`, `userId`, `organizationId`;
- encrypted `oidcConfig` or encrypted `samlConfig`, exactly one of which is set;
- optional `domainVerified`;
- creation and update timestamps;
- unique provider ID and compound domain/organization indexes.

Secrets, private keys, certificates containing private material, and client
secrets are encrypted through an injected `TokenCipher`. Public responses never
return stored configuration secrets.

OIDC/SAML state, AuthnRequest correlation, logout correlation, and assertion
replay records use the core verification model. Values that act as bearers are
random, single-use, expiring, and hash-only at rest.

### Provider registration

Provider IDs are normalized, length-bounded, and rejected when they collide
with credential, built-in social, default SSO, or other account-provider IDs.
Domains are canonical bare DNS names; URL-shaped domains, ports, wildcards,
public suffixes, and ambiguous Unicode are rejected.

Registration is fail-closed:

- personal providers are owned by the creating user;
- organization providers require the configured organization authorizer;
- configurable provider limits are enforced after authorization;
- OIDC discovery or SAML metadata validation completes before persistence;
- replacement/update checks ownership against the stored provider;
- audit events record creation, update, deletion, verification, and sign-in.

### OIDC and OAuth 2.0

OIDC authorization-code flows use PKCE S256, random single-use state, nonce,
bounded scopes, and a five-minute default ceremony lifetime. State records bind
the provider, callback URL, sign-up intent, PKCE verifier hash, and nonce.

Discovery:

- requires HTTPS outside explicit test configuration;
- validates exact issuer equality;
- requires authorization, token, and JWKS endpoints for OIDC;
- accepts only `client_secret_basic` and `client_secret_post`;
- uses a bounded injected HTTP client with redirects disabled;
- validates every discovered URL through an injected outbound URL policy;
- limits response size and JSON depth and rejects unknown/invalid algorithms.

Callbacks consume state before issuing a session, exchange the code once,
validate the ID token signature against a bounded JWKS cache, and enforce
issuer, audience, expiration, issued-at, nonce, and authorized-party rules.
Email-based linking requires a verified email and either a verified provider
domain or explicit application authorization. Successful authentication uses
the core fixation-safe `IssueSession` capability.

### SAML 2.0

SAML support is service-provider initiated by default and uses an audited Go
SAML implementation behind a small verifier interface. Production mode
requires signed assertions, audience and recipient validation, issuer matching,
timestamp validation, and SHA-2-or-better algorithms. Deprecated algorithms are
rejected by default.

AuthnRequest IDs are random, expire after five minutes by default, and are
consumed atomically when validating `InResponseTo`. IdP-initiated SSO is an
explicit option. Assertion IDs are always stored and atomically consumed for
replay protection across instances.

SAML POST bodies and metadata have independent bounded sizes. XML processing
must not resolve external entities or fetch schemas. RelayState and configured
IdP-initiated destinations accept only same-origin relative paths or exact
trusted-origin URLs.

SAML callback endpoints may omit browser origin headers because they are
cross-site IdP posts, but they do not bypass correlation, signature, audience,
recipient, timestamp, issuer, replay, or redirect validation.

### Domain verification and provisioning

Domain verification uses an injected DNS TXT resolver, a random hash-at-rest
challenge, bounded resolver timeouts, and an explicit expiry. Verified domains
may permit verified-email linking only for their exact canonical domain.

User and organization provisioning hooks receive immutable copies of the
resolved user info and provider metadata. Hooks must be idempotent when
configured for every login. Organization assignment cannot grant a role above
the configured authorizer's ceiling and never trusts a request-supplied
organization ID.

### Errors, hooks, and operational behavior

Provider and account enumeration use generic public errors. OAuth/SAML provider
errors are allowlisted and safely encoded before redirects. Detailed causes are
kept for structured logging and audit sinks, not returned to the browser.

All clients, caches, hooks, resolvers, clocks, and token sources are injected or
immutable after construction. No request credentials are stored in shared
mutable state. Rate-limit rules cover registration, sign-in, callbacks, domain
verification, and logout.

## Consequences

- SSO stays adapter-independent and mountable under any auth base path.
- The Go API follows Better Auth's route and model vocabulary while failing
  closed on provider management and protocol validation.
- SAML and OIDC verification remain testable with deterministic clocks,
  generated fixtures, bounded clients, and replaceable protocol ports.
- SCIM is a separate plugin and PR; it may reference SSO provider IDs but is not
  required for SSO operation.

## Verification

The implementation requires:

- black-box registration, discovery, sign-in, callback, CRUD, and logout tests;
- OIDC issuer/audience/nonce/PKCE/JWKS and redirect failure fixtures;
- SAML signature, audience, recipient, correlation, replay, timestamp,
  algorithm, payload-size, and cross-provider failure fixtures;
- organization BOLA and provider-collision regression tests;
- concurrent state/assertion consumption tests;
- fuzz tests for state, RelayState, XML input, and callback parsing;
- `go test`, race detector, vet, staticcheck, vulnerability scanning, and
  adapter schema migration checks.
