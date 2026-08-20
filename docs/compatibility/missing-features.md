# Better Auth Feature Gap Register

This is the release-planning register for parity with the TypeScript Better
Auth server. It is intentionally separate from the plugin-kernel implementation
checklist so a kernel primitive is not confused with a shipped feature plugin.

Baseline: Better Auth 1.6.26 documentation and source as reviewed on
2026-08-09. Every item
requires black-box HTTP tests, adapter conformance tests, threat-model review,
and client-contract documentation before its status can become complete.

The focused [Better Auth v1.7.1 security and interoperability overlay](./better-auth-v1.7.1.md)
supersedes this baseline for SAML verification, SCIM Boolean ingress and account
namespacing, transaction requirements, and migration safety. The broader 1.7
plugin redesign remains a separate migration.

## Server plugin contract gaps

| Capability | Current state | Planned work |
| --- | --- | --- |
| endpoint body/query validation | `EndpointValidator`, `EndpointValidatorFunc`, and strict `ObjectValidator` run before middleware/endpoint code | implemented |
| endpoint metadata | validators are implemented, but endpoints do not yet declare OpenAPI metadata | add operation IDs, tags, response schemas, and documentation generation |
| plugin initialization context extension | initialization can add schema and exact origins | add typed, immutable plugin context values without exposing secrets or mutable global state |
| wildcard trusted origins | compiled HTTPS hostname patterns with IDNA, public-suffix, scheme, port and malicious-suffix tests | implemented; custom application schemes remain a documented deliberate difference |
| request-derived trusted origins | bounded request-scoped `TrustedOriginResolver`; additive results pass the same compiler and fail closed | implemented |
| direct in-process endpoint invocation | HTTP handler only | decide whether a typed Go service API is useful; hooks must have identical semantics if added |
| plugin error-code registry | structured errors exist, but plugins have no construction-time registry | add namespaced collision validation and documentation generation |
| generated client actions and reactive atoms | not a server-library concern | implement in `better-auth-sdk-go` where a Go equivalent is useful |
| endpoint OpenAPI generation | not implemented | build on endpoint validation/metadata after that contract stabilizes |
| instrumentation spans for plugin lifecycle | not implemented | add an OpenTelemetry-neutral observer port for endpoints, middleware, hooks, and database operations |

Exact HTTPS origins remain the preferred production default. Bounded wildcard
patterns and request-derived origins are available when multi-tenant
deployments require them; both use the same fail-closed compiler and expand the
CSRF trust boundary, so applications should keep their policies as narrow as
possible.

## Built-in plugin implementation backlog

The kernel in this PR makes these possible; it does not implement them. Each
plugin should be its own package or a small cohesive PR series.

### Authentication

- two-factor authentication — implemented in the dedicated ADR 0005 PR;
- passkeys/WebAuthn — implemented in the dedicated ADR 0004 PR;
- magic link;
- email OTP — missing; v1.6.26 acceptance requires (1) checking account
  existence only after OTP verification so invalid OTP responses cannot
  enumerate users, (2) passing `email-verification` to custom generators from
  sign-up hooks, and (3) validating a reset password before consuming the OTP
  so corrected-password retries remain possible;
- phone number;
- anonymous users;
- username;
- Google One Tap;
- Sign In with Ethereum;
- multi-session;
- last-login-method tracking.

Generic OAuth consumer support is already part of the core social-provider
layer rather than a plugin.

### Authorization and identity management

- full admin user-management parity beyond the certified bounded impersonation
  flow (administrator role/ID selection, admin-target policy, duration,
  rotation and audit are complete; user CRUD, bans and session administration
  remain);
- organizations, members, invitations, teams, roles, and permissions —
  implemented in the dedicated ADR 0006 runtime PR;
- SSO with OIDC and SAML — experimental runtime implemented; pinned/live
  enterprise certification is required before v1-stable promotion;
- SCIM provisioning — connection management and User CRUD/list/filter/PUT/PATCH
  experimental runtime implemented; TypeScript/live-directory certification is
  required before v1-stable promotion. Better Auth 1.7 managed connections,
  server-only credential lifecycle APIs, and terminal dynamic binding are
  deferred until the 1.7 SCIM connection/credential architecture lands.

### API and tokens

- agent authentication;
- API keys;
- JWT issuance and verification — missing; v1.6.26 JWK reads and writes must
  use the adapter scoped to the surrounding transaction, avoiding SQLite
  deadlocks and making PostgreSQL/MySQL key creation commit or roll back with
  that transaction;
- bearer authentication;
- one-time tokens;
- OAuth proxy — missing; v1.6.26 proxy callbacks must preserve and safely parse
  Apple's `form_post` `user` payload before provider profile mapping.

### Storage compatibility

- Secondary session storage is not implemented. If added, deleting a user must
  delete every indexed session value and the user's active-session index in
  addition to any configured database copies. Batch session lookup must skip
  missing, malformed JSON, and structurally invalid entries without discarding
  valid sessions from the same request.
- Database-backed rate-limit storage is not implemented; the injected
  `RateLimiter` port remains the supported contract. If database cleanup is
  added, expired-row pruning must be awaited when no background task handler
  exists and remain best-effort when pruning fails.
- Redis secondary storage is not implemented. If added, `listKeys` and `clear`
  must use cursor-based `SCAN`, escape glob metacharacters in the configured
  prefix, deduplicate list results, never issue an empty `DEL`, and document
  page-by-page partial failure and concurrent-keyspace semantics.

### OAuth and OIDC servers

- OAuth 2.1 authorization server;
- OpenID Connect provider;
- MCP provider authentication;
- device authorization grant.

When the OAuth authorization/resource server is implemented, its protected
resource errors must include RFC 6750 `403 insufficient_scope` challenges with
every missing scope, as required by the v1.7.1 overlay.

### Security and utilities

- CAPTCHA provider integration;
- Have I Been Pwned password checks;
- internationalized public errors;
- OpenAPI reference generation;
- reusable integration/E2E test utilities.

### External integration plugins

Payment, billing, analytics, and other vendor integrations should live outside
the security core. The upstream catalog currently includes Stripe, Polar,
Autumn Billing, Creem, Dodo Payments, Commet, and Dub. They still need
compatibility entries, but are lower priority than authentication,
authorization, and token features.

## Proposed delivery order

1. passkeys/WebAuthn and two-factor authentication — implemented;
2. organizations — implemented; expanded admin and authorization policies;
3. enterprise SSO and SCIM interoperability certification;
4. endpoint metadata/error registries and instrumentation;
5. magic link, email OTP, username, anonymous, and bearer;
6. API key, JWT, one-time-token, and multi-session;
7. OAuth/OIDC provider, MCP, device authorization, utilities, and external
   integrations.

Order may change when a consuming application needs a feature sooner, but no
feature skips its security contract or adapter-independent tests.
