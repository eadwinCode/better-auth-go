# Changelog

All notable changes are documented here. Releases follow Semantic Versioning.

## [Unreleased]

### Added

- `CreatePlaceholderEmail` and `PlaceholderEmailOptions` for stable,
  namespaced, non-routable addresses under the reserved
  `placeholder.invalid` domain.
- Adapter-conformance coverage for committed and nested transaction-scoped
  work, plus black-box evidence that user deletion removes all primary-storage
  sessions.
- ADR 0020 and feature-gap acceptance criteria for Better Auth v1.6.26 changes
  whose secondary-storage, email-OTP, JWT, Redis, database-rate-limit storage,
  and OAuth-proxy components are not yet implemented.

### Changed

- The checked-in TypeScript oracle, upstream source inventory, compatibility
  tests, and CI labels now pin Better Auth v1.6.26.

## [1.0.1] - 2026-07-29

### Added

- `ErrNoSession`, `SessionResult`, and
  `Server.ResolveSession(context.Context, *http.Request)` for concurrency-safe,
  in-process resolution of the configured session cookie without HTTP or JSON
  loopback.
- Public resolver coverage for absent and invalid cookies, expired and revoked
  sessions, disabled users, configured cookie names, impersonation metadata,
  concurrent access, and adapter-failure distinction.

### Changed

- Internal session resolution now preserves adapter and database failures for
  in-process callers while the existing HTTP endpoints continue returning
  Better Auth-compatible generic `401` or `200 null` responses without
  serializing causes.

## [1.0.0] - 2026-07-29

### Added

- Server plugin kernel with initialization, dependencies, dynamic endpoints,
  middleware, hooks, trusted origins, rate-limit rules, schema and database
  hooks, background tasks, and session/ownership helpers.
- Initial embeddable `net/http` authentication server.
- Better Auth v1.6-aligned routes, schema, generic adapter vocabulary, and social
  provider IDs.
- Native Argon2id, opaque hash-at-rest sessions, CSRF/origin defenses, recovery,
  verification, OAuth/OIDC, admin impersonation, audit, and outbox contracts.
- MongoDB and in-memory adapters plus a public adapter conformance suite.
- Core user/account/session management, including verified email change,
  password rotation, opt-in deletion, OAuth linking and token refresh.
- Plugin endpoint body/query validators with a strict declarative validator.
- Shared `database/sql`, PostgreSQL, and SQLite adapters with explicit additive
  schema migrations.
- Passkey/WebAuthn plugin with Better Auth-shaped endpoints, exact RP/origin
  policy, hash-at-rest single-use challenges, W3C fixture coverage, guarded
  counters, and core session rotation.
- Two-factor authentication plugin with Better Auth-shaped TOTP, delivered OTP,
  backup-code, trusted-device, and sign-in interception flows; encrypted secret
  material; hash-at-rest challenges; atomic attempts; and account lockout.
- Merged-schema index declarations for SQL and MongoDB plugin models.
- Enterprise SSO security contract and construction foundation with an
  adapter-independent provider schema, encrypted configuration boundary,
  fail-closed provider/domain/redirect policy, organization authorization
  ports, and hardened OIDC discovery.
- Enterprise SSO runtime with encrypted provider management, OIDC PKCE/state/
  nonce/JWKS ceremonies, verified-domain identity completion, DNS verification,
  signed SAML metadata/ACS correlation and replay protection, provisioning
  hooks, and bounded single logout.
- SCIM 2.0 security and construction foundation with a hash-only provider
  schema, bounded bearer/filter parsing, organization authorization ports,
  standard metadata endpoints, and unsafe-method plugin routing.
- Complete SCIM 2.0 connection and User provisioning runtime with one-time
  hash-only bearer issuance and rotation, ownership and tenant isolation,
  bounded list/filter/PUT/PATCH operations, session-revoking deactivation,
  tenant-safe deprovisioning, durable audits, and black-box security fixtures.
- Better Auth v1.6 email/password options for disabled signup, automatic
  sign-in, required email verification, and password-reset session revocation.
- Enumeration-safe synthetic duplicate-signup responses when verification is
  required or automatic sign-in is disabled.
- A checked-in Better Auth 1.6.25 Bun oracle with authenticated test-only mail
  capture and pull-request CI differential coverage.
- Canonical `POST /request-password-reset` and
  `GET /reset-password/{token}` callback routes with redirect allowlist
  enforcement; the previous `/forget-password` path remains an alias.
- A bounded request-scoped `TrustedOriginResolver`, compiled HTTPS hostname
  wildcard policies, malicious-suffix/public-suffix defenses, and concurrent
  tenant-isolation coverage.
- Request-pipeline certification for validator, hook, response-bound and
  rate-limiter failure handling, plus session/provider-token rotation and
  concurrency evidence.
- A reusable clean-checkout release-candidate workflow covering Go quality,
  race, vulnerability, fuzz, Better Auth 1.6.25 differential, real database
  migration, external-module installation, and artifact-contract gates.
- Semantic-tag release archives, checksums, an SPDX SBOM, and Sigstore-backed
  GitHub provenance attestations.
- Production operations and versioning guides covering the v1 boundary,
  deployment, backup/restore, proxy/cookie policy, key rotation, upgrades,
  rollback, and release verification.

### Changed

- SSO, SCIM, and the other feature-plugin packages are explicitly experimental
  and outside the first v1 compatibility guarantee pending their own promotion
  evidence.

- Core user/session HTTP JSON now uses Better Auth v1.6 camelCase fields and a
  nullable `image` value.
- Public HTTP errors now use top-level Better Auth-shaped `code`, `message`,
  and optional `requestId` fields while preserving stable Go error constants.
- `POST /update-user` now returns Better Auth's `{"status":true}` response;
  updated state remains available through `GET /get-session`.
- Password bounds now default to Better Auth v1.6's 8-byte minimum and 128-byte
  maximum, with route-specific public validation codes.
- Password reset no longer signs in the reset browser and revokes existing
  sessions only when configured. Reset and verification tokens default to a
  one-hour lifetime.
- Missing-user credential sign-in performs password-hash work before returning
  the generic authentication error.
- Recovery messages, verification responses, authenticated verification
  errors, session-revocation responses, and update-session responses now match
  the pinned v1.6.25 wire shapes.
- Session listing now requires a fresh session, and reports the upstream
  `SESSION_NOT_FRESH` error when freshness has expired.

[Unreleased]: https://github.com/eadwinCode/better-auth-go/compare/v1.0.1...HEAD
[1.0.1]: https://github.com/eadwinCode/better-auth-go/releases/tag/v1.0.1
[1.0.0]: https://github.com/eadwinCode/better-auth-go/releases/tag/v1.0.0
