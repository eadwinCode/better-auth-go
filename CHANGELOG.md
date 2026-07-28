# Changelog

All notable changes are documented here. Releases follow Semantic Versioning.

## [Unreleased]

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
- SCIM 2.0 security and construction foundation with a hash-only provider
  schema, bounded bearer/filter parsing, organization authorization ports,
  standard metadata endpoints, and unsafe-method plugin routing.
- Better Auth v1.6 email/password options for disabled signup, automatic
  sign-in, required email verification, and password-reset session revocation.
- Enumeration-safe synthetic duplicate-signup responses when verification is
  required or automatic sign-in is disabled.
- A checked-in Better Auth 1.6.25 Bun oracle with authenticated test-only mail
  capture and pull-request CI differential coverage.
- Canonical `POST /request-password-reset` and
  `GET /reset-password/{token}` callback routes with redirect allowlist
  enforcement; the previous `/forget-password` path remains an alias.

### Changed

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

[Unreleased]: https://github.com/eadwinCode/better-auth-go/commits/main
