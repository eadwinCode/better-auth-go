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
- Merged-schema index declarations for SQL and MongoDB plugin models.

[Unreleased]: https://github.com/eadwinCode/better-auth-go/commits/main
