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

[Unreleased]: https://github.com/eadwinCode/better-auth-go/commits/main
