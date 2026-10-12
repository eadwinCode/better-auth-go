# Changelog

All notable changes are documented here. Releases follow Semantic Versioning.

## [Unreleased]

Proposed release: `1.1.0`. It adds features and ports Better Auth v1.7.2 to
v1.7.7 (see `docs/compatibility/better-auth-v1.7.7.md`). Some behavior changes
are listed under **Changed**; read them before upgrading.

### Added

- Experimental `plugin/onetimetoken`, a port of Better Auth's
  `one-time-token` plugin: `GET /one-time-token/generate`,
  `POST /one-time-token/verify`, every upstream option, the `set-ott` header,
  and `Manager.Generate` for server-side token creation.
- `HookContext.ResumeSession` and `ErrSessionExpired`, so a plugin can return
  or attach an existing session without creating a new one or storing its raw
  token.
- TypeScript oracle instances and the
  `TestBetterAuthV177OneTimeTokenCompatibility` differential suite.
- ADR 0021 and the one-time-token guide, including a cross-subdomain sign-in
  example.

- Cloudflare social provider (36 built-in providers).
- `TokenAuthCustom` and `social.Options.CustomizeTokenRequest` for providers
  that need non-standard token request authentication.
- `postgresql.NewWithOptions(db, postgresql.Options{SchemaName: ...})` to keep
  Better Auth tables in their own PostgreSQL schema. `Migrate` creates the
  schema first.
- A live database schema check: `Server.CheckSchema`, the `SchemaChecker`
  adapter interface (SQLite and PostgreSQL), `DiffSchema`,
  `SchemaMismatchError` and `Config.DisableSchemaValidation`.
- `FindAccountByKey` and `ErrAmbiguousAccount`.
- `InferNullOrigin`, `HookContext.MaxPasswordBytes` and
  `HookContext.CheckPasswordNotTooLong` for plugins.
- Conformance suites `adaptertest.RunAccountIdentity`,
  `adaptertest.RunMappedIdentity` and `adaptertest.RunSchemaCheck`.
- The TypeScript oracle now runs Better Auth 1.7.7, with
  `scripts/check-upstream-v1.7.7.sh` and an audit of every v1.7.2 to v1.7.7
  change.

### Changed

- Requests on SQLite and PostgreSQL now fail with `500 SCHEMA_MISMATCH` until
  the database has every table and column Better Auth needs and no required
  column it never writes. Run `Migrate` (no restart needed) or set
  `Config.DisableSchemaValidation`.
- An over-long password now returns `400 PASSWORD_TOO_LONG` before any lookup
  or hash on sign-in, change-password, delete-user and the two-factor password
  checks. Sign-in and change-password used to return `401`, and delete-user
  `INVALID_PASSWORD`. `Server.VerifyPassword` now returns this error instead of
  `false, nil`.
- Change-password applies its rate limit before it checks passwords.
- Basic-auth token requests send the client only in the `Authorization`
  header, form-URL-encoded as RFC 6749 requires. Figma and Railway now use
  Basic auth; Spotify and Zoom send the secret in the body; Notion refreshes
  with the secret in the body. PayPal and Zoom use PKCE, TikTok sends the code
  verifier, and Reddit sends its own `Accept` and `User-Agent` headers.
- Providers that return no email use `{id}@{provider}.placeholder.invalid`.
  Roblox, TikTok and Twitter used the username as the email, so those sign-ins
  always failed. Stored Reddit and WeChat addresses change from
  `@reddit.invalid` and `@wechat.invalid`. Placeholder addresses are never
  marked verified, even for `TrustedProviders`.
- PostgreSQL `Migrate` only looks at tables in the target schema and stops
  with a clear error when a view or other relation has a Better Auth table name.
- The memory adapter builds unique rules from the stored schema and no longer
  treats empty values as duplicates. The MongoDB adapter rejects
  `Collections` combined with schema model renames.
- An `Origin: null` request with exactly `Sec-Fetch-Site: same-origin` is
  checked using the request's own origin, as in Better Auth 1.7.2.
- SSO return paths accept any safe relative URL (query, fragment, `~`) and now
  resolve against the site origin instead of the auth base path.

### Removed

These APIs came with the Better Auth 1.7.0 account change on `main` and were
never released:

- the `account.issuer` column and its unique index, `OAuthAccountIssuer`,
  `CredentialAccountIssuer`, `social.Options.AccountIssuer` and
  `OAuthAccount.Issuer`;
- `migration/v17` `StagingSchema`, `Backfill`, `FinalizeSQL` and
  `ProviderIssuers`. `migration/v17.RewriteAccountIDs` remains for account ID
  rewrites such as Microsoft `sub` to `oid`.

Accounts are keyed by `(providerId, accountId)` again, as in Better Auth 1.7.3
and better-auth-go v1.0.x. Databases from v1.0.x need no change. Databases
built from unreleased `main` should follow `migration/v17/README.md`.

### Security

- Enabling TOTP again after it is verified fails with `TOTP_ALREADY_ENABLED`
  and keeps the old authenticator and backup codes (Better Auth #11037).
- A provider key that matches more than one account fails sign-in and linking
  instead of picking one.
- One-time tokens are single-use (atomic consume) and expire after 3 minutes
  by default. The raw session token is never stored; it is sealed under a key
  derived from the one-time token. Verify never attaches a cookie for a
  revoked or expired session or a disabled user.

## [1.0.2] - 2026-08-09

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

[Unreleased]: https://github.com/eadwinCode/better-auth-go/compare/v1.0.2...HEAD
[1.0.2]: https://github.com/eadwinCode/better-auth-go/releases/tag/v1.0.2
[1.0.1]: https://github.com/eadwinCode/better-auth-go/releases/tag/v1.0.1
[1.0.0]: https://github.com/eadwinCode/better-auth-go/releases/tag/v1.0.0
