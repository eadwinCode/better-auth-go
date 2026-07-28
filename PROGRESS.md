# Better Auth v1.6.25 Production Progress

This file is the release tracker for `better-auth-go`. The compatibility target
is pinned to **Better Auth TypeScript 1.6.25**. A capability is not production
complete merely because it compiles or has an implementation: it must satisfy
the HTTP contract, adapter contract, security checks, and test evidence listed
here.

The scope is limited to behavior shipped by the pinned Better Auth release.
Features introduced after 1.6.25 and Go-only product features are not part of
this release.

## Status vocabulary

| Status | Meaning |
| --- | --- |
| Complete | Implemented and covered by the required release evidence. |
| Partial | Some implementation or tests exist, but a release gate is open. |
| Missing | Required v1.6.25 behavior has no implementation. |
| Deliberate difference | Intentional Go security behavior documented and tested separately. |
| Not applicable | JavaScript/runtime-specific behavior with no server-side Go equivalent. |

## Current release decision

**Not production-stable as a complete Better Auth 1.6.25 replacement.**

The current core is suitable for controlled evaluation, and the repository's
ordinary test suite is green. Production parity remains blocked by the
complete cross-runtime HTTP matrix, provider certification, release-to-release
database upgrade tests, incomplete SSO and SCIM ceremonies, and the remaining
1.6.25 plugin backlog.

## Evidence snapshot

Last updated: 2026-07-28

| Gate | Command or evidence | Result |
| --- | --- | --- |
| Go unit and black-box tests | `go test -count=1 ./...` | Pass |
| TypeScript oracle type check | `bun run typecheck` in `compat/typescript-oracle` | Pass |
| TypeScript oracle migration | `scripts/test-typescript-compat.sh` isolated SQLite setup | Pass |
| Go/TypeScript core characterization | `scripts/test-typescript-compat.sh` | Pass; lifecycle, recovery, verification, reset-callback, multi-session, email change, direct/emailed deletion, account linking/unlinking, provider-token and impersonation suites |
| Pinned upstream source inventory | `scripts/check-upstream-v1.6.25.sh` | Pass at tag commit `07a646e` |
| Formatting | `test -z "$(gofmt -l .)"` | Pass |
| Vet | `go vet ./...` | Pass |
| Race detector | `go test -race -count=1 ./...` | Pass |
| Staticcheck | `go run honnef.co/go/tools/cmd/staticcheck@v0.6.1 ./...` | Pass |
| Vulnerability scan | `govulncheck ./...` | Pass; no called vulnerabilities |
| Fuzz smoke matrix | Nine 10-second targets from `.github/workflows/ci.yml` | Pass |
| SQLite adapter conformance | `go test -count=1 ./adapter/sqlite` | Pass as part of full suite |
| MongoDB adapter conformance | `MONGODB_URI=... go test -count=1 ./adapter/mongodb` | Pass on MongoDB 8 single-node replica set |
| PostgreSQL adapter conformance | `POSTGRES_DSN=... go test -count=1 ./adapter/postgresql` | Pass on PostgreSQL 17 |
| Release workflow | `.github/workflows/release.yml` | Partial; does not run all certification gates |

Update this table with the date and exact command whenever evidence is rerun.
Do not convert a pending or skipped integration test into a pass.

## Compatibility baseline

- Better Auth package: `better-auth@1.6.25`
- Better Auth source: tag `v1.6.25`, commit
  `07a646ea190167370fbbb60a0fa2c3be3bec5522`; sibling checkout
  `../better-auth-repo`, overridable with `BETTER_AUTH_UPSTREAM_DIR`
- TypeScript HTTP oracle: checked in at `compat/typescript-oracle`; override
  with `BETTER_AUTH_TS_DIR` only when testing another compatible fixture
- Go module: `github.com/eadwinCode/better-auth-go`
- Default route prefix: `/api/auth`
- Provider catalog: **35** built-in provider IDs plus the generic OAuth/OIDC
  consumer API

The oracle must be treated as a black box. Tests compare public HTTP status,
JSON, headers, cookies, redirects, and resulting authentication state. Random
IDs, tokens, password hashes, and timestamps may be normalized, but observable
contract differences must be listed below.

## Capability matrix

### Core server

| Capability | Implementation | Cross-runtime HTTP evidence | Status |
| --- | --- | --- | --- |
| Email/password sign-up and sign-in | Present, including v1.6 lifecycle options and callbacks | Default lifecycle, bounds and duplicate errors differential; send-on-signup/signin, existing-user callback and option/security matrix in Go | Certified for the pinned core option contract |
| Sign-out and session retrieval | Present | Lifecycle characterization added | Partial |
| Session refresh and revocation | Present | Session list/update and single/other/all revocation differential; refresh is Go-only rotation | Partial |
| User update, email change, deletion | Present | User update, both change-email modes, enumeration resistance, direct password deletion, emailed deletion callback, replay/ownership and resulting state tests pass | Certified for the pinned core option contract |
| Password change and recovery | Present | Change-password plus request/reset/callback/invalid/replay differential; callback ordering, concurrency and revocation Go tests | Certified for the pinned core option contract |
| Email verification | Present | Send/verify/resend/state differential plus send modes, before/after callbacks and auto-sign-in lifecycle tests | Certified for the pinned core option contract |
| Account list/link/unlink | Present | Public link flow, listing, unlink success/missing/final-account errors differential pass | Partial pending remaining linking options/collisions |
| Provider access/refresh tokens | Present | Safe read/refresh fields, local provider refresh, persistence and refresh-token redaction differential pass | Partial pending provider-specific fixtures |
| Admin impersonation | Bounded implementation present | Authorization, one-hour session, active identity and stop/restore differential; durable Go audit tests pass | Partial pending remaining admin-plugin options |
| Request validators and size limits | Present | Go failure tests | Partial |
| Trusted origins and CSRF | Present | Cross-runtime origin characterization added | Partial |
| `onRequest`, `onResponse`, route and database hooks | Present | Go ordering/rollback/race tests | Partial |
| Rate-limiter hook | Present | Go plugin test | Partial |
| Versioned public API and release metadata | Pre-1.0 development version | No release candidate | Partial |

Core completion requires a differential matrix for every pinned route and
enabled option, including success, validation, authorization, replay, and
failure behavior.

### Social OAuth and generic OAuth/OIDC

| Capability | Status | Remaining evidence |
| --- | --- | --- |
| 35 provider presets | Certified deterministic matrix | Live credential runs remain release-operator evidence |
| Authorization code, state and PKCE | Partial | Differential callback/error/replay matrix |
| OIDC nonce and ID-token verification | Certified | Issuer, audience, nonce, expiry, RS256, deterministic clock and JWKS rotation fixtures pass |
| Verified-email linking | Partial | Cross-runtime linking and collision matrix |
| Refresh and revocation | Partial | Generic refresh is certified; provider-specific revocation remains provider-dependent |
| Generic OAuth/OIDC consumer API | Certified | Discovery, custom mapping, all client-auth modes, refresh, redirect, response-bound, error-redaction and SSRF fixtures pass |
| Live provider interoperability | Missing release evidence | Selected sandbox-provider runs with secrets supplied by CI or release operator |

Live provider tests are release certification, not ordinary pull-request tests.
They must never log provider credentials or returned tokens.

### High-risk plugins already started

| Plugin | Implementation | Status |
| --- | --- | --- |
| Passkey/WebAuthn | Full Go ceremony and adapter tests present | Partial pending TypeScript/browser differential certification |
| Two-factor authentication | TOTP, delivered OTP, backup codes and trusted devices present | Partial pending TypeScript differential certification |
| Organizations | Runtime, membership, invitations, teams, roles and tests present | Partial pending TypeScript differential certification |
| SSO | Schema, configuration and hardened OIDC discovery foundation only | Partial; OIDC/SAML HTTP ceremonies are release blockers |
| SCIM | Schema, token, filter and metadata foundation only | Partial; RFC 7644 connection and provisioning routes are release blockers |

### Exact pinned v1.6.25 plugin inventory

The local upstream tag exports these 27 plugins from
`better-auth/plugins`:

- access, admin, anonymous, bearer, captcha and custom session;
- device authorization, email OTP, generic OAuth and Have I Been Pwned;
- JWT, last-login-method, magic link, MCP and multi-session;
- OAuth popup, OAuth proxy and OIDC provider;
- One Tap, one-time token, OpenAPI and organizations;
- phone number, SIWE, test utilities, two-factor and username.

The pinned monorepo also publishes seven server-plugin packages:

- `@better-auth/api-key`;
- `@better-auth/i18n`;
- `@better-auth/oauth-provider`;
- `@better-auth/passkey`;
- `@better-auth/scim`;
- `@better-auth/sso`;
- `@better-auth/stripe`.

Passkey, two-factor and organizations have Go implementations; SSO and SCIM
have foundations. Everything else above remains missing or partial unless its
capability matrix says otherwise. TypeScript adapters, Expo/Electron clients,
telemetry internals and Redis secondary storage are not feature-plugin parity
items; their server-side concepts are handled through the Go adapter, hook and
storage contracts where applicable.

This inventory is enforced by `scripts/check-upstream-v1.6.25.sh`. Agent Auth
and later payment/analytics integrations are not exported by the pinned tag and
must not enter the v1.6.25 release scope.

### Database adapters

| Adapter | Unit/conformance | Real database | Migration/concurrency | Status |
| --- | --- | --- | --- | --- |
| Memory | Pass | In-process | Pass | Complete for testing only |
| SQLite | Pass | Real SQLite | Frozen `ecf48ac` upgrade, idempotency, preservation, indexes and rollback pass | Certified |
| MongoDB | Pass | Pass on MongoDB 8 replica set | Frozen `ecf48ac` upgrade, idempotent indexes, preservation and rollback pass | Certified |
| PostgreSQL | Pass | Pass on PostgreSQL 17 | Frozen `ecf48ac` upgrade, idempotency, preservation, indexes and rollback pass | Certified |

Adapter independence is a public contract. New database adapters must pass the
shared `adaptertest` suite and may not require changes to authentication or
plugin code.

## Documented HTTP differences

These differences are visible in the initial TypeScript-oracle
characterization and must be either accepted in the compatibility contract or
closed before the stable release:

| Surface | Better Auth 1.6.25 | Current Go behavior | Decision |
| --- | --- | --- | --- |
| Successful password response token | Returns a bearer token | Returns `null`; only opaque cookie is issued | Deliberate security difference |
| Session cookie | Signed Better Auth cookie name/format | `__Host-` opaque token, hash-at-rest | Deliberate security difference |
| User/session JSON field names | camelCase with nullable `image` | Same | Resolved by ADR 0009 and differential tests |
| Public error JSON | top-level `code` and `message` with upstream codes | Authentication, origin, password bounds and duplicate-signup codes match | Partial; remaining route-specific codes need certification |
| Duplicate sign-up | 422 by default; synthetic success with verification or no auto-sign-in | Same | Resolved by ADR 0010; default behavior differential, protected modes security-tested |
| Successful `update-user` response | `{"status":true}` | Same | Resolved by ADR 0009 and differential tests |
| Session/account management responses | Upstream names and session tokens | stable IDs and token redaction | Deliberate security difference; remaining shapes need review |
| Verification token replay | A valid signed token returns success after the account is verified | hashed token is consumed once; replay returns `INVALID_TOKEN` | Deliberate security difference |
| CSRF model | trusted-origin/cookie behavior from upstream | trusted origin plus explicit double-submit token for authenticated mutations | Deliberate security difference |
| Same-email change error | Returns only `message` for this `BAD_REQUEST` | Always returns structured `code` and `message` | Deliberate structured-error guarantee |
| Provider refresh response | Returns the provider refresh token | Omits refresh tokens while returning safe access/ID-token metadata | Deliberate credential-redaction guarantee |
| Impersonation session preservation | Stores and restores the original signed admin session cookie | Revokes/rotates on entry and creates a new actor session on exit, with durable audit events | Deliberate fixation-protection and audit guarantee |

No additional difference may be normalized away by the test harness without an
entry in this table and a compatibility decision.

## Required test matrix

### Every pull request

1. Formatting, `go test -count=1 ./...`, vet and staticcheck.
2. Race detector for all packages.
3. Fuzz smoke for every committed fuzz target.
4. TypeScript-oracle core characterization.
5. SQLite conformance and migrations.
6. Security failure tests for every changed endpoint or plugin.

### Release candidate

1. All pull-request gates from a clean checkout.
2. Real MongoDB and PostgreSQL conformance, migrations and concurrent mutation
   tests.
3. Complete TypeScript 1.6.25 differential endpoint and option matrix.
4. All 35 social-provider fixtures and generic OAuth/OIDC fixtures (present).
5. Selected live provider sandbox tests.
6. Passkey tests in supported browsers.
7. SSO OIDC/SAML protocol fixtures and SCIM RFC 7644 fixtures.
8. Dependency vulnerability scan and review of any accepted finding.
9. Install-from-tag test in a separate example module.
10. Upgrade test from the previous release database schema.

## Recommended work order

1. Complete SSO and SCIM.
2. Implement and certify the remaining exports from the pinned 1.6.25 plugin
   inventory in small, security-reviewed pull requests.
3. Run `v1.0.0-rc.1`; publish `v1.0.0` only after every release gate above is
   green or explicitly marked as an approved deliberate difference.

## Maintenance rule

Each pull request affecting compatibility must update:

1. the relevant capability row;
2. its test evidence;
3. any newly observed HTTP difference; and
4. the remaining recommendation order.

“Implemented” without reproducible evidence remains **Partial**.
