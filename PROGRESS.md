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
| TypeScript oracle type check | `bun run typecheck` in `better-auth-ts` | Pass |
| TypeScript oracle migration | `bun --env-file=.env.example run migrate` | Pass |
| Go/TypeScript core characterization | `scripts/test-typescript-compat.sh` | Pass; 13 lifecycle/security subtests |
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
- TypeScript HTTP oracle: sibling checkout `../better-auth-ts`; override with
  `BETTER_AUTH_TS_DIR` for another local layout
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
| Email/password sign-up and sign-in | Present | Lifecycle characterization added | Partial |
| Sign-out and session retrieval | Present | Lifecycle characterization added | Partial |
| Session refresh and revocation | Present | Go black-box tests only | Partial |
| User update, email change, deletion | Present | User update differential passes; remaining routes use Go tests | Partial |
| Password change and recovery | Present | Go black-box tests only | Partial |
| Email verification | Present | Go black-box tests only | Partial |
| Account list/link/unlink | Present | Go black-box tests only | Partial |
| Provider access/refresh tokens | Present | Go black-box tests only | Partial |
| Admin impersonation | Bounded implementation present | Go audit tests only | Partial |
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
| 35 provider presets | Partial | Provider-specific request/profile fixtures and catalog documentation correction |
| Authorization code, state and PKCE | Partial | Differential callback/error/replay matrix |
| OIDC nonce and ID-token verification | Partial | Issuer, audience, JWKS rotation, clock and algorithm fixtures |
| Verified-email linking | Partial | Cross-runtime linking and collision matrix |
| Refresh and revocation | Partial | Provider-specific fixtures |
| Generic OAuth/OIDC consumer API | Partial | Discovery, mapping, token-auth, redirect and SSRF certification |
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
| SQLite | Pass | Real SQLite | Present | Partial pending upgrade/rollback matrix |
| MongoDB | Pass | Pass on MongoDB 8 replica set | Transaction rollback and index tests pass | Partial pending upgrade matrix |
| PostgreSQL | Pass | Pass on PostgreSQL 17 | Atomicity, rollback and additive mapped migration pass | Partial pending release-to-release upgrade matrix |

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
| Public error JSON | top-level `code` and `message` with upstream codes | Top-level shape and authentication/origin codes match | Partial; remaining route-specific codes need certification |
| Duplicate sign-up | 422 by default; synthetic success with verification or no auto-sign-in | Generic 409 | Open; implement with the full email/password option contract |
| Successful `update-user` response | `{"status":true}` | Same | Resolved by ADR 0009 and differential tests |
| Session/account management responses | Upstream names and session tokens | stable IDs and token redaction | Deliberate security difference; remaining shapes need review |
| CSRF model | trusted-origin/cookie behavior from upstream | trusted origin plus explicit double-submit token for authenticated mutations | Deliberate security difference |

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
4. All 35 social-provider fixtures and generic OAuth/OIDC fixtures.
5. Selected live provider sandbox tests.
6. Passkey tests in supported browsers.
7. SSO OIDC/SAML protocol fixtures and SCIM RFC 7644 fixtures.
8. Dependency vulnerability scan and review of any accepted finding.
9. Install-from-tag test in a separate example module.
10. Upgrade test from the previous release database schema.

## Recommended work order

1. Implement the pinned email/password option contract, especially
   `autoSignIn`, `requireEmailVerification`, enumeration-safe duplicate
   sign-up, password bounds and reset-session revocation.
2. Expand the TypeScript oracle and differential harness across the remaining
   core routes and resolve or document every observed difference.
3. Extend MongoDB, PostgreSQL and SQLite coverage with release-to-release
   migration fixtures, and make the TypeScript oracle reproducible in CI.
4. Certify all 35 social-provider presets and generic OAuth/OIDC.
5. Complete SSO and SCIM.
6. Implement and certify the remaining exports from the pinned 1.6.25 plugin
   inventory in small, security-reviewed pull requests.
7. Run `v1.0.0-rc.1`; publish `v1.0.0` only after every release gate above is
   green or explicitly marked as an approved deliberate difference.

## Maintenance rule

Each pull request affecting compatibility must update:

1. the relevant capability row;
2. its test evidence;
3. any newly observed HTTP difference; and
4. the remaining recommendation order.

“Implemented” without reproducible evidence remains **Partial**.
