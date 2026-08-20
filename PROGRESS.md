# Better Auth v1.7.0 Migration Progress

This file is the release tracker for `better-auth-go`. The active migration target
is pinned to **Better Auth TypeScript 1.7.0**; the previously certified stable
boundary remains the documented v1.6.25 surface until the 1.7 matrix completes. A capability is not production
complete merely because it compiles or has an implementation: it must satisfy
the HTTP contract, adapter contract, security checks, and test evidence listed
here.

The 1.7 implementation status and explicit deferrals are recorded in
`docs/compatibility/better-auth-v1.7.md`.

## Status vocabulary

| Status | Meaning |
| --- | --- |
| Complete | Implemented and covered by the required release evidence. |
| Partial | Some implementation or tests exist, but a release gate is open. |
| Missing | Required v1.6.25 behavior has no implementation. |
| Deliberate difference | Intentional Go security behavior documented and tested separately. |
| Not applicable | JavaScript/runtime-specific behavior with no server-side Go equivalent. |

## Current release decision

**`v1.0.0` is production-stable within the declared v1 boundary.**

The first v1 stability boundary is intentionally narrower than a complete
Better Auth 1.6.25 replacement: it covers the core server, first-party
MongoDB/PostgreSQL/SQLite adapters, social-provider presets, and generic
OAuth/OIDC consumer. Feature packages below `plugin/`, including SSO and SCIM,
are experimental until separately promoted. The exact `v1.0.0-rc.1` tag passed
the release matrix, its published artifacts and provenance were independently
verified, and the public module was exercised in an isolated Clevixbase
checkout. The exact `v1.0.0` tag then repeated every certification gate,
published successfully, and passed independent module, checksum, and
attestation verification.

## Evidence snapshot

Last updated: 2026-08-20

| Gate | Command or evidence | Result |
| --- | --- | --- |
| Go unit and black-box tests | `go test -count=1 ./...` | Pass |
| TypeScript oracle type check | `bun run typecheck` in `compat/typescript-oracle` | Pass |
| TypeScript oracle migration | `scripts/test-typescript-compat.sh` isolated SQLite setup | Pass |
| Go/TypeScript core characterization | `scripts/test-typescript-compat.sh` | Pass; lifecycle, recovery, verification, reset-callback, multi-session, email change, direct/emailed deletion, OAuth callback/error/replay/new-user, linking collision/options, provider-token, sign-out/session and impersonation-option suites |
| Pinned upstream source inventory | `scripts/check-upstream-v1.6.25.sh` | Pass at tag commit `07a646e` |
| Formatting | `test -z "$(gofmt -l .)"` | Pass |
| Vet | `go vet ./...` | Pass |
| Race detector | `go test -race -count=1 ./...` | Pass |
| Staticcheck | `go run honnef.co/go/tools/cmd/staticcheck@v0.6.1 ./...` | Pass |
| Vulnerability scan | `go run golang.org/x/vuln/cmd/govulncheck@latest ./...` | Pass; no called vulnerabilities |
| Fuzz smoke matrix | Twelve 10-second targets from `.github/workflows/ci.yml` | Pass |
| SQLite adapter conformance | `go test -count=1 ./adapter/sqlite` | Pass as part of full suite |
| MongoDB adapter conformance | `MONGODB_URI=... go test -count=1 ./adapter/mongodb` | Pass on MongoDB 8 single-node replica set |
| PostgreSQL adapter conformance | `POSTGRES_DSN=... go test -count=1 ./adapter/postgresql` | Pass on PostgreSQL 17 |
| Workflow contract | `go run github.com/rhysd/actionlint/cmd/actionlint@latest .github/workflows/*.yml` | Pass |
| Release archive contract | `scripts/test-release-artifacts.sh` | Pass; semantic-name, archive-root, Git-metadata and checksum checks |
| External-module install | `scripts/test-install-module.sh v1.0.0` in release run `30441089802` and independent local rerun | Pass without `replace`; resolved the exact public stable tag |
| Release workflow | `v1.0.0` run `30441089802` | Pass; exact-tag certification and stable publication completed |
| Published artifact integrity | Stable archives, SBOM, checksums, and GitHub attestations | Pass; every SHA-256 checksum and repository identity attestation verified after download |
| Real consumer | Clevixbase commit `cd77b7af`, isolated checkout with `v1.0.0-rc.1` and no `replace` | Pass; mounted SQLite signup/session/sign-out flow under `-race`, full `go test ./...`, and `go vet ./...` |

Update this table with the date and exact command whenever evidence is rerun.
Do not convert a pending or skipped integration test into a pass.

## Compatibility baseline

- Active migration source: Better Auth `v1.7.0`, commit
  `c3688ba88edff12dfcb1ced007e332711509ac29`
- Migration contract: `docs/compatibility/better-auth-v1.7.md`

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
| Sign-out and session retrieval | Present | Anonymous/authenticated retrieval, authenticated/repeated sign-out, cookie clearing and post-sign-out differential; Go origin/CSRF failures asserted | Certified for the pinned core option contract |
| Session refresh and revocation | Present | Session list/update and single/other/all revocation differential; Go-only refresh has one-winner rotation, replacement-session, ownership, replay and race evidence | Certified for the pinned management contract plus the documented Go rotation extension |
| User update, email change, deletion | Present | User update, both change-email modes, enumeration resistance, direct password deletion, emailed deletion callback, replay/ownership and resulting state tests pass | Certified for the pinned core option contract |
| Password change and recovery | Present | Change-password plus request/reset/callback/invalid/replay differential; callback ordering, concurrency and revocation Go tests | Certified for the pinned core option contract |
| Email verification | Present | Send/verify/resend/state differential plus send modes, before/after callbacks and auto-sign-in lifecycle tests | Certified for the pinned core option contract |
| Account list/link/unlink | Present | Public link flow, listing/unlink, verified local implicit linking, enable/disable, trusted providers, different-email, profile update, requestSignUp, same/cross-user and concurrent collision tests pass | Certified for the pinned core option contract |
| Provider access/refresh tokens | Present | Safe read/refresh fields, local provider refresh, persistence and refresh-token redaction differential; Go missing/unsupported/expired/failure, automatic-refresh, encrypted-persistence and one-winner concurrency evidence pass | Certified for configured providers; live provider behavior remains release-operator evidence |
| Admin impersonation | Bounded implementation present | Authorization, admin roles/IDs, admin-target default/opt-in, one-hour session, active identity and stop/restore differential; durable Go audit tests pass | Certified for the bounded core impersonation contract; full admin plugin remains separate |
| Request validators and size limits | Present | Go malformed, unknown-field, panic, oversized-request and oversized-response failure matrix passes | Certified for the pinned server/plugin contract |
| Trusted origins and CSRF | Present | Exact/wildcard/dynamic origin differential plus malicious-suffix, resolver failure/panic, CSRF and concurrent tenant-isolation evidence pass | Certified with the documented HTTPS and double-submit differences |
| `onRequest`, `onResponse`, route and database hooks | Present | Go lifecycle ordering, early/error response, rollback, panic containment and race tests pass | Certified for the pinned server/plugin contract |
| Rate-limiter hook | Present | Core/plugin denial, error, panic, bounded retry metadata and no-write failure evidence pass | Certified injected-port contract; no built-in storage implementation |
| Versioned public API and release metadata | v1 stable/experimental boundary documented; semantic tag and attested artifact workflow present | Stable exact-tag install, publication, checksum, attestation, and real-consumer RC evidence pass | Certified in `v1.0.0` |

Core completion requires a differential matrix for every pinned route and
enabled option, including success, validation, authorization, replay, and
failure behavior.

### Social OAuth and generic OAuth/OIDC

| Capability | Status | Remaining evidence |
| --- | --- | --- |
| 35 provider presets | Certified deterministic matrix | Live credential runs remain release-operator evidence |
| Authorization code, state and PKCE | Certified | Callback success/error/new-user, state/provider binding, replay, PKCE and sanitized-error matrix pass; pinned generic-OAuth weakness is a documented difference |
| OIDC nonce and ID-token verification | Certified | Issuer, audience, nonce, expiry, RS256, deterministic clock and JWKS rotation fixtures pass |
| Verified-email linking | Certified | Explicit/implicit, local verification, trusted-provider evidence, same-user refresh, cross-user and concurrent collision matrix pass |
| Refresh and revocation | Partial | Generic refresh is certified; provider-specific revocation remains provider-dependent |
| Generic OAuth/OIDC consumer API | Certified | Discovery, custom mapping, all client-auth modes, refresh, redirect, response-bound, error-redaction and SSRF fixtures pass |
| Live provider interoperability | Missing release evidence | Selected sandbox-provider runs with secrets supplied by CI or release operator |

Live provider tests are release certification, not ordinary pull-request tests.
They must never log provider credentials or returned tokens.

### Experimental feature plugins

| Plugin | Implementation | Status |
| --- | --- | --- |
| Passkey/WebAuthn | Full Go ceremony and adapter tests present | Experimental; outside the first v1 stability guarantee |
| Two-factor authentication | TOTP, delivered OTP, backup codes and trusted devices present | Experimental; outside the first v1 stability guarantee |
| Organizations | Runtime, membership, invitations, teams, roles and tests present | Experimental; outside the first v1 stability guarantee |
| SSO | Provider management, OIDC/PKCE/JWKS, domain verification, signed SAML ACS/metadata/replay protection and SLO are implemented | Experimental; deterministic suites pass, but pinned/live interoperability promotion gates remain |
| SCIM | Connection management, hash-only bearer authentication, metadata and complete User CRUD/list/filter/PUT/PATCH runtime | Experimental; deterministic suites pass, but pinned/live directory promotion gates remain |

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

Passkey, two-factor, organizations, SSO, and SCIM have experimental Go
implementations outside the first v1 guarantee. Everything else above remains
missing or partial unless its capability matrix says otherwise. TypeScript
adapters, Expo/Electron clients,
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
| Anonymous sign-out | Returns success without an existing session/CSRF cookie | Requires a valid double-submit CSRF cookie; repeated sign-out is idempotent after one is issued | Deliberate CSRF security difference |
| Generic OAuth provider error | Redirects to global error URL before state parsing, reflects `error_description`, and leaves state reusable | Consumes valid state first, uses only its allowlisted error URL, emits a bounded code, and never reflects provider descriptions | Deliberate provider-error and replay hardening |
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
5. Selected live social-provider sandbox tests or an explicitly approved
   provider-operated-risk decision.
6. Dependency vulnerability scan and review of any accepted finding.
7. Install-from-tag test in a separate example module.
8. Versioned archive/checksum/SBOM publication and signed provenance
   verification.
9. Upgrade test from the previous release database schema.

Browser passkey, pinned SSO/SCIM differential, and live enterprise
interoperability are plugin-promotion gates rather than first-v1 release gates
while those packages remain experimental.

## Recommended work order

1. Maintain the stable v1 boundary through reviewed patch/minor releases and
   repeat the exact-tag certification and artifact verification for each.
2. Upgrade the GitHub Actions runtime versions before their Node.js 20
   compatibility shims are removed.
3. Promote SSO, SCIM, and other experimental plugins only through their
   independent ADR and interoperability gates.

## Maintenance rule

Each pull request affecting compatibility must update:

1. the relevant capability row;
2. its test evidence;
3. any newly observed HTTP difference; and
4. the remaining recommendation order.

“Implemented” without reproducible evidence remains **Partial**.
