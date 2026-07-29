# better-auth-go Implementation Plan

This plan implements ADR 0001 in reviewable slices. Each slice ends with focused
tests and an intentional commit.

## Phase 0: Repository and compatibility contracts

1. Initialize `github.com/eadwinCode/better-auth-go`.
2. Add ADR 0001, this plan, license, contribution guidance, and security policy.
3. Pin an audited Better Auth v1.6 compatibility snapshot and provider catalog.
4. Define v1 public records, configuration, hooks/plugins, error codes, and
   constructor.
5. Add fail-closed configuration tests.

Exit criteria:

- a consumer can compile against the root package;
- invalid origins, cookie settings, durations, Argon2 parameters, or missing
  required ports prevent server construction.

## Phase 1: Security primitives

1. Implement injected cryptographic token source and SHA-256 token hashing.
2. Implement strict PHC Argon2id hashing and verification.
3. Add the password verifier/rehash interface and a composable legacy bridge.
4. Implement PKCE S256, state generation, constant-time comparisons, and safe
  cookie parsing.

Exit criteria:

- crypto fixture tests pass;
- malformed hashes cannot trigger unbounded allocation;
- token and cookie parsers have fuzz targets.

## Phase 2: Generic adapter and schema layer

1. Implement Better Auth-aligned adapter operations, predicates, projections,
   joins, sorting, pagination, capability metadata, and transactions.
2. Implement schema registry, model/field renaming, value transforms, and ID
   generation.
3. Implement safe adapter factory fallbacks while refusing to weaken required
   atomicity.
4. Implement typed core store over `user`, `session`, `account`,
   `verification`, audit, and outbox models.
5. Publish an adapter conformance suite.

Exit criteria:

- a third-party database adapter needs only the generic contract;
- schema extensions and renamed models/fields work;
- atomic consume, guarded increment, and rollback tests pass.

## Phase 3: Core email/password and sessions

1. Implement sign-up and sign-in services.
2. Implement session get, refresh/rotate, revoke, and sign-out.
3. Implement secure host-only cookie issuance and clearing.
4. Add generic authentication failures, size limits, origin/CSRF checks, and
   rate-limit hook calls.
5. Emit versioned `user.created` outbox events.

Exit criteria:

- black-box HTTP tests cover the full lifecycle;
- fixation and replay attempts fail;
- account existence is not disclosed by public errors.

## Phase 4: Recovery and verification

1. Implement password-reset issuance and atomic consumption.
2. Implement email-verification issuance and atomic consumption.
3. Integrate the mail delivery port with generic public responses.
4. Revoke existing sessions after password reset and issue a fresh session.

Exit criteria:

- tokens are hash-at-rest, expiring, purpose-bound, and single-use;
- mail failures do not expose account existence;
- reset replay and purpose confusion tests fail safely.

## Phase 5: Social OAuth/OIDC

1. Implement the generic OAuth2/OIDC authorization-code engine, discovery/JWKS,
   nonce, S256 PKCE, encrypted provider-token persistence, and profile mapping.
2. Port provider presets and provider-specific behavior for all IDs listed in
   `docs/compatibility/better-auth-v1.6.md`.
3. Implement Better Auth-compatible `sign-in/social` and callback routes.
4. Validate exact callback/error/new-user destinations against allowlists.
5. Require provider-appropriate verified identity evidence and atomically link
   or create accounts.
6. Rotate any existing session and map provider errors safely.

Exit criteria:

- every upstream provider ID has a registry and contract fixture;
- provider-specific fixtures test token/profile semantics without live secrets;
- black-box tests cover happy path, replay, state expiry, nonce/PKCE, unverified
  identity, account conflicts, malicious redirects, SSRF, oversized responses,
  and provider errors.

## Phase 6: Admin impersonation and audit

1. Invoke the authorization port with actor and subject context.
2. Atomically create a capped impersonation session and durable start audit
   event.
3. Rotate the actor's current browser session token.
4. Stop impersonation by rotating back to the actor and durably recording the
   stop event.
5. Expose actor/subject metadata in server-side session records without leaking
   unnecessary security data.

Exit criteria:

- unauthorized attempts fail closed;
- sessions never exceed one hour;
- a session cannot exist without its audit event.

## Phase 7: MongoDB adapter

1. Implement the complete generic adapter contract, codecs, index creation, and
   health checks.
2. Implement native atomic consume/guarded increment and transactions.
3. Use unique indexes and conditional updates for replay/concurrency safety.
4. Document replica-set/sharded-cluster requirements.
5. Add integration tests gated by `MONGODB_URI`.

Exit criteria:

- the adapter passes the shared conformance suite;
- concurrent token/session consumption has exactly one winner;
- all persisted secret material is hashed.

## Phase 8: Production readiness

1. Add runnable `net/http` and MongoDB examples.
2. Add API, compatibility, adapter-authoring, provider-authoring, deployment,
   migration bridge, threat model, and operations docs.
3. Add CI for format, test, vet, race, fuzz smoke, govulncheck, and staticcheck.
4. Add release workflow, changelog policy, and semantic version documentation.
5. Run `go test ./...`, `go vet ./...`, `go test -race ./...`, fuzz smoke tests,
   `govulncheck ./...`, and `staticcheck ./...`.
6. Run graphify over the completed repository and review the architecture graph.

Exit criteria:

- all locally available checks pass;
- optional checks clearly report missing external services/tools;
- the branch is pushed and a draft PR documents design, security properties,
  validation, and remaining release gates.

## Phase 9: Server plugin kernel

1. Compile immutable plugin descriptors with IDs, dependencies, initialization,
   schema, trusted origins, and collision-safe endpoints.
2. Implement bounded `OnRequest`, rate-limit, middleware, before, endpoint,
   after, and `OnResponse` execution.
3. Add parameterized routes, endpoint middleware, session and ownership
   helpers, application hooks, and background-task injection.
4. Decorate logical database operations with transaction-aware before/after
   hooks.
5. Test deterministic ordering, early returns, origin precedence, response
   mutation, panic containment, rollback, collisions, and concurrent requests.
6. Maintain a categorized feature-gap register that separates kernel
   primitives from built-in plugin implementations.

Exit criteria:

- plugin code cannot bypass origin checks or mandatory response headers;
- configuration cycles, route ambiguity, and invalid plugin contributions fail
  construction;
- request-specific state is never retained on the server or plugin registry;
- built-in plugin implementations have an explicit follow-up backlog.

## Phase 10: Core management, validators, and SQL adapters

1. Complete Better Auth-shaped user, account, provider-token, and session
   management routes with ownership, freshness, and CSRF checks.
2. Add dependency-free plugin body/query validators before endpoint code.
3. Implement a schema-aware `database/sql` adapter with explicit additive
   migrations and PostgreSQL/SQLite dialect packages.
4. Run SQLite through the public adapter conformance suite and cover management
   routes with black-box security tests.
5. Keep passkeys, 2FA, organizations, SSO, and SCIM in subsequent threat-model
   PRs.

Exit criteria:

- account/session listings never expose password, provider refresh tokens, raw
  session tokens, or token hashes;
- cross-user account/session mutations have no effect;
- password changes rotate the current session atomically;
- validator failures occur before middleware and endpoint code;
- SQLite passes CRUD, atomic consume/increment, concurrency, and rollback tests;
- PostgreSQL and SQLite share parameterized query and migration behavior.

## Phase 11: Passkeys/WebAuthn

1. Add ADR 0004 and freeze the Better Auth-shaped passkey endpoint and schema
   contracts.
2. Add a narrow request-scoped plugin capability for fixation-safe core session
   issuance and rotation.
3. Implement an opt-in `passkey` plugin using the audited Go WebAuthn library,
   exact configured origins, an explicit RP ID, and fail-closed construction.
4. Store challenge handles hashed at rest and consume ceremony-bound,
   five-minute challenges atomically.
5. Store validated credentials with random opaque user handles, globally unique
   credential IDs, counters, backup flags, transports, and required attestation
   metadata.
6. Implement registration, discoverable and user-bound authentication, list,
   rename, and delete routes with validators, session/freshness checks, CSRF,
   ownership, and rate-limit rules.
7. Add black-box HTTP tests, WebAuthn fixtures, replay and cross-ceremony
   failures, origin/RP failures, counter concurrency tests, cookie parser fuzz
   coverage, adapter schema tests, and race checks.
8. Document browser integration, migration differences, and the explicit
   user-verification policy.

Exit criteria:

- a challenge can be consumed only once and only for its ceremony and user;
- assertion verification uses configured origins and RP ID, never request-
  supplied policy;
- credential IDs and discoverable user handles are ownership-bound;
- successful sign-in rotates an existing session or creates a new hashed-token
  session;
- passkey list/update/delete expose Better Auth's public credential fields but
  never opaque user handles, full verifier records, or another user's
  credential;
- zero-only authenticators work while non-zero counter regressions fail closed;
- all unit, black-box, race, vet, and applicable static/security checks pass;
- 2FA, organizations, SSO, and SCIM remain in later PRs.

## Phase 12: Two-factor authentication

1. Add ADR 0005 and freeze the Better Auth v1.6-shaped TOTP, delivered OTP,
   backup-code, trusted-device, and sign-in interception contracts.
2. Extend the user schema with `twoFactorEnabled` and add an adapter-independent
   `twoFactor` model with encrypted secret material and durable lockout state.
3. Intercept successful credential sign-in, revoke the provisional session,
   and issue a single-use hash-at-rest pending-login challenge.
4. Implement TOTP enrollment and verification, injectable OTP delivery,
   encrypted backup-code management, and server-only backup-code viewing.
5. Add consume-and-rearm per-challenge attempts, shared account lockout, trusted
   device rotation, session rotation, trusted-origin/CSRF enforcement, and
   durable security audits.
6. Add black-box flows, RFC 6238 fixtures, concurrency and replay tests, adapter
   migration checks, cookie fuzzing, race checks, documentation, and examples.

Exit criteria:

- a first-factor credential session is never usable while 2FA is pending;
- TOTP secrets and backup codes are always encrypted at rest;
- pending-login, OTP, and trusted-device bearer values are hash-only at rest;
- concurrent verification cannot exceed the attempt budget or consume one
  backup code more than once;
- successful second-factor verification consumes the challenge before issuing
  a fixation-safe session and clears consecutive account failures;
- sensitive management requires a fresh session, trusted origin, CSRF, and a
  password whenever a credential account exists;
- all unit, black-box, race, vet, fuzz, static, and applicable security checks
  pass;
- organizations, SSO, and SCIM remain in later isolated PRs.

## Phase 13: Organizations and tenant authorization

1. Add ADR 0006 and freeze the Better Auth v1.6 organization, membership,
   invitation, team, permission, dynamic-role, and active-context contracts.
2. Add adapter-independent organization models plus session active organization
   and team fields, including explicit compound indexes for SQL and MongoDB.
3. Implement immutable static access control and bounded organization-scoped
   dynamic roles.
4. Implement organization CRUD, active context, member management, invitation
   delivery/transitions, teams, permission checks, and server-only direct
   membership.
5. Enforce target-scoped authorization, verified-email invitation binding,
   transactional last-owner rules, limits, lifecycle hooks, session cleanup,
   CSRF/freshness, and durable audits.
6. Add cross-tenant black-box tests, concurrency invariants, adapter migration
   tests, fuzzing, documentation, examples, and complete release gates.

Exit criteria:

- no target identifier can move authorization across organizations;
- the final owner cannot leave, be removed, or lose ownership;
- invitation acceptance is authenticated, email-bound, expiring, and
  one-winner;
- team membership is subordinate to organization membership;
- active session metadata never replaces a durable membership check;
- dynamic roles cannot grant permissions the actor does not possess;
- compound uniqueness holds in MongoDB, PostgreSQL, and SQLite;
- SSO and SCIM remain separate later PRs.

## Phase 14: Enterprise SSO

1. Add ADR 0007 and freeze the Better Auth v1.6.25 SSO provider, OIDC/OAuth2,
   SAML, domain-verification, provisioning, and management contracts.
2. Add the adapter-independent `ssoProvider` schema, encrypted provider
   configuration, provider collision rules, organization authorization port,
   and durable audit vocabulary.
3. Implement bounded OIDC discovery, authorization code with PKCE, single-use
   state and nonce, JWKS validation, verified-email linking, shared/per-provider
   callbacks, and fixation-safe sessions.
4. Implement SAML SP metadata, AuthnRequest correlation, signed assertion
   verification, replay/timestamp/audience/recipient/algorithm enforcement,
   IdP-initiated policy, and single logout.
5. Implement provider CRUD, domain verification, provisioning hooks, trusted
   redirects, generic provider errors, rate limits, and request-size limits.
6. Add black-box protocol fixtures, concurrency/replay tests, fuzzing, adapter
   migration checks, documentation, examples, and complete release gates.

Exit criteria:

- provider registration cannot cross user or organization ownership boundaries;
- OIDC discovery and metadata fetches cannot escape the outbound URL policy;
- every OIDC callback is PKCE-, state-, nonce-, issuer-, and audience-bound;
- every SAML assertion is signature-, issuer-, audience-, recipient-,
  timestamp-, provider-, and replay-bound;
- provider secrets and private keys are encrypted and never returned;
- successful SSO rotates or creates only core hash-at-rest sessions;
- SCIM remains an independent Phase 15.

## Phase 15: SCIM 2.0 provisioning

1. Add ADR 0008 and freeze the Better Auth v1.6.25 SCIM connection,
   management, User resource, metadata, filter, PATCH, and error contracts.
2. Extend plugin routing for PUT, PATCH, and DELETE with unsafe-method origin
   enforcement and explicit bearer-endpoint origin exceptions.
3. Add the adapter-independent `scimProvider` schema, hash-only bearer tokens,
   provider collision rules, personal ownership, organization authorization,
   token rotation, hooks, and audits.
4. Implement RFC 7644 media types/errors, metadata, pagination, bounded filters,
   and User GET/list/POST/PUT/PATCH/DELETE with provider-account ownership.
5. Enforce explicit existing-user linking, transactional organization
   membership, subordinate-team cleanup, session revocation, and cross-tenant
   deprovisioning boundaries.
6. Add black-box protocol fixtures, concurrency/rotation tests, fuzzing,
   adapter migration checks, documentation, examples, and release gates.

Exit criteria:

- raw SCIM tokens are returned once and never persisted;
- provider IDs cannot collide with another account-producing provider;
- every user mutation is bound to the authenticating provider account;
- organization-scoped DELETE cannot delete a global cross-tenant user;
- filters and PATCH paths cannot become arbitrary adapter queries;
- management authorization is target-scoped and cannot cross owners or tenants;
- SSO remains an independent plugin.

## Phase 16: Core OAuth, session, and admin partial closure

1. Persist allowlisted OAuth success, error, and new-user destinations plus
   signup intent inside single-use state.
2. Make callback errors state-bound and sanitized, certify GET/POST replay,
   and route new users independently from returning users.
3. Implement the Better Auth v1.6.25 account-linking controls for enabled,
   implicit-linking, trusted-provider, local-verification, different-email,
   unlink-last-account, and profile-update policy.
4. Make same-user explicit links idempotent, reject cross-user provider
   identity collisions with stable public errors, and enforce global provider
   identity uniqueness in every first-party adapter.
5. Add a dedicated TypeScript differential matrix for session retrieval,
   sign-out, callback failures/replay, linking collisions, and bounded
   impersonation options.
6. Add immutable admin selection options around the existing authorization
   port while preserving one-hour sessions, rotation, and durable audits.
7. Update compatibility/progress evidence and run every release-relevant local
   gate before opening PR #20.

Exit criteria:

- a callback destination can only come from consumed, allowlisted state;
- OAuth state and provider identities have exactly one winner under replay or
  concurrent collision;
- implicit linking requires verified provider and local identity evidence by
  default;
- sign-out clears the browser cookie, revokes the session, remains safely
  repeatable, and cannot bypass trusted-origin/CSRF enforcement;
- administrator selection and admin-target impersonation fail closed while
  every successful transition remains capped, rotated, and audited;
- all pinned v1.6.25 differential, unit, black-box, race, fuzz, vet, static,
  vulnerability, and available adapter checks pass.

## Phase 17: Request-pipeline and policy certification

1. Add ADR 0017 and freeze the Better Auth v1.6.25 trusted-origin and shared
   request-pipeline contract.
2. Add bounded wildcard origin compilation plus an optional request-scoped
   trusted-origin resolver whose output is immutable and isolated per request.
3. Certify origin/CSRF enforcement, request and response limits, endpoint
   validators, request/response hooks, middleware, database hooks, and
   rate-limit failure behavior without weakening mandatory security headers.
4. Complete session refresh/revocation and provider-token failure,
   persistence, ownership, redaction, and concurrency evidence.
5. Extend the pinned TypeScript oracle where equivalent public HTTP behavior
   exists and record every intentional Go security difference.
6. Update the progress and compatibility registers, run all release-relevant
   checks, and publish the work as PR #21.

Exit criteria:

- wildcard origins cannot match attacker suffixes or public suffixes;
- dynamic origins are validated, resolved once, and cannot bleed across
  concurrent requests;
- origin, validation, and limiter failures occur before endpoint mutation;
- after/onResponse hooks cannot remove mandatory response security headers;
- database-hook failures roll back the surrounding transaction;
- session rotation and revocation have one-winner, ownership-bound evidence;
- provider refresh preserves encrypted credentials and never returns refresh
  tokens;
- all unit, differential, race, fuzz, adapter, static, vulnerability, and
  upstream-contract checks pass.

## Phase 18: v1 release-candidate certification

1. Freeze the v1 stability boundary in ADR 0018. Keep SSO, SCIM, and the other
   feature-plugin packages experimental until their separate promotion gates
   pass.
2. Add one reusable clean-checkout certification workflow for test, vet, race,
   static analysis, vulnerability analysis, every fuzz target, the pinned
   TypeScript differential suite, and upstream inventory.
3. Require real SQLite, PostgreSQL 17, and MongoDB 8 replica-set migration and
   conformance tests without silent skips.
4. Add an external-module install check that uses a candidate commit during
   pull requests and the exact semantic tag during releases.
5. Replace the minimal tag workflow with a semantic-tag-validated,
   certification-dependent release that produces versioned archives,
   checksums, an SPDX SBOM, and signed GitHub provenance attestations.
6. Document deployment, backup/restore, cookie and proxy policy, secret/key
   rotation, schema upgrades, rollback boundaries, and artifact verification.
7. Run the complete release-candidate matrix locally where possible, publish
   one draft PR, and require every GitHub gate to pass.

Exit criteria:

- no experimental feature package is implied to be inside the v1 stability
  guarantee;
- the release workflow cannot publish before the reusable certification
  workflow succeeds for the exact tag;
- required database integration tests cannot pass by skipping;
- an external module compiles against the candidate ref without a local
  `replace`;
- archives and checksums are version-named and covered by signed provenance;
- operator documentation covers recovery, rotation, proxy/cookie, migration,
  rollback, and verification procedures;
- the candidate branch is clean and all local and GitHub release gates pass.

## Phase 19: v1 stable promotion

1. Publish `v1.0.0-rc.1` from the merged release-candidate commit and require
   the exact tag to pass the reusable certification workflow.
2. Download the published archives, checksum file, and SPDX SBOM; verify every
   checksum and GitHub provenance attestation against this repository.
3. Install the public candidate tag without a local `replace` in an isolated
   checkout of a real consuming application.
4. Mount the standard handler in that application, migrate a real SQLite
   database, and exercise signup, session retrieval, CSRF-protected sign-out,
   secure host-only cookies, and post-sign-out revocation under the race
   detector.
5. Run the consuming application's full Go test and vet suites with its pinned
   non-Go workspace dependencies installed.
6. Record the candidate evidence in the changelog and progress register, merge
   it through ordinary pull-request CI, then publish `v1.0.0`.
7. Independently verify the stable tag, release metadata, checksums, SBOM, and
   attestations after publication.

Exit criteria:

- the candidate and stable tags each resolve to a commit on `main`;
- the candidate has no release-blocking security, migration, race, or public
  contract defect;
- the real consumer resolves exactly `v1.0.0-rc.1` without `replace`;
- the consumer's mounted auth lifecycle and full Go validation pass;
- the stable release cannot publish unless its exact-tag certification passes;
- all `plugin/` packages remain explicitly outside the first v1 stability
  guarantee.

## Phase 20: In-process session resolution patch

1. Freeze the additive v1.0.1 API in ADR 0019: `ErrNoSession`,
   `SessionResult`, and `Server.ResolveSession`.
2. Split the private resolver into a cause-preserving core and a
   Better Auth-compatible HTTP adapter.
3. Return `ErrNoSession` for absent, unknown, expired, revoked, and
   disabled-user sessions while preserving wrapped adapter failures for
   application availability handling.
4. Certify the configured cookie name, impersonation metadata, and concurrent
   read-only resolution without returning the opaque token.
5. Preserve `GET /get-session`'s `200 null`, protected-route `401`, and
   idempotent sign-out behavior without serializing resolver causes.
6. Update the public API guide, README, and changelog, then run the complete
   patch-release certification and publish v1.0.1.

Exit criteria:

- applications resolve a session in-process without HTTP or JSON loopback;
- `errors.Is(err, ErrNoSession)` covers every authentication-invalid state;
- infrastructure and context failures remain distinguishable and wrapped;
- session and user values, including impersonation fields, match the existing
  public types;
- resolution is safe under concurrent use and the race detector;
- the v1.0.0 API and HTTP behavior remain compatible;
- v1.0.1 passes exact-tag certification and publishes signed, versioned
  artifacts.
