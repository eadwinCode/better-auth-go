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
