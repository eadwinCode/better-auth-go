# better-auth-go Implementation Plan

This plan implements ADR 0001 in reviewable slices. Each slice ends with focused
tests and an intentional commit.

## Phase 0: Repository and contracts

1. Initialize `github.com/eadwinCode/better-auth-go`.
2. Add ADR 0001, this plan, license, contribution guidance, and security policy.
3. Define v1 public records, configuration, ports, error codes, and constructor.
4. Add fail-closed configuration tests.

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

## Phase 2: Core email/password and sessions

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

## Phase 3: Recovery and verification

1. Implement password-reset issuance and atomic consumption.
2. Implement email-verification issuance and atomic consumption.
3. Integrate the mail delivery port with generic public responses.
4. Revoke existing sessions after password reset and issue a fresh session.

Exit criteria:

- tokens are hash-at-rest, expiring, purpose-bound, and single-use;
- mail failures do not expose account existence;
- reset replay and purpose confusion tests fail safely.

## Phase 4: Google OAuth

1. Implement authorization redirect with S256 PKCE and persisted single-use
   state.
2. Validate exact callback destinations against the allowlist.
3. Implement bounded code exchange and user-info retrieval.
4. Require verified email and atomically link or create the account.
5. Rotate any existing session and map provider errors safely.

Exit criteria:

- black-box tests cover happy path, replay, state expiry, PKCE, unverified email,
  account conflicts, malicious redirects, oversized responses, and provider
  errors.

## Phase 5: Admin impersonation and audit

1. Invoke the authorization port with actor and subject context.
2. Atomically create a capped impersonation session and durable audit event.
3. Rotate the actor's current browser session token.
4. Expose actor/subject metadata in server-side session records without leaking
   unnecessary security data.

Exit criteria:

- unauthorized attempts fail closed;
- sessions never exceed one hour;
- a session cannot exist without its audit event.

## Phase 6: MongoDB adapter

1. Implement collections, codecs, index creation, and health checks.
2. Implement all adapter operations using MongoDB transactions where required.
3. Use unique indexes and conditional updates for replay/concurrency safety.
4. Document replica-set/sharded-cluster requirements.
5. Add integration tests gated by `MONGODB_URI`.

Exit criteria:

- the adapter passes the shared conformance suite;
- concurrent token/session consumption has exactly one winner;
- all persisted secret material is hashed.

## Phase 7: Production readiness

1. Add runnable `net/http` and MongoDB examples.
2. Add API, deployment, migration bridge, threat model, and operations docs.
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

