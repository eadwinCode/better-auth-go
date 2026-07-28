# ADR 0011: Recovery, verification, and session certification

- Status: accepted
- Date: 2026-07-28
- Better Auth reference: `better-auth` v1.6.25

## Context

The first cross-runtime suite certifies signup, signin, signout, session
retrieval, account listing, user update, password change, and a small part of
session management. Password recovery and email verification have Go
black-box coverage but no successful TypeScript differential flow because the
reference server does not expose delivered test mail. The reference server is
also maintained outside this repository, so CI cannot reproduce the
cross-runtime evidence.

Source review found an avoidable route mismatch: Better Auth v1.6.25 exposes
`POST /request-password-reset` with `redirectTo`, while Go exposes only
`POST /forget-password`. Session mutation success responses also use
`{"status":true}` upstream and `{"success":true}` in Go.

Opaque cookie-only sessions, hash-at-rest session and one-time tokens, stable
session IDs in lists, and double-submit CSRF protection remain required Go
security properties.

## Decision

1. Add `POST /request-password-reset` as the canonical v1.6.25 route and accept
   `redirectTo`. Keep `/forget-password` as a documented pre-1.0 compatibility
   alias.
2. Validate recovery and verification callback URLs through the existing
   trusted redirect allowlist before issuing mail.
3. Match the upstream generic password-reset message and the observable
   `{"status":true}` response shapes for session revocation.
4. Require a fresh session for `GET /list-sessions`, matching Better Auth
   v1.6.25. Session revocation continues to use the authoritative database
   session plus Go's trusted-origin and CSRF checks.
5. Keep recovery and verification tokens random, single-use, expiring, and
   hash-at-rest even though the TypeScript implementation uses different token
   storage and encoding internally.
6. Check a pinned TypeScript oracle into this repository. Its mail capture
   endpoint is test-only, authenticated by an injected secret, and bound to
   the loopback test server. CI runs the differential suite against this
   fixture.
7. Differential tests compare public status, safe JSON fields, redirects,
   cookies, replay behavior, and resulting authentication state. Random
   credentials and the deliberate token-redaction differences are asserted
   separately instead of normalized away.

## Implementation plan

1. Vendor the minimal Better Auth 1.6.25 Bun oracle and add authenticated mail
   capture controls.
2. Add recovery and verification success, invalid-token, replay, callback
   allowlist, and enumeration-resistant response comparisons.
3. Add multi-client session list, single-session revocation, other-session
   revocation, and all-session revocation comparisons.
4. Correct only differences proven by pinned source or differential results,
   then run the full Go, race, fuzz, static, vulnerability, and real-adapter
   gates.

## Consequences

- Cross-runtime core evidence becomes reproducible in pull-request CI.
- Existing users of `/forget-password` are not broken, while new integrations
  can use the pinned Better Auth route.
- Session lists and revoke-session inputs remain a deliberate wire difference:
  Go never reconstructs or returns stored bearer tokens and revokes by stable,
  owned session ID.
- The test-control API is not compiled into or exposed by the Go library.
