# ADR 0013: Verified account deletion

- Status: accepted
- Date: 2026-07-28
- Better Auth reference: `better-auth` v1.6.25

## Context

ADR 0012 certifies direct account deletion with a password or a fresh session,
but Better Auth v1.6.25 also supports an emailed deletion-verification flow.
When configured, `POST /delete-user` creates an expiring token and sends a
callback URL instead of deleting immediately. The callback requires the
requesting user's session, consumes the token once, runs deletion hooks,
deletes the user and related authentication state, clears the cookie, and
optionally redirects to an allowed callback URL.

The Go library already has an injectable mailer, opaque hash-at-rest one-time
tokens, transactional user deletion, trusted redirect validation, and
request-scoped contexts. It does not yet expose the deletion-verification
option, deletion hooks, a deletion-token lifetime, or
`GET /delete-user/callback`.

## Decision

1. Extend `UserManagementConfig` with
   `SendDeleteAccountVerification`, `BeforeDelete`, and `AfterDelete`.
   Hooks use `UserDeletionHook`, which receives the request context and the
   public user.
2. Add `Config.DeleteUserTTL`, defaulting to Better Auth v1.6.25's 24 hours
   and constrained to one minute through seven days.
3. Add the purpose-separated `PurposeUserDeletion` one-time token. Tokens are
   cryptographically random, stored only as hashes, expire, and are consumed
   atomically.
4. When deletion verification is enabled, `POST /delete-user` validates the
   optional callback URL, creates the token, sends `account-deletion` mail, and
   returns `{"success":true,"message":"Verification email sent"}` without
   deleting the account. An omitted callback defaults to the same-origin root,
   as v1.6.25 does; non-root callbacks remain allowlisted.
5. Add authenticated `GET /delete-user/callback`. It validates the callback
   allowlist, rate limits by token hash, consumes the token before hooks or
   deletion, verifies token ownership, deletes the user, clears the session
   cookie, and returns the v1.6.25 success body or an allowed redirect.
6. Accept a deletion token in `POST /delete-user`, matching the upstream
   server-side API shape while retaining Go's CSRF requirement for the POST
   mutation.
7. A wrong-owner callback burns the token, as Better Auth v1.6.25 does.
   Concurrent replay therefore has at most one successful deletion.
8. Password-authorized deletion does not require a fresh session. Direct
   deletion without a password does. Requesting or completing emailed
   verification requires an authoritative authenticated session but not a
   fresh one, matching the pinned flow.
9. `BeforeDelete` runs after token consumption but before destructive work and
   may stop deletion. `AfterDelete` runs after durable deletion and cookie
   clearing. An after-hook error is observable but cannot roll back deletion.
10. The pinned TypeScript oracle exposes a second base path with verification
    enabled. This preserves the existing direct-deletion tests while adding
    black-box differential evidence for the optional flow.

## Implementation plan

1. Add configuration, hook, token-purpose, store-consumption, and route
   contracts.
2. Refactor direct and callback deletion through one hook-aware destructive
   operation.
3. Add black-box tests for mail delivery, hash-at-rest storage, success,
   redirect allowlisting, invalid token, wrong owner, replay, expiry, hook
   ordering, and password/fresh-session behavior.
4. Extend the checked-in Better Auth 1.6.25 oracle and differential suite.
5. Update the production tracker and run every release gate.

## Consequences

- Applications can require proof of mailbox access before account deletion
  without implementing authentication persistence themselves.
- The Go token remains stronger at rest than the upstream raw-token identifier.
- Hooks provide the pinned lifecycle extension without coupling the library to
  application cleanup or provisioning.
- The remaining email/password option work after this ADR is limited to
  change-email modes and the remaining lifecycle callbacks/options.
