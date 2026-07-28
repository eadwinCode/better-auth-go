# ADR 0012: Core management differential certification

- Status: accepted
- Date: 2026-07-28
- Better Auth reference: `better-auth` v1.6.25

## Context

The pinned differential suite covers the basic email/password lifecycle,
recovery, verification, and session management. Email change, user deletion,
account linking and unlinking, provider-token routes, and admin impersonation
have Go black-box tests but no cross-runtime HTTP evidence.

Source review of Better Auth v1.6.25 found observable drift:

- changing to the current email is an error upstream but succeeds in Go;
- changing to an email owned by another user is enumeration resistant upstream
  but returns a conflict in Go;
- unlink-account status, error codes, and HTTP statuses differ;
- provider-token response fields and the automatic-refresh window differ;
- delete-user success omits the upstream message; and
- the two implementations preserve the administrator identity differently
  during impersonation.

The Go security contract still requires opaque hash-at-rest sessions,
single-use hash-at-rest verification tokens, encrypted OAuth credentials, no
refresh-token disclosure, bounded impersonation, session rotation, and durable
audit events.

## Decision

1. Add a pinned cross-runtime matrix for the public HTTP behavior and resulting
   state of all five management surfaces.
2. Make change-email enumeration resistant. A request for an email already
   owned by another user performs equivalent token-generation work, returns
   `{"status":true}`, sends no mail, and changes no state. Changing to the
   current email returns the v1.6.25 bad-request response.
3. Match Better Auth v1.6.25 unlink-account results: successful unlink returns
   `{"status":true}`, a missing account is `ACCOUNT_NOT_FOUND` with HTTP 400,
   and refusal to remove the last sign-in method is
   `FAILED_TO_UNLINK_LAST_ACCOUNT` with HTTP 400.
4. Match the provider-token account/provider selection errors, expose
   `scopes` as an array, expose the ID token when present, and use the upstream
   five-second automatic-refresh window.
5. Deliberately continue to omit refresh tokens from both provider-token
   responses. Refresh tokens remain encrypted at rest and are credentials for
   server-to-provider use, not browser return values. This is an explicit
   security difference from Better Auth v1.6.25 `/refresh-token`.
6. Match the delete-user success body and credential error contract for the
   direct password-authorized flow. The optional emailed deletion callback is
   tracked separately because enabling it changes the public configuration
   and mail-port contract.
7. Compare impersonation authorization, one-hour maximum expiry, response
   shape, cookie transition, active identity, and stop behavior. Go continues
   to rotate and revoke the actor session on entry and creates a new actor
   session on exit, while Better Auth stores and restores the original admin
   session cookie. Go also keeps durable start/stop audit events. These are
   deliberate implementation and security differences.
8. The checked-in TypeScript oracle exposes a loopback-only deterministic
   OAuth token endpoint protected by fixture client credentials. Account
   linking itself must still run through the public HTTP flow.

## Implementation plan

1. Enable change-email, delete-user, the admin plugin, and a loopback generic
   OAuth provider in the Better Auth 1.6.25 oracle.
2. Add a deterministic local OAuth token response while exercising account
   linking through the public endpoint.
3. Add cross-runtime black-box tests for email-change enumeration behavior,
   direct deletion, account listing/unlinking, provider-token read/refresh,
   and impersonation entry/exit/authorization.
4. Correct only differences demonstrated by the pinned source and tests.
5. Run all existing Go, race, static, vulnerability, fuzz, SQL, MongoDB, and
   TypeScript compatibility gates before release.

## Consequences

- The remaining core-management recommendation gains reproducible CI evidence.
- Applications receive v1.6.25-compatible route shapes without weakening the
  Go token-storage and impersonation guarantees.
- Provider refresh-token redaction and impersonation session replacement stay
  documented differences and are asserted independently.
- Emailed account deletion remains a visible follow-up item rather than being
  silently treated as certified.
