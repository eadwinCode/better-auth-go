# ADR 0010: Email/password option contract

- Status: accepted
- Date: 2026-07-28
- Better Auth reference: `better-auth` v1.6.25

## Context

The initial Go core always created a session after email signup, always revoked
all sessions and created a replacement session after password reset, and always
returned a conflict for duplicate email signup. Better Auth v1.6.25 makes those
transitions depend on `autoSignIn`, `requireEmailVerification`, and
`revokeSessionsOnPasswordReset`.

Those options cannot be implemented independently. Duplicate-signup
enumeration protection is enabled whenever verification is required or
automatic sign-in is disabled, and both conditions also suppress session
creation for a newly registered user.

## Decision

1. `Config.EmailPassword` exposes the Better Auth option names
   `DisableSignUp`, `AutoSignIn`, `RequireEmailVerification`, and
   `RevokeSessionsOnPasswordReset`. `AutoSignIn` is a pointer so an omitted
   value preserves Better Auth's `true` default.
2. The password bounds default to Better Auth v1.6.25's 8-byte minimum and
   128-byte maximum. The existing explicit bounds remain supported and are
   applied consistently to signup, password change, password creation, and
   reset.
   Password-reset and email-verification tokens default to Better Auth's
   one-hour lifetime while retaining explicit Go duration overrides.
3. A new signup creates a session only when automatic sign-in is enabled and
   email verification is not required.
4. Requiring email verification sends the existing hash-at-rest,
   single-use verification token after signup and prevents credential sign-in
   until verification succeeds.
5. Duplicate signup returns Better Auth's explicit 422 error in the default
   auto-sign-in mode. When verification is required or automatic sign-in is
   disabled, it performs the password hash work and returns a synthetic,
   sessionless success response without reading private fields from the
   existing account.
6. Password reset consumes the token and changes or creates the credential
   account atomically. It does not sign the browser in. Existing sessions are
   revoked in the same transaction only when
   `RevokeSessionsOnPasswordReset` is enabled.
7. Missing-user and missing-credential sign-in paths perform password hashing
   before returning the generic credential error to reduce timing-based email
   enumeration.
8. Route-specific validation and policy failures use the corresponding Better
   Auth v1.6.25 public error codes.

## Security consequences

- Synthetic signup responses contain only caller-supplied normalized public
  fields, a fresh identifier, and the injected clock value.
- No session bearer is created, stored, or set in a cookie on a sessionless
  signup.
- Verification and reset tokens remain opaque, single-use, expiring, and
  hash-at-rest.
- Applications should enable `RevokeSessionsOnPasswordReset` when their threat
  model requires password reset to terminate every existing device. The
  default remains `false` for Better Auth compatibility.
- The Go implementation continues to measure password bounds in bytes to cap
  password-hashing work deterministically. Non-ASCII edge behavior is a
  documented runtime difference from JavaScript UTF-16 string length.

## Compatibility consequences

- This is a pre-1.0 behavior correction. The default password maximum changes
  from 1024 bytes to 128 bytes, the reset and verification token lifetimes
  change to one hour, and password reset no longer creates a session or revokes
  existing sessions unless configured.
- Opaque cookie-only sessions, token redaction, and explicit double-submit
  CSRF remain deliberate security differences.
