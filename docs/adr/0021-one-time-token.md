# ADR 0021: One-time-token plugin

- Status: Accepted
- Date: 2026-10-12
- Better Auth reference: `better-auth` v1.7.0, commit `c3688ba`
  (`packages/better-auth/src/plugins/one-time-token/`). The plugin files are
  the same in v1.6.25+24, v1.7.0, v1.7.1 and v1.7.7+42.

## Context

Apps on another subdomain cannot read `__Host-` session cookies. Better Auth's
`one-time-token` plugin solves this: a signed-in user gets a short-lived token,
and whoever holds it trades it once for the session. A consuming application
(a separate Go service on a subdomain) needs this hand-off.

Two parts of the upstream design do not fit Go as is:

1. Upstream stores the raw session token in the verification row. Go stores
   only session token hashes, so it cannot rebuild the cookie from the
   database, and it must not start storing raw tokens.
2. Upstream verify sets the session cookie before it checks whether the
   session has expired.

## Decision

1. Add `plugin/onetimetoken` with Better Auth's routes, options, messages,
   `set-ott` header, token format (32 URL-safe characters) and defaults
   (3 minutes, `plain` storage). The Go option names follow the TypeScript
   ones; `ExpiresIn` is a `time.Duration`.
2. Add one kernel capability, `HookContext.ResumeSession(rawToken)`. It loads
   an existing session with the same checks as request session resolution and
   returns an `IssuedSession` for that same session. It returns
   `ErrSessionExpired` (which matches `ErrNoSession`) for an expired session
   and `ErrNoSession` for a missing or revoked session or a disabled user.
   Plugins never write the session cookie themselves.
3. Seal the session token in the verification row's metadata with AES-256-GCM.
   The key is HMAC-SHA-256 of a fixed label keyed by the one-time token, which
   is different from the stored SHA-256 hash. The stored token value is bound
   in as extra authenticated data, so a sealed value cannot move between rows.
4. Consume the row with the adapter's atomic `ConsumeOne`, filtered by expiry,
   so concurrent redemptions resolve to one success.
5. Check the session state before attaching a cookie. An expired session never
   gets a cookie.
6. Copy Better Auth's origin rule for verify: when the request carries
   cookies, `Origin` must be present and trusted; otherwise there is no origin
   check. The check runs before the token is consumed.
7. `DisableClientRequest` rejects the HTTP generate route. `Manager.Generate`
   is the server-side way to create a token, checked against the caller's
   resolved session and raw session token.

## Consequences

- HTTP behavior matches Better Auth 1.7.0 for every option; the TypeScript
  differential suite `TestBetterAuthV170OneTimeTokenCompatibility` asserts it.
- Deliberate differences: no raw session token at rest, a different
  verification row layout, no `session.token` in the verify body, no cookie on
  an expired-session error, and the structured `code` on errors.
- A custom `GenerateToken` must return high-entropy tokens. A weak token
  weakens both guessing resistance and the key that seals the session.
- `SetOTTHeaderOnNewSession` adds a token whenever a response sets a session
  cookie, including Go-only session rotation routes. If another plugin revokes
  that session later in the same response (two-factor does for a provisional
  sign-in), the token cannot be redeemed.
- No plugin rate-limit rule is added. Default tokens carry 192 random bits, and
  a per-IP limit would throttle a single server that redeems for many users.
  Applications can still add one through the rate-limiter port.
