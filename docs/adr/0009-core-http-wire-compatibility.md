# ADR 0009: Core HTTP wire compatibility

- Status: accepted
- Date: 2026-07-28
- Better Auth reference: `better-auth` v1.6.25

## Context

The first Go-versus-TypeScript black-box suite proved that the core lifecycle
has compatible state transitions but still exposes avoidable wire differences:

- core `User` and `Session` values serialize several fields as snake_case;
- Go errors are nested below an `error` property and use internal lowercase
  codes, while Better Auth returns top-level `code` and `message` properties;
- `POST /update-user` returns the updated user instead of
  `{"status":true}`.

Opaque cookie tokens, hash-at-rest session storage, token redaction and the
double-submit CSRF cookie are intentional security differences and are not
changed by this decision.

Duplicate sign-up behavior is intentionally excluded. Better Auth v1.6.25
returns either an explicit 422 error or an indistinguishable synthetic success
depending on `requireEmailVerification` and `autoSignIn`. That behavior must be
implemented with the complete email/password option contract so this library
does not introduce an account-enumeration oracle.

## Decision

1. Core user and session JSON uses Better Auth's camelCase field vocabulary.
   Go field names and database schema names do not change.
2. Public HTTP errors use a top-level object containing `code`, `message`, and
   optional `requestId`. Internal `ErrorCode` values remain stable for Go hooks
   and plugins; the HTTP boundary maps them to Better Auth-shaped codes.
3. Authentication and origin errors proven by the oracle use the exact
   `INVALID_EMAIL_OR_PASSWORD` and `INVALID_ORIGIN` codes.
4. `POST /update-user` returns `{"status":true}` after the transactional update.
   Updated user state remains observable through `GET /get-session`.
5. The differential suite rejects legacy snake_case fields and nested error
   envelopes so compatibility cannot silently regress.

## Consequences

- Existing pre-1.0 HTTP consumers relying on snake_case or nested errors must
  update. This is accepted before the first stable release.
- The exported Go `Error` type and its lowercase `ErrorCode` constants remain
  source-compatible.
- More specific Better Auth error-code mapping remains incremental. Codes not
  yet assigned a route-specific upstream code use a stable status-category
  mapping at the HTTP boundary.
- Duplicate sign-up parity remains an explicit release blocker until the
  email/password configuration increment lands.
