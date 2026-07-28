# ADR 0003: Core management APIs, endpoint validation, and SQL adapters

- Status: Accepted
- Date: 2026-07-28
- Scope: the release immediately following the plugin-kernel merge

## Context

The server already owns signup, signin, signout, session refresh, recovery,
verification, OAuth callback handling, and impersonation. Better Auth
applications also depend on the core user, account, and session-management
routes. Plugin authors need an endpoint validation contract that is independent
of any particular validation library. PostgreSQL and SQLite must be supported
without coupling the authentication domain to SQL.

This work precedes passkeys, two-factor authentication, organizations, and SSO.
Those plugins have larger security and data-model contracts and are deliberately
not included here.

## Decisions

### Core management surface

The server adds these Better Auth-shaped routes:

| Method | Route | Contract |
| --- | --- | --- |
| POST | `/update-user` | Updates only schema fields marked as input fields. Core identity and security fields are never client-writable. |
| POST | `/change-email` | Opt-in, fresh-session flow that changes the address only after a single-use verification sent to the new inbox. |
| POST | `/delete-user` | Opt-in, fresh-session deletion with password reauthentication for credential users. |
| POST | `/change-password` | Requires the current credential, rotates the browser session, and may revoke every other session. |
| GET | `/list-accounts` | Returns account metadata only; credentials and provider tokens are never returned. |
| POST | `/link-social` | Links only a verified provider identity bound to the authenticated user and one-time OAuth state. |
| POST | `/unlink-account` | Requires a fresh session and refuses to remove the last sign-in method by default. |
| POST | `/get-access-token` | Returns a decrypted access token only for an account owned by the current user. |
| POST | `/refresh-token` | Uses an optional provider refresh port, encrypts the replacement set, and never returns the refresh token. |
| GET | `/list-sessions` | Returns active session metadata without raw tokens or token hashes. |
| POST | `/revoke-session` | Revokes an owned session by opaque session ID. Omitting the ID revokes the current session for backward compatibility. |
| POST | `/revoke-other-sessions` | Revokes every active session except the current one. |
| POST | `/revoke-sessions` | Revokes every active session and clears the browser cookie. |
| POST | `/update-session` | Updates only plugin-defined session fields marked as input fields. |

`Server.SetPassword` and `Server.VerifyPassword` provide the server-only
equivalent of Better Auth's internal password endpoints. They are not mounted as
HTTP routes.

Session lists expose stable session IDs instead of bearer tokens. This is an
intentional security difference from JavaScript implementations that persist or
return raw session tokens: this library stores only token hashes.

### Freshness and mutation security

Sensitive account mutations require a session created within
`SessionFreshAge`, which defaults to 24 hours. Every state-changing HTTP route
continues to require a trusted Origin and the double-submit CSRF token.
Password changes always replace the current session so a captured session
cannot survive credential rotation.

### Endpoint validators

Plugin endpoints may declare independent body and query validators. Validators
run after request-wide `OnRequest` hooks and rate limiting, but before endpoint
middleware, before-hooks, or endpoint code. This preserves request
normalization hooks while ensuring application logic never sees unvalidated
input. Validation errors produce the existing structured `BAD_REQUEST` response
without exposing validator internals.

The validator interface accepts decoded values and is intentionally small so
applications can bridge any validation package. The library also provides a
strict declarative object validator for common JSON and query contracts.

### SQL architecture

The domain continues to depend only on `DatabaseAdapter`. A shared
`database/sql` implementation owns query construction, identifier validation,
transactions, atomic consume/update operations, and schema migration.
`adapter/postgresql` and `adapter/sqlite` are thin dialect constructors.

SQL adapters are schema-aware. During server construction, an adapter that
implements `SchemaConfigurableAdapter` receives the fully merged core and plugin
schema before the existing logical-to-physical schema wrapper is applied. This
keeps custom fields and model/field mappings working without SQL-specific
knowledge in the server.

Schema migration is explicit through `Migrate`; constructing a server never
changes a database. Values use portable scalar storage and the existing schema
adapter performs JSON, date, boolean, and array encoding. SQL identifiers are
quoted only after strict validation, predicates are parameterized, and
single-row mutations reject empty predicates.

## Consequences

- Existing adapters remain source compatible.
- Plugin endpoint validation is available without selecting a validation
  dependency for consumers.
- PostgreSQL and SQLite share behavior and adapter conformance tests.
- Raw session tokens remain write-only bearer credentials.
- The compatibility register must continue to list email change, deletion,
  OAuth linking/token routes, and the high-risk plugins as missing until their
  full security contracts are implemented.
