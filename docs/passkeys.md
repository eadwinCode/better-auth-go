# Passkeys/WebAuthn

The `plugin/passkey` package implements Better Auth's passkey server endpoint
sequence as an embeddable Go plugin. It supports registration, user-bound and
discoverable authentication, listing, renaming, and deletion.

## Configure

```go
passkeys, err := passkey.New(passkey.Config{
	RPID:          "example.com",
	RPDisplayName: "Example",
	Origins: []string{
		"https://app.example.com",
	},
})
if err != nil {
	return err
}

config.Plugins = append(config.Plugins, passkeys)
auth, err := betterauth.New(config)
if err != nil {
	return err
}
```

`RPID` must equal an origin host or a registrable suffix of every configured
origin. Wildcards and public suffixes are rejected. Production origins require
HTTPS; `http://localhost` is permitted for local development. Cross-origin
iframe ceremonies are disabled.

User verification defaults to `passkey.VerificationRequired`. Set
`passkey.VerificationPreferred` only when supporting authenticators without UV
is required. Resident credentials default to `preferred`, attestation defaults
to `none`, and the challenge lifetime defaults to five minutes.

`AuthenticatorAttachment`, `RequireResidentKey`, and `ResidentKey` expose the
remaining Better Auth authenticator-selection controls. `ChallengeCookie`,
`ChallengeTTL`, and `MaxCredentials` have bounded secure defaults.

## Registration and verification hooks

Better Auth-compatible passkey-first registration is opt-in:

```go
Registration: passkey.RegistrationConfig{
	AllowWithoutSession: true,
	ResolveUser: func(
		ctx *betterauth.HookContext,
		registrationContext string,
	) (passkey.RegistrationUser, error) {
		return resolvePendingRegistration(ctx.Context, registrationContext)
	},
}
```

Construction fails if sessionless registration is enabled without a resolver.
Resolver output is stored only in the server-side challenge record. The target
user must exist before credential persistence; an `AfterVerification` callback
may create the account or return a different target only when no browser
session authenticated the ceremony.

`Registration.Extensions` and `Authentication.Extensions` are request-scoped
extension resolvers. `Registration.AfterVerification` and
`Authentication.AfterVerification` run after cryptographic verification but
before credential/counter/session persistence. Callbacks receive public-safe
verification metadata and must be concurrency-safe.
Callbacks that perform external side effects must also be idempotent: a later
guarded database write may lose a legitimate concurrency race and reject the
request.

`Config.Schema` supports Better Auth-style passkey model/field mapping and
additional fields through the generic merged schema contract.

## Browser sequence

Registration:

1. Establish a normal fresh session and obtain the server's CSRF token.
2. `GET /api/auth/passkey/generate-register-options`.
3. Pass the JSON response to `navigator.credentials.create({publicKey:
   options})`.
4. `POST /api/auth/passkey/verify-registration` with
   `{"response": credential, "name": "Laptop"}`, the trusted `Origin`, session
   cookie, and `X-CSRF-Token`.

For passkey-first/sessionless registration, add `"createSession": true` to
step 4. The verified passkey and initial session are persisted in one database
transaction; session cookies are applied only after commit. The response adds
the `session` and `user` fields to the passkey resource.

Authentication:

1. `GET /api/auth/passkey/generate-authenticate-options`. An existing session
   restricts the returned allow-list to that user's passkeys; without one, the
   flow uses discoverable credentials.
2. Pass the JSON response to `navigator.credentials.get({publicKey: options})`.
3. `POST /api/auth/passkey/verify-authentication` with
   `{"response": assertion}` and the trusted `Origin`.
4. Accept the rotated session and CSRF cookies returned by the server.

The JSON serialization used by browsers must convert `ArrayBuffer` members to
unpadded base64url strings. Better Auth's passkey browser client or any standard
WebAuthn JSON helper can perform this conversion.

## Management routes

| Method | Path | Requirements |
| --- | --- | --- |
| GET | `/api/auth/passkey/list-user-passkeys` | active session |
| POST | `/api/auth/passkey/update-passkey` | session, CSRF, trusted origin, ownership |
| POST | `/api/auth/passkey/delete-passkey` | session, CSRF, trusted origin, ownership |

Management responses include Better Auth's public fields. They never expose the
opaque user handle or full WebAuthn verifier record.

## Persistence and migrations

The plugin contributes the logical `passkey` model to `Server.Schema()`.
PostgreSQL and SQLite applications must run the adapter's explicit `Migrate`
after constructing the server. MongoDB applications must create merged-schema
indexes:

```go
if err := mongoAdapter.EnsureIndexes(ctx, auth.Schema()); err != nil {
	return err
}
```

Credential IDs are unique, user and user-handle lookups are indexed, and all
core challenge consumption and counter updates use adapter atomic operations.
MongoDB still requires a replica set or sharded cluster for transactions.

## Security properties

- The WebAuthn library verifies the challenge, ceremony type, exact origin, RP
  ID, user presence, configured user-verification policy, signature, user
  handle, backup flags, and public key.
- The browser challenge handle is a secure host-only HttpOnly cookie; only its
  SHA-256 hash is persisted.
- Challenges expire and have one verification attempt. Registration challenges
  cannot authenticate and authentication challenges cannot register.
- Every account uses a stable random opaque WebAuthn user handle across its
  credentials.
- Sessionless enrollment is disabled by default and requires an application
  resolver; a session-authenticated enrollment cannot be rebound.
- Credential creation enforces the configured per-user maximum transactionally.
- A non-zero signature counter has a guarded one-winner update. Clone warnings
  and counter regressions fail authentication; zero-only authenticators remain
  compatible with WebAuthn.
- Successful authentication rotates a valid existing browser session or creates
  a new opaque hash-at-rest session, preventing fixation.
