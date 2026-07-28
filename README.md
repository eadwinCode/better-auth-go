# better-auth-go

`better-auth-go` is an embeddable authentication server library for Go. It owns
authentication state and exposes a standard `net/http` handler; it is not a
client SDK and does not require a Node or Bun service.

The public server and adapter contracts track Better Auth TypeScript v1.6 while
using native Go security defaults:

- Better Auth-compatible core route names under `/api/auth`;
- email/password sign-up, sign-in, password change, verified email change,
  opt-in deletion, sign-out, session listing/rotation/revocation, and account
  linking/unlinking;
- password reset and email verification with single-use hash-at-rest tokens;
- Better Auth's 34 built-in social-provider IDs plus generic OAuth2/OIDC;
- authorization-gated, one-hour maximum admin impersonation with durable audit;
- Argon2id password hashes and an injected migration verifier for legacy scrypt;
- opaque 256-bit session tokens with only SHA-256 hashes persisted;
- host-only `__Host-` Secure HttpOnly SameSite cookies;
- exact trusted-origin, CSRF, callback allowlist, request-size, and rate-limit
  enforcement;
- Better Auth-aligned generic database adapters, schema extensions, model/field
  mappings, transactions, atomic consume, and guarded increments;
- MongoDB, PostgreSQL, SQLite, a public adapter conformance suite, and an
  in-memory development adapter.
- an opt-in Better Auth-shaped passkey/WebAuthn plugin with hash-at-rest,
  single-use challenges and fixation-safe core session rotation;
- an opt-in Better Auth-shaped 2FA plugin with encrypted TOTP/backup material,
  delivered OTP, trusted devices, shared attempt budgets, and durable lockout.

The project is pre-1.0. Review the compatibility matrix and changelog before
upgrading.

## Install

```bash
go get github.com/eadwinCode/better-auth-go
```

## Minimal server

```go
package main

import (
	"context"
	"log"
	"net/http"

	betterauth "github.com/eadwinCode/better-auth-go"
	"github.com/eadwinCode/better-auth-go/adapter/mongodb"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type mailer struct{}

func (mailer) Send(context.Context, betterauth.Mail) error {
	// Deliver through your transactional provider. Never log message.Token.
	return nil
}

type adminPolicy struct{}

func (adminPolicy) CanImpersonate(context.Context, betterauth.User, betterauth.User) error {
	// Replace with an application authorization decision.
	return betterauth.ErrNotFound
}

func main() {
	ctx := context.Background()
	client, err := mongo.Connect(options.Client().ApplyURI("mongodb://localhost:27017"))
	if err != nil {
		log.Fatal(err)
	}
	database, err := mongodb.New(mongodb.Config{Database: client.Database("app")})
	if err != nil {
		log.Fatal(err)
	}
	auth, err := betterauth.New(betterauth.Config{
		PublicURL:               "https://auth.example.com",
		TrustedOrigins:          []string{"https://app.example.com"},
		Database:                database,
		Mailer:                  mailer{},
		ImpersonationAuthorizer: adminPolicy{},
	})
	if err != nil {
		log.Fatal(err)
	}
	if err := database.EnsureIndexes(ctx, auth.Schema()); err != nil {
		log.Fatal(err)
	}
	log.Fatal(http.ListenAndServe(":8080", auth.Handler()))
}
```

The full runnable example is in [`examples/nethttp`](./examples/nethttp).

## Mounting

`Handler()` accepts full request paths. With the default configuration it serves
under `/api/auth`. To share a mux:

```go
mux := http.NewServeMux()
mux.Handle("/api/auth/", auth.Handler())
```

Set `Config.BasePath` to mount elsewhere. Route paths do not contain an extra Go
specific version segment.

## Social providers

Construct providers with `social.New` and register them by Better Auth provider
ID:

```go
google, err := social.New("google", social.Options{
	ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
	ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
})
if err != nil {
	return err
}

cipher, err := betterauth.NewAESGCMTokenCipher(providerTokenKey)
if err != nil {
	return err
}

config.SocialProviders = map[string]betterauth.OAuthProvider{
	"google": google,
}
config.AllowedRedirectURLs = []string{
	"https://app.example.com/auth/complete",
}
config.ProviderTokenCipher = cipher
```

Supported built-in IDs are exported as `social.SupportedProviders`. Custom
OAuth2 providers use the same constructor with explicit authorization, token,
and user-info URLs. Provider endpoints must be HTTPS, provider HTTP clients are
bounded and refuse redirects, OIDC ID tokens validate signature/issuer/audience/
expiry/nonce, and provider credentials are encrypted before persistence.

Some providers do not assert a verified email. They can authenticate a stable
provider account, but automatic email linking remains blocked until the
application supplies a trustworthy verification/collection policy through a
custom profile mapper. This is a deliberate account-takeover defense.

## Passkeys

Passkeys are opt-in and remain a normal server plugin:

```go
import "github.com/eadwinCode/better-auth-go/plugin/passkey"

passkeys, err := passkey.New(passkey.Config{
	RPID:          "example.com",
	RPDisplayName: "Example",
	Origins:       []string{"https://app.example.com"},
})
if err != nil {
	return err
}
config.Plugins = append(config.Plugins, passkeys)
```

The default requires authenticator user verification. Set
`UserVerification: passkey.VerificationPreferred` only when compatibility with
authenticators that cannot assert UV is an explicit product decision. RP ID and
origins are exact construction-time policy; request headers cannot expand them.

The HTTP flow matches Better Auth's generate/verify registration and
authentication routes, plus list, rename, and delete. WebAuthn challenges are
represented in the browser by a secure `__Host-` cookie, stored only as a hash,
and atomically consumed. See the [passkey guide](./docs/passkeys.md) and
[ADR 0004](./docs/adr/0004-passkeys-webauthn.md).

## Two-factor authentication

Two-factor authentication is an isolated server plugin:

```go
import "github.com/eadwinCode/better-auth-go/plugin/twofactor"

cipher, err := betterauth.NewAESGCMTokenCipher(twoFactorKey)
if err != nil {
	return err
}
twoFactor, err := twofactor.New(twofactor.Config{
	Issuer: "Example",
	Cipher: cipher,
	DeliverOTP: func(
		ctx *betterauth.HookContext,
		user betterauth.User,
		code string,
	) error {
		return deliverOTP(ctx.Context, user, code)
	},
})
if err != nil {
	return err
}
config.Plugins = append(config.Plugins, twoFactor)
```

The plugin provides Better Auth's enable/disable, TOTP, delivered OTP, backup
code, trusted-device, and credential-sign-in challenge flows. Secret material
is encrypted, opaque challenge/device values are hash-only at rest, and the
first-factor session is revoked before a 2FA redirect is returned. See the
[2FA guide](./docs/two-factor.md) and
[ADR 0005](./docs/adr/0005-two-factor-authentication.md).

## Server plugins and hooks

`Config.Plugins` provides the Better Auth-style server extension lifecycle:
plugin initialization and dependencies, schema, exact and parameterized
endpoints, endpoint and route middleware, before/after hooks, global
`OnRequest`/`OnResponse`, trusted origins, rate-limit rules, database hooks, and
background tasks. `Config.Hooks` provides the same global lifecycle for
application-owned customization without manufacturing a plugin.

```go
auditPlugin := betterauth.Plugin{
	ID: "audit",
	TrustedOrigins: []string{"https://admin.example.com"},
	Endpoints: []betterauth.PluginEndpoint{{
		Name: "get-event",
		Path: "/audit/events/:id",
		Method: http.MethodGet,
		QueryValidator: betterauth.ObjectValidator{
			Fields: map[string]betterauth.FieldValidation{
				"expand": {Kind: betterauth.ValidationBoolean},
			},
		},
		Use: []betterauth.RequestHook{betterauth.SessionMiddleware},
		Handler: func(ctx *betterauth.HookContext) (*betterauth.PluginResponse, error) {
			return betterauth.JSONResponse(http.StatusOK, map[string]string{
				"id": ctx.Params["id"],
			})
		},
	}},
	OnResponse: func(ctx *betterauth.HookContext, response *betterauth.PluginResponse) error {
		response.Headers.Set("X-Auth-Plugin", ctx.PluginID)
		return nil
	},
}
config.Plugins = []betterauth.Plugin{auditPlugin}
```

For state-changing API requests, trusted-origin enforcement runs before plugin
code. Plugins may contribute exact origins but cannot expand policy from request
data or remove mandatory no-store/security headers. Protocol endpoints that
authenticate without browser credentials may use an explicit construction-time
origin exception; this does not bypass their middleware, validators, hooks,
rate limits, or response hooks. Plugin descriptors are copied during `New`;
callbacks must be concurrency-safe and must not retain request-scoped
`HookContext` values. Plugin cookies can be appended with
`PluginResponse.SetCookie`, which enforces Secure, HttpOnly, SameSite, host-only
`__Host-` cookies. Cookie-authenticated mutation endpoints should use both
`SessionMiddleware` and `CSRFMiddleware`; origin enforcement remains mandatory
independently.
Endpoint `BodyValidator` and `QueryValidator` declarations run after
`OnRequest` and rate limiting but before middleware, before-hooks, and endpoint
code. `ObjectValidator` is dependency-free; `EndpointValidatorFunc` can bridge
an application's existing validation package.
The default background runner waits inline; inject `Config.BackgroundTasks`
when work should be handed to a durable asynchronous queue.

See [ADR 0002](./docs/adr/0002-plugin-kernel.md) and the
[plugin compatibility checklist](./docs/compatibility/plugin-kernel.md). The
[feature gap register](./docs/compatibility/missing-features.md) separately
tracks endpoint-contract deltas and every built-in plugin family so kernel
support is never reported as feature parity.

## Database adapters

The `DatabaseAdapter` API maps Better Auth's adapter operations:

`Create`, `FindOne`, `FindMany`, `Count`, `Update`, `UpdateMany`, `Delete`,
`DeleteMany`, `ConsumeOne`, `IncrementOne`, and `Transaction`.

Adapters declare value, ID, join, and transaction capabilities. The schema
wrapper maps logical model/field names and transforms JSON, dates, booleans, and
arrays when the database lacks native types. Run the public conformance suite:

```go
func TestAdapter(t *testing.T) {
	adaptertest.Run(t, func(t *testing.T) betterauth.DatabaseAdapter {
		return newYourAdapter(t)
	})
}
```

MongoDB uses native `findOneAndDelete`, guarded `findOneAndUpdate`, unique/TTL
indexes, and transactions. Multi-document core flows require a replica set or
sharded cluster.

PostgreSQL and SQLite use the shared `database/sql` implementation. The
application owns the driver and connection pool. Migration is explicit and
additive:

```go
database, err := sql.Open("sqlite", sqliteDSN) // import your chosen driver
if err != nil {
	return err
}
adapter, err := sqlite.New(database)
if err != nil {
	return err
}
config.Database = adapter
auth, err := betterauth.New(config)
if err != nil {
	return err
}
if err := adapter.Migrate(ctx, auth.Schema()); err != nil {
	return err
}
```

Use `adapter/postgresql.New` with a PostgreSQL `*sql.DB`. `Migrate` runs in a
transaction, creates missing tables/indexes, adds missing nullable columns, and
never drops data. A newly required column on a populated table fails closed so
the application can perform an explicit backfill migration.

Email change and user deletion are disabled until
`Config.User.ChangeEmailEnabled` and `Config.User.DeleteUserEnabled` are set.
The former verifies the new inbox with a single-use token; credential-user
deletion requires password reauthentication.

## Password migration

Argon2id is canonical for new passwords. To import Better Auth scrypt records,
implement `PasswordVerifier` as a bridge:

1. recognize and verify the legacy format with strict parameter bounds;
2. return `PasswordVerification{Valid: true, ReplacementHash: argonHash}`;
3. let sign-in atomically replace the old hash.

Legacy compatibility is opt-in; new records are never written in the legacy
format.

## Security model

Read [`SECURITY.md`](./SECURITY.md) and
[`docs/adr/0001-auth-server-architecture.md`](./docs/adr/0001-auth-server-architecture.md)
before deploying. Important operational requirements:

- terminate TLS before requests reach the application;
- preserve `Secure` and `__Host-` cookie rules;
- configure exact trusted origins and redirect URLs;
- do not enable proxy-header trust unless a trusted proxy overwrites them;
- keep provider-token encryption keys outside source control and rotate through
  an application key-ring implementation;
- run MongoDB as a replica set or sharded cluster;
- treat mail links, OAuth codes, cookies, and raw tokens as secrets;
- consume outbox events idempotently.

## Compatibility and roadmap

- [Better Auth v1.6 compatibility matrix](./docs/compatibility/better-auth-v1.6.md)
- [Implementation plan](./IMPLEMENTATION_PLAN.md)
- [Architecture decision record](./docs/adr/0001-auth-server-architecture.md)
- [Plugin-kernel decision record](./docs/adr/0002-plugin-kernel.md)
- [Management, validation, and SQL decision record](./docs/adr/0003-core-management-validation-and-sql.md)
- [Passkey/WebAuthn decision record](./docs/adr/0004-passkeys-webauthn.md)
- [Two-factor authentication decision record](./docs/adr/0005-two-factor-authentication.md)
- [Organizations decision record](./docs/adr/0006-organizations.md)
- [Organizations integration guide](./docs/organizations.md)
- [Enterprise SSO decision record](./docs/adr/0007-enterprise-sso.md)
- [Enterprise SSO integration status](./docs/sso.md)
- [SCIM provisioning decision record](./docs/adr/0008-scim-provisioning.md)
- [SCIM integration status](./docs/scim.md)
- [Changelog](./CHANGELOG.md)

The server plugin kernel, passkeys, two-factor authentication, and organizations
are implemented. Enterprise SSO and SCIM have isolated security/schema
foundations under active development. Username, magic links, API keys, and
other feature plugins remain separate compatibility milestones with their own
threat models.

## License

MIT
