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
- Better Auth's 35 built-in social-provider IDs plus generic OAuth2/OIDC;
- authorization-gated, one-hour maximum admin impersonation with durable audit;
- Argon2id password hashes and an injected migration verifier for legacy scrypt;
- opaque 256-bit session tokens with only SHA-256 hashes persisted;
- concurrency-safe in-process session resolution for application handlers,
  without HTTP or JSON loopback;
- host-only `__Host-` Secure HttpOnly SameSite cookies;
- exact, bounded wildcard, or request-resolved trusted-origin policy; CSRF,
  callback allowlist, request-size, and rate-limit enforcement;
- Better Auth-aligned generic database adapters, schema extensions, model/field
  mappings, transactions, atomic consume, and guarded increments;
- MongoDB, PostgreSQL, SQLite, a public adapter conformance suite, and an
  in-memory development adapter.
- an opt-in Better Auth-shaped passkey/WebAuthn plugin with hash-at-rest,
  single-use challenges and fixation-safe core session rotation;
- an opt-in Better Auth-shaped 2FA plugin with encrypted TOTP/backup material,
  delivered OTP, trusted devices, shared attempt budgets, and durable lockout.

The v1 stability guarantee covers the core server and first-party MongoDB,
PostgreSQL, and SQLite adapters. Packages below `plugin/`, including SSO and
SCIM, remain experimental and outside that guarantee. Review
[Versioning and stability](./docs/versioning.md), the compatibility matrix, and
the changelog before upgrading.

The pinned cross-runtime suite is reproducible from this repository:

```bash
cd compat/typescript-oracle
bun install --frozen-lockfile
cd ../..
scripts/test-typescript-compat.sh
```

## Install

```bash
go get github.com/eadwinCode/better-auth-go
```

Production deployments should pin an exact released tag. The release workflow
tests installation from an external module without a local `replace` directive.

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

## Resolving sessions in application handlers

Use `ResolveSession` when an application route needs the current identity
without an HTTP/JSON call back into the auth handler:

```go
result, err := auth.ResolveSession(r.Context(), r)
switch {
case errors.Is(err, betterauth.ErrNoSession):
	http.Error(w, "authentication required", http.StatusUnauthorized)
	return
case err != nil:
	http.Error(w, "service unavailable", http.StatusServiceUnavailable)
	return
}
user := result.User
session := result.Session
```

The method uses the configured session-cookie name and is safe for concurrent
requests. Missing, invalid, expired, or revoked sessions and disabled users
match `ErrNoSession`; database and adapter failures remain distinct. It is a
read-only resolver and does not run HTTP hooks, CSRF/origin policy, rotate
sessions, set cookies, or return the raw token. See
[In-process session resolution](./docs/session-resolution.md) for the full API
and error contract.

## Email and password options

The production-sensitive Better Auth v1.6 options are grouped under
`Config.EmailPassword`:

```go
autoSignIn := false
config.EmailPassword = betterauth.EmailPasswordConfig{
	DisableSignUp:                 false,
	AutoSignIn:                    &autoSignIn,
	RequireEmailVerification:      true,
	RevokeSessionsOnPasswordReset: true,
}
```

`AutoSignIn` is optional so its omitted value can preserve Better Auth's
`true` default. Requiring verification or disabling automatic sign-in produces
a sessionless signup and enables synthetic duplicate responses that do not
reveal whether the email already exists. Required verification sends the
configured mailer's single-use verification message and blocks credential
sign-in until it is consumed.

Password reset does not sign in the reset browser. Better Auth's compatible
default preserves existing sessions; set `RevokeSessionsOnPasswordReset` when a
reset must terminate every device. Passwords default to 8–128 bytes, and reset
and verification tokens default to a one-hour lifetime. Applications can
override the existing `MinPasswordBytes`, `MaxPasswordBytes`,
`PasswordResetTTL`, and `EmailVerificationTTL` fields.

Accounts whose upstream identity has no deliverable email can use
`CreatePlaceholderEmail` to derive a deterministic, namespaced address under
the reserved `placeholder.invalid` domain. The function validates both
components and never produces a routable address.

The remaining Better Auth 1.6 lifecycle callbacks and delivery modes are
available through `Config.EmailVerification`, `Config.EmailPassword`, and
`Config.User`:

```go
sendOnSignUp := true
config.EmailVerification = betterauth.EmailVerificationConfig{
	SendOnSignUp:                &sendOnSignUp,
	SendOnSignIn:                true,
	AutoSignInAfterVerification: true,
	BeforeVerification:          beforeVerification,
	AfterVerification:           afterVerification,
}
config.EmailPassword.OnPasswordReset = onPasswordReset
config.EmailPassword.OnExistingUserSignUp = onExistingUserSignUp
config.EmailPassword.CustomSyntheticUser = syntheticUserFactory
config.User.SendChangeEmailConfirmation = true
config.User.UpdateEmailWithoutVerification = false
```

`SendOnSignUp` is tri-state: when omitted, it follows
`RequireEmailVerification`. Existing-user signup callbacks run through the
configured background-task runner and never alter the synthetic,
enumeration-resistant response. Change-email confirmation sends first to the
verified old inbox and only then sends the single-use verification link to the
new inbox.

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

Generic OIDC providers use discovery:

```go
enterprise, err := social.NewOIDC(ctx, "enterprise-oidc", social.Options{
	ClientID:     os.Getenv("OIDC_CLIENT_ID"),
	ClientSecret: os.Getenv("OIDC_CLIENT_SECRET"),
	Issuer:       "https://identity.example.com",
})
```

Discovery pins the returned issuer, validates authorization/token/user-info/
JWKS endpoints, requires authorization-code and RS256 support when advertised,
rejects redirects and private literal endpoints, and applies the same timeout
and response-size limits as preset providers.

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
code. Plugins may contribute exact or HTTPS hostname-pattern origins. Applications
may inject a request-scoped `TrustedOriginResolver` for bounded multi-tenant
policy; its static and dynamic results are additive, pass the same validation,
and fail closed on errors or panics. Resolver implementations must not trust
unvalidated `Host` or forwarding headers. Neither plugins nor response hooks can
remove mandatory no-store/security headers. Protocol endpoints that
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
Wildcard origins allow `*` and `?` only in an HTTPS hostname, for example
`https://*.example.com`; paths, credentials, wildcard ports, IP patterns, and
public-suffix patterns are rejected. Exact HTTP origins remain restricted to
loopback development addresses.
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
deletion requires password reauthentication. Setting
`Config.User.SendDeleteAccountVerification` makes deletion send an
`account-deletion` mail with a single-use callback token instead. Applications
may use `Config.User.BeforeDelete` and `Config.User.AfterDelete` for lifecycle
work; the before hook can stop deletion, while the after hook runs only after
the account and authentication records have been durably removed.

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
- prefer exact trusted origins and configure exact redirect URLs; keep any
  wildcard or request-resolved origin policy tenant-bound and narrow;
- do not enable proxy-header trust unless a trusted proxy overwrites them;
- keep provider-token encryption keys outside source control and rotate through
  an application key-ring implementation;
- run MongoDB as a replica set or sharded cluster;
- treat mail links, OAuth codes, cookies, and raw tokens as secrets;
- consume outbox events idempotently.

The complete deployment, backup/restore, proxy/cookie, key-rotation, and upgrade
runbook is in [Production operations](./docs/production-operations.md).

## Compatibility and roadmap

- [Better Auth v1.6 compatibility matrix](./docs/compatibility/better-auth-v1.6.md)
- [Better Auth v1.6.26 production progress](./PROGRESS.md)
- [Versioning and stability](./docs/versioning.md)
- [In-process session resolution](./docs/session-resolution.md)
- [Production operations](./docs/production-operations.md)
- [Implementation plan](./IMPLEMENTATION_PLAN.md)
- [Architecture decision record](./docs/adr/0001-auth-server-architecture.md)
- [Plugin-kernel decision record](./docs/adr/0002-plugin-kernel.md)
- [Management, validation, and SQL decision record](./docs/adr/0003-core-management-validation-and-sql.md)
- [Passkey/WebAuthn decision record](./docs/adr/0004-passkeys-webauthn.md)
- [Two-factor authentication decision record](./docs/adr/0005-two-factor-authentication.md)
- [v1 release-candidate decision record](./docs/adr/0018-v1-release-candidate.md)
- [In-process session-resolution decision record](./docs/adr/0019-in-process-session-resolution.md)
- [Organizations decision record](./docs/adr/0006-organizations.md)
- [Organizations integration guide](./docs/organizations.md)
- [Enterprise SSO decision record](./docs/adr/0007-enterprise-sso.md)
- [Enterprise SSO integration status](./docs/sso.md)
- [SCIM provisioning decision record](./docs/adr/0008-scim-provisioning.md)
- [SCIM integration status](./docs/scim.md)
- [Changelog](./CHANGELOG.md)

The stable server plugin kernel and experimental passkey, two-factor,
organization, enterprise SSO, and SCIM feature packages are implemented.
Username, magic links, API keys, and other feature plugins remain separate
compatibility milestones with their own threat models.

## License

MIT
