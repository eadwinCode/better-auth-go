# better-auth-go

`better-auth-go` is an embeddable authentication server library for Go. It owns
authentication state and exposes a standard `net/http` handler; it is not a
client SDK and does not require a Node or Bun service.

The public server and adapter contracts track Better Auth TypeScript v1.6 while
using native Go security defaults:

- Better Auth-compatible core route names under `/api/auth`;
- email/password sign-up, sign-in, sign-out, sessions, rotation, and revocation;
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
- MongoDB, a public adapter conformance suite, and an in-memory development
  adapter.

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
	if err := database.EnsureCoreIndexes(ctx); err != nil {
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
code. Plugins may contribute exact origins but cannot bypass a failed check or
remove mandatory no-store/security headers. Plugin descriptors are copied
during `New`; callbacks must be concurrency-safe and must not retain
request-scoped `HookContext` values. Plugin cookies can be appended with
`PluginResponse.SetCookie`, which enforces Secure, HttpOnly, SameSite,
host-only `__Host-` cookies. Cookie-authenticated mutation endpoints should use
both `SessionMiddleware` and `CSRFMiddleware`; origin enforcement remains
mandatory independently.
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
- [Changelog](./CHANGELOG.md)

The server plugin kernel is implemented. Individual feature plugins—passkeys,
two-factor, organizations, username, magic links, SSO, SCIM, API keys, and
others—remain separate compatibility milestones with their own threat models.

## License

MIT
