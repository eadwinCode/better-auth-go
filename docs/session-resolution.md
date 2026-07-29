# In-process session resolution

Applications embedding `better-auth-go` can resolve the authenticated identity
for their own `net/http` handlers without calling the auth HTTP endpoint:

```go
func requireSession(auth *betterauth.Server, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		result, err := auth.ResolveSession(r.Context(), r)
		switch {
		case errors.Is(err, betterauth.ErrNoSession):
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		case err != nil:
			// Log the internal error through the application's protected
			// telemetry. Do not return database details to the client.
			http.Error(w, "service unavailable", http.StatusServiceUnavailable)
			return
		}

		ctx := context.WithValue(r.Context(), authenticatedUserKey{}, result.User)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
```

The additive public contract is:

```go
var ErrNoSession error

type SessionResult struct {
	Session Session
	User    User
}

func (s *Server) ResolveSession(
	ctx context.Context,
	request *http.Request,
) (SessionResult, error)
```

Pass a non-nil context. The resolver reads `Config.Cookie.Name`, hashes the
opaque cookie value, and loads the existing `Session` and `User`. It returns
`ErrNoSession` for a missing or invalid cookie, an absent session or user, an
expired or revoked session, or a disabled user. Use `errors.Is`; do not compare
error strings.

Database, adapter, context, and record-decoding failures are wrapped and remain
distinct from `ErrNoSession`. This lets an application distinguish an anonymous
request from an authentication-store outage without exposing the underlying
cause.

The method is concurrency-safe and read-only. It does not:

- invoke the auth `Handler` or encode/decode HTTP JSON;
- run HTTP middleware, request hooks, response hooks, CSRF, or trusted-origin
  policy;
- rotate, refresh, revoke, or otherwise mutate the session;
- set cookies; or
- return the opaque cookie token.

The returned `Session` retains all existing public fields, including
`ImpersonatorID` and `ImpersonationID`. Its `TokenHash` is the stored SHA-256
hash, never the raw bearer token.

Use `Handler` when an operation needs the Better Auth HTTP pipeline. In-process
resolution is intended for application authorization after the browser has
already obtained a session through the normal authentication routes.

The HTTP contract is unchanged: `GET /get-session` returns `200 null` when no
session can be resolved, protected core routes return the same generic `401`,
and no resolver cause is serialized.
