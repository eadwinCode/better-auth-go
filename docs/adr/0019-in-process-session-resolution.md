# ADR 0019: In-process session resolution

- Status: Accepted
- Date: 2026-07-29
- Target release: v1.0.1

## Context

Applications embedding `better-auth-go` need the authenticated `Session` and
`User` while serving their own `net/http` routes. In v1.0.0 the only public
path to that state is `GET /api/auth/get-session`, which would force an
in-process application to perform HTTP and JSON loopback.

The existing private resolver intentionally converts every persistence error
into the same public unauthorized error. That is correct for Better
Auth-compatible HTTP responses, but it prevents an embedding application from
distinguishing an unauthenticated request from a database outage.

## Decision

The root package exports:

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

`ResolveSession` reads the configured session-cookie name, hashes the opaque
token exactly as the HTTP server does, and queries the existing server store.
It does not call `Handler`, serialize JSON, mutate the request, rotate the
session, refresh cookies, or run the request hook pipeline.

The method returns `ErrNoSession` when:

- the request or configured cookie is absent;
- the cookie value is empty or outside the accepted bound;
- no matching session or user exists;
- the session is expired or revoked; or
- the user is disabled.

Adapter, database, context, and record-decoding errors are returned as wrapped
errors that do not match `ErrNoSession`. Callers can use `errors.Is` for both
`ErrNoSession` and wrapped adapter sentinels.

The private HTTP adapter continues converting every resolver failure to the
existing generic unauthorized error. Therefore `GET /get-session` still
returns `200 null` for every unavailable session, protected endpoints still
return the existing generic `401`, sign-out stays idempotent, and persistence
causes are never serialized.

`Server` remains immutable after construction. Resolution reads immutable
configuration and delegates through the concurrency-safe adapter contract, so
one server can resolve requests concurrently.

## Consequences

- Embedding applications can authenticate their own handlers without
  HTTP/JSON loopback.
- Applications can map `ErrNoSession` to an anonymous or unauthorized result
  while treating infrastructure failures as availability errors.
- The raw session token remains private and is never returned.
- The v1.0.0 public API and HTTP wire contract remain source- and
  behavior-compatible.
- Request hooks and plugin middleware are deliberately not invoked; callers
  that need the full Better Auth HTTP pipeline must continue using `Handler`.
