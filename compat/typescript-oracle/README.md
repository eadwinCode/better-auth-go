# Better Auth 1.7.7 TypeScript oracle

This test-only Bun server pins the published `better-auth@1.7.7` package for
Go-versus-TypeScript HTTP differential tests. It is not a production service.

`scripts/test-typescript-compat.sh` creates an isolated SQLite database, runs
the migration, starts this server on loopback, and executes the Go
compatibility suite. Successful recovery and verification flows use an
authenticated test-control endpoint to inspect messages captured by the
in-memory mail callbacks. The endpoint is outside the Better Auth base path,
requires `BETTER_AUTH_TEST_CONTROL_SECRET`, and exists only in this fixture.
The pinned admin and generic OAuth plugins are also enabled. A
credential-protected loopback token endpoint supports public account-linking,
provider-token, and impersonation differential flows without external calls.
The fixture also mounts a second auth instance at `/api/auth-delete` with
`sendDeleteAccountVerification` enabled so direct and verified account
deletion can be characterized independently.
One-time-token instances are mounted at `/api/auth-ott` and
`/api/auth-ott-<option>`. Each enables the pinned `oneTimeToken` plugin with
one option, so every option's HTTP effect is compared on its own. The
`-ott-short-token` and `-ott-short-session` instances use one- and two-second
lifetimes so expiry can be observed without fake timers.

Install dependencies with:

```sh
bun install --frozen-lockfile
```
