# Better Auth 1.6.25 TypeScript oracle

This test-only Bun server pins the published `better-auth@1.6.25` package for
Go-versus-TypeScript HTTP differential tests. It is not a production service.

`scripts/test-typescript-compat.sh` creates an isolated SQLite database, runs
the migration, starts this server on loopback, and executes the Go
compatibility suite. Successful recovery and verification flows use an
authenticated test-control endpoint to inspect messages captured by the
in-memory mail callbacks. The endpoint is outside the Better Auth base path,
requires `BETTER_AUTH_TEST_CONTROL_SECRET`, and exists only in this fixture.

Install dependencies with:

```sh
bun install --frozen-lockfile
```
