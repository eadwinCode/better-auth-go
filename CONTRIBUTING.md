# Contributing

## Development

Requirements:

- Go 1.25 or newer (release validation uses the pinned Go 1.26.5 toolchain);
- MongoDB replica set for integration tests;
- `staticcheck` and `govulncheck` for release validation.

Run:

```bash
gofmt -w .
go test ./...
go vet ./...
go test -race ./...
govulncheck ./...
staticcheck ./...
```

Set `MONGODB_URI` to include the MongoDB adapter integration/conformance suite.
Without it, those tests skip explicitly.

## Design changes

Changes to route names, cookie/token formats, adapter methods, core schemas,
provider IDs, account-linking behavior, or cryptographic defaults require an ADR
and compatibility-matrix update.

Every adapter must pass `adaptertest.Run`. Every provider change needs:

- authorization URL fixture;
- token exchange fixture;
- profile/verified-email fixture;
- provider-error and oversized-response cases;
- ID-token/JWKS fixtures where applicable.

## Commits and pull requests

Keep commits intentional and independently reviewable. Pull requests must state:

- the security invariant or compatibility behavior changed;
- user/developer impact;
- checks run;
- any upstream Better Auth version/commit consulted;
- any deliberate compatibility difference.
