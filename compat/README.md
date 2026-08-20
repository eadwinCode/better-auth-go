# Better Auth compatibility tests

This directory owns the external black-box and differential Go tests against
the pinned Better Auth TypeScript oracle in `typescript-oracle/`.

- Run the complete differential suite with
  `scripts/test-typescript-compat.sh`.
- Run only the Go package without an oracle with `go test ./compat`; tests that
  require the oracle skip unless `BETTER_AUTH_TS_URL` and
  `BETTER_AUTH_TS_CONTROL_SECRET` are set.
- Provider preset implementation tests remain beside the `social` package
  because they intentionally exercise package-private provider contracts.

The tests characterize the active Better Auth v1.7.0 migration target. The
certified stable baseline remains v1.6.26. Deliberate security differences
are asserted explicitly instead of being normalized away.
