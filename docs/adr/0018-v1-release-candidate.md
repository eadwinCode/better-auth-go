# ADR 0018: v1 release-candidate certification and stability boundary

- Status: Accepted
- Date: 2026-07-29
- Better Auth reference: `better-auth` v1.6.25
- Scope: the release-candidate PR following PR #21

## Context

The core authentication server, social-provider catalog, generic OAuth/OIDC
consumer, and first-party database adapters now have deterministic security,
compatibility, race, fuzz, and migration evidence. The repository does not yet
have a release-candidate workflow that repeats all of that evidence from a
clean checkout before a tag can publish.

The SSO and SCIM packages have substantial implementations and black-box
security fixtures. They do not yet have pinned Better Auth cross-runtime
coverage or live interoperability evidence across representative enterprise
identity providers and directories. Treating those packages as v1-stable would
therefore promise more than the reproducible evidence supports.

As a Go library, the release artifact is primarily the versioned module fetched
through the Go module proxy. Release archives are still useful for offline
review and software-supply-chain policy, but they must identify their source
tag, carry checksums, and have verifiable signed provenance.

## Decision

### v1 stability boundary

The v1 compatibility guarantee covers:

- the root `betterauth` package and its documented public HTTP/security
  contract;
- the generic adapter contract and adapter conformance helpers;
- the MongoDB, PostgreSQL, and SQLite adapter packages;
- the 35 deterministic social-provider presets and generic OAuth/OIDC consumer
  API, subject to documented provider-operated interoperability limits.

The feature packages under `plugin/`, including SSO and SCIM, remain
**experimental** for the first v1 release. They continue to run in ordinary and
release-candidate CI, but their public APIs and wire behavior are outside the
v1 compatibility guarantee until each package has its own promotion ADR,
pinned differential evidence, and required live interoperability evidence.
Experimental does not mean insecure or abandoned; it means that production
support and semantic-compatibility promises have not been certified.

### Release-candidate gates

Add a reusable release-certification workflow and invoke it from pull-request
CI and the tag release workflow. It must start from `actions/checkout`, avoid
developer-machine state, and run:

1. formatting, unit/black-box tests, vet, race, staticcheck, and vulnerability
   analysis;
2. every committed fuzz target for a bounded smoke interval;
3. the pinned Better Auth 1.6.25 source inventory and TypeScript differential
   suite;
4. SQLite migrations and real PostgreSQL 17/MongoDB 8 replica-set migrations,
   conformance, and race tests;
5. SSO and SCIM deterministic protocol/security suites despite their
   experimental stability status;
6. an external-module installation check using the candidate commit on pull
   requests and the exact semantic tag during a release.

The workflow must fail if tests silently skip a required real database. Service
credentials used by CI are test-only and never become release artifacts.

### Versioned, attested release artifacts

Only an existing tag matching `vMAJOR.MINOR.PATCH` or
`vMAJOR.MINOR.PATCH-rc.N` may publish. The release workflow:

- completes the reusable certification workflow using the exact tag;
- verifies that the tag resolves to the checked-out commit;
- creates version-named source `tar.gz` and `zip` archives from `git archive`;
- creates SHA-256 checksums and an SPDX JSON software bill of materials;
- generates a Sigstore-backed signed GitHub build-provenance attestation for
  the archives and checksum file;
- creates a GitHub prerelease for `-rc.N` tags and a normal release otherwise;
- uploads the archives, checksums, and SBOM before publishing the GitHub
  release; repository immutable-release protection should be enabled so the
  published tag and assets cannot later be replaced.

Consumers verify archive checksums locally and provenance with
`gh attestation verify ... --repo eadwinCode/better-auth-go`.

### Operational documentation

Add one production operations guide covering:

- TLS termination, trusted proxy headers, host-only cookies, origin and CSRF
  policy;
- database backup/restore and restore drills;
- application secrets, provider-token encryption keys, and rotation through a
  multi-key `TokenCipher`;
- schema migration ordering, rolling deployments, rollback limits, and
  release-to-release upgrades;
- release artifact and module verification.

The guide must distinguish library invariants from application/operator
responsibilities and must not imply that experimental plugins are v1-stable.

## Consequences

The first v1 release can make a precise stability promise without deleting or
freezing the SSO and SCIM implementations prematurely. Applications may still
evaluate those packages, but must pin versions, run interoperability tests, and
accept possible breaking changes until promotion.

Merging this PR prepares the repository for `v1.0.0-rc.1`; it does not itself
create the tag or prove the tag-triggered publication path. The release is
production-stable only after the candidate tag completes every gate and the
published artifacts and attestations are independently verified.
