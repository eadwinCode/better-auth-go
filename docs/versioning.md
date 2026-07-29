# Versioning and stability

`better-auth-go` follows Semantic Versioning for the public surfaces included in
the declared stability boundary.

## v1 stable boundary

The v1 compatibility guarantee covers:

- the root `github.com/eadwinCode/better-auth-go` package;
- the generic database adapter and adapter-conformance contracts;
- `adapter/mongodb`, `adapter/postgresql`, and `adapter/sqlite`;
- the documented core HTTP routes and security behavior;
- the 35 social-provider presets and generic OAuth/OIDC consumer API, excluding
  behavior controlled independently by provider services.

Within that boundary, incompatible exported API changes, documented wire
contract changes, or persistent-schema changes require a new major version.
Security fixes may deliberately reject inputs that were previously accepted;
such changes are documented in the changelog.

## Experimental packages

All packages below `plugin/` are experimental for the first v1 release,
including passkeys, two-factor authentication, organizations, SSO, and SCIM.
They are compiled, tested, race-checked, fuzzed where applicable, and reviewed
for security, but are not included in the v1 compatibility guarantee.

Experimental packages may have breaking API or wire changes in a v1 minor
release. Applications using them should:

1. pin an exact module version;
2. run their own protocol and interoperability tests before upgrades;
3. read the changelog for every release;
4. avoid exposing a newly upgraded plugin to production before a staged
   rollout.

A plugin becomes stable only through a promotion ADR that identifies its
pinned compatibility matrix, real interoperability evidence, supported
configuration, migration path, and operational ownership. Implementation or
deterministic fixtures alone are not promotion evidence.

## Tags and release candidates

Release tags have one of these forms:

- `vMAJOR.MINOR.PATCH`
- `vMAJOR.MINOR.PATCH-rc.N`

Release candidates are prereleases. They exercise the exact tag-install and
artifact publication path but do not receive the stable compatibility promise.
The first stable release follows only after the candidate gates and upgrade
drill pass.

The Go module path remains `github.com/eadwinCode/better-auth-go` throughout
v1. A future v2 would use Go's `/v2` module suffix.

## Release artifacts

The canonical online installation is the tagged Go module. GitHub releases also
contain versioned source archives, an SPDX JSON SBOM, and SHA-256 checksums.
GitHub Actions signs provenance attestations with a short-lived Sigstore
certificate. Repository maintainers should enable GitHub immutable releases so
published tags and assets cannot be replaced.

After downloading an archive and checksum file:

```bash
sha256sum --check better-auth-go_1.0.0_checksums.txt
gh attestation verify better-auth-go_1.0.0_source.tar.gz \
  --repo eadwinCode/better-auth-go
```

Use `shasum -a 256 -c` instead of `sha256sum --check` on macOS. Verification
must identify this repository as the signer. An archive without a matching
checksum and valid repository attestation is not an official release artifact.

See [ADR 0018](./adr/0018-v1-release-candidate.md) for the release decision.
