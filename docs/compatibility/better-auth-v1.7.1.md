# Better Auth v1.7.1 security and interoperability overlay

This document records the focused Better Auth v1.7.1 migration applied on top
of the repository's broader v1.7.0 migration and certified v1.6.26 baseline.
It does not expand the explicit deferrals in the v1.7 migration contract.

Primary upstream references, reviewed on 2026-08-20:

- [Better Auth v1.7.1 release notes](https://github.com/better-auth/better-auth/releases/tag/v1.7.1)
- [Better Auth v1.7.0...v1.7.1 comparison](https://github.com/better-auth/better-auth/compare/v1.7.0...v1.7.1)

## Implemented scope

| Upstream behavior | Go status | Evidence |
| --- | --- | --- |
| Verify SAML assertion signatures against raw XML | implemented | exact incoming assertion element is structurally selected and verified before `crewjam/saml` unmarshalling |
| Enforce assertion-signing policy | implemented | response-only signatures are accepted only when `WantAssertionsSigned` is false; present assertion signatures are always verified |
| Prevent SAML signature wrapping | implemented | protocol root, direct-child position, a single assertion, a single direct XMLDSig signature, and authenticated assertion ID are required |
| Bound and accurately advertise SP metadata | implemented | serialized metadata is capped by `MaxMetadataSize`; `AuthnRequestsSigned` and `WantAssertionsSigned` reflect configuration |
| Parse SCIM Boolean strings case-insensitively | implemented | exact `true`/`false` strings are normalized for User `active` and `primary` on emails, phone numbers, addresses, roles, and entitlements, including PATCH forms |
| Separate SCIM IDs from SSO provider IDs | implemented | connection-scoped `scimUser` bindings are separate from authentication accounts, so equal public SCIM and SSO provider IDs cannot share identity rows |
| Require native database transactions | implemented | server construction rejects adapters without transaction capability; adapter conformance verifies rollback |
| Refuse unsafe required-column additions | implemented | SQL migration preflights the entire schema and rejects required/no-default additions to populated tables before DDL; static defaults and reviewed external backfills remain possible |

Tests cover SAML response-only/assertion-only/both-signed policy combinations,
signature wrapping, foreign-namespace signature decoys, malformed XML,
oversized metadata, every SCIM Boolean location, transaction rollback, and SQL
migration refusal/backfill/rollback.

## Deferred compatibility work

### SCIM managed connections and credential lifecycle

Better Auth 1.7 adds an optional managed-connection catalog with server-only
credential create, rotate, and revoke APIs plus terminal connection binding
during dynamic decommissioning. This repository now has connection-scoped
`scimUser` bindings, but still uses one hash-only bearer credential per
connection and session-authorized browser management endpoints. Adding
lookalike APIs would duplicate the remaining upstream client/config and
credential architecture and make later migration less safe.

The dependency is explicit: port the remaining server-only credential catalog,
terminal binding, native group/provisioning-domain, and tombstone behavior as a
reviewed SCIM workstream. Until then, deployments must not claim those surfaces
or first-request dynamic decommission behavior.

### OAuth provider insufficient-scope challenges

The Go repository implements OAuth/OIDC clients for social login and enterprise
SSO, but it does not implement Better Auth's OAuth authorization/resource
server provider. RFC 6750 `403 insufficient_scope` challenges listing all
missing scopes therefore have no applicable request path yet. This behavior is
required when the OAuth provider package is introduced.

### Dependency refreshes

No TypeScript-only dependency churn was ported. Existing Go XML and database
dependencies already provide the primitives required for the protocol and
migration changes in this overlay.

## Rollout notes

1. Follow the v1.7 SCIM cutover in `docs/migrations/better-auth-1.7.md` and fully
   reprovision the directory into `scimUser` bindings. Do not translate legacy
   authentication-account provisioning state in place.
2. Fetch SP metadata after rollout and confirm the IdP sees the intended
   `WantAssertionsSigned` and `AuthnRequestsSigned` values.
3. Providers configured with `WantAssertionsSigned=true` must sign the
   assertion itself; a signed response containing an unsigned assertion is now
   rejected.
4. Review every newly required SQL field. Supply a static `DefaultValue`, run a
   separately reviewed backfill before migration, or leave the field nullable
   until the backfill is complete.
5. Run the SSO, SCIM, adapter, migration, race, and full suites against the
   deployment's production database driver before promotion.
