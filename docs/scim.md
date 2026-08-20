# SCIM 2.0 provisioning

> **Experimental:** `plugin/scim` is not included in the better-auth-go v1
> compatibility or production-support guarantee. Pin an exact version and run
> interoperability tests against every directory before deployment. See
> [Versioning and stability](./versioning.md).

The `plugin/scim` package is an inbound directory-provisioning service aligned
with `@better-auth/scim` v1.6.25, RFC 7643, and RFC 7644. It is independent of
the SSO plugin and mounts through the same standard `net/http` handler as the
core authentication server.

## Implemented contract

Management routes, relative to the configured authentication base path:

- `POST /scim/generate-token`
- `GET /scim/list-provider-connections`
- `GET /scim/get-provider-connection`
- `POST /scim/delete-provider-connection`

SCIM routes:

- `POST|GET /scim/v2/Users`
- `GET|PUT|PATCH|DELETE /scim/v2/Users/:userId`
- `GET /scim/v2/ServiceProviderConfig`
- `GET /scim/v2/Schemas`
- `GET /scim/v2/Schemas/:schemaId`
- `GET /scim/v2/ResourceTypes`
- `GET /scim/v2/ResourceTypes/:resourceTypeId`

The runtime includes bounded pagination and equality filters, User resource
mapping, PUT replacement, bounded `add`/`replace`/`remove` PATCH operations,
deactivation with session revocation, personal and organization-safe
deprovisioning, lifecycle hooks, and durable audit events.

## Construction

```go
scimPlugin, err := scim.New(scim.Config{
	ProviderOwnership: true,
	CanGenerateToken: func(
		ctx *betterauth.HookContext,
		providerID string,
		organizationID string,
	) (bool, error) {
		return applicationPolicyAllows(ctx, providerID, organizationID), nil
	},
})
if err != nil {
	log.Fatal(err)
}
```

Add the resulting plugin to `betterauth.Config.Plugins`. Token generation is a
fresh-session mutation and requires trusted origin plus the core double-submit
CSRF token.

Organization-scoped connections additionally require an
`OrganizationAuthorizer`. The port owns organization role checks and bounded
membership provisioning/removal without coupling SCIM to a particular
organization plugin implementation. Membership mutation callbacks receive a
request copy whose `Database` is the active provisioning transaction and must
use that adapter for their writes. Implement `OrganizationRoleAuthorizer` when
the port should receive the normalized `RequiredRoles` list directly; the base
port remains available when the application already encapsulates that policy.

## Bearer and ownership boundary

Raw bearer tokens are returned once. Persistence stores only a fixed SHA-256
hash of the random secret. Rotation replaces the hash atomically and invalidates
the previous token; connection deletion invalidates the token immediately.

`/scim/v2/Users` accepts `application/scim+json` and `application/json`.
Protocol routes use bearer authentication and are the only unsafe SCIM routes
allowed to skip browser-origin checks. Their middleware, endpoint validators,
rate limits, hooks, request-size limit, and response hooks still run.

Every managed User must have a core account row for the authenticated SCIM
connection. Core account provider IDs use the internal
`scim:<connection-id>` namespace rather than the public SCIM provider ID. This
allows SSO and SCIM to reuse a public identifier without sharing account rows.
A matching global email is never enough to grant management access.
Existing-user linking is disabled by default and fails closed unless explicit
domain, membership, or application policy is configured.

Existing installations upgrading from the public-provider-ID account layout
must explicitly backfill each SCIM account row to `scim:<connection-id>` before
serving traffic. Automatic legacy fallback is intentionally not provided
because an equal SSO provider ID makes ownership ambiguous.

Ingress accepts exact `true` and `false` string values case-insensitively for
User `active` and the `primary` field on emails, phone numbers, addresses,
roles, and entitlements. Values with surrounding whitespace and other truthy
forms remain invalid.

Organization deprovisioning removes only that membership and SCIM account link;
it never deletes the global user. Personal deprovisioning deletes the global
user only when the SCIM identity is the user's sole account.

## Deterministic fixtures

`DefaultConnections` exists for migration and protocol fixtures. It accepts
only pre-hashed secrets:

```go
secret := "fixture-secret-with-sufficient-entropy"
raw := base64.RawURLEncoding.EncodeToString([]byte(secret + ":directory"))
plugin, _ := scim.New(scim.Config{
	DefaultConnections: []scim.DefaultConnection{{
		ProviderID: "directory",
		TokenHash:  betterauth.HashToken(secret),
	}},
})
```

Applications should use the management route for production token issuance.
The token encoder remains package-private; external tests should capture the
one-time value returned by `POST /scim/generate-token`.

## Verification

Committed tests cover connection issuance/rotation/deletion, owner isolation,
hash-only storage, bearer failure equivalence, media types, complete User
lifecycle, filters, pagination, PUT/PATCH, deactivation/session revocation,
organization-safe deprovisioning, audit durability, and fuzz targets for
bearer, filter, and patch parsing.

Live enterprise-directory interoperability and a pinned TypeScript differential
suite remain promotion gates. Until they pass, the package remains experimental
even though its deterministic security suite is part of release-candidate CI.
See [ADR 0008](./adr/0008-scim-provisioning.md) for the security contract.
