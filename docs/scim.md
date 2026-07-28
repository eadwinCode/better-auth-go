# SCIM 2.0 provisioning

The `plugin/scim` package is the isolated inbound directory-provisioning
integration aligned with `@better-auth/scim` v1.6.25, RFC 7643, and RFC 7644.

## Current foundation

The current branch implements:

- adapter-independent `scimProvider` schema with unique provider IDs and
  hash-only bearer credentials;
- personal ownership and organization authorization/provisioning ports;
- bounded provider, role, linking, bearer, filter, patch, and pagination
  configuration;
- Better Auth-compatible bearer token wire parsing with constant-time stored
  hash comparison;
- collision-safe default connection fixtures that accept only pre-hashed
  tokens;
- bounded SCIM equality-filter parsing that maps only allowlisted paths to
  logical adapter fields;
- standard ServiceProviderConfig, Schema, and ResourceType endpoints using
  `application/scim+json`;
- plugin-kernel PUT, PATCH, and DELETE support with trusted-origin enforcement
  for every unsafe method;
- explicit standards-path and bearer-origin exceptions without bypassing
  middleware, validation, hooks, or rate limiting.

Connection management and User provisioning endpoints remain release-gated on
this branch. Applications must not treat the metadata/schema foundation as a
complete SCIM service.

## Construction

```go
scimPlugin, err := scim.New(scim.Config{
	ProviderOwnership: true,
})
if err != nil {
	log.Fatal(err)
}
```

Organization-scoped default connections require an `OrganizationAuthorizer`.
Raw default tokens are rejected; deterministic fixtures must supply
`betterauth.HashToken(secret)`.

## Protocol boundary

The eventual `/scim/v2/Users` routes authenticate with a SCIM bearer token, not
a browser session. Those endpoints explicitly skip browser origin checks while
still running token middleware, validators, hooks, rate limits, and response
hooks. Session-authenticated management routes continue to require trusted
origin, CSRF, and a fresh session.

See [ADR 0008](./adr/0008-scim-provisioning.md) for the full token, ownership,
linking, deactivation, deprovisioning, and cross-tenant security contract.
