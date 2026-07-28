# ADR 0008: SCIM 2.0 provisioning

- Status: Accepted
- Date: 2026-07-28
- Better Auth reference: `@better-auth/scim` v1.6.25
- Protocol references: RFC 7643 and RFC 7644

## Context

`better-auth-go` needs an inbound SCIM 2.0 service for enterprise directory
provisioning. SCIM is not a browser authentication flow: identity providers use
bearer credentials to create, query, update, deactivate, and deprovision users.
Those credentials can manage many accounts, so token issuance, tenant scoping,
resource ownership, and deprovisioning boundaries are high-risk.

Better Auth v1.6.25 exposes personal and organization-scoped SCIM provider
connections, management endpoints, `/scim/v2/Users`, and standard metadata
resources. Its public route and resource shapes are the compatibility target.
The Go implementation keeps stronger native invariants: bearer secrets are
hash-only at rest, external identifiers never grant access to a global user by
themselves, and organization deprovisioning cannot delete a cross-tenant
principal.

## Decision

### Package and branch isolation

SCIM is an opt-in `plugin/scim` package with plugin ID `scim`. It is independent
of SSO: a SCIM connection has its own provider ID and may coexist with any
account provider. It reuses the organization foundation through a narrow
authorization/provisioning port but does not import or depend on the SSO
package.

### Better Auth v1.6 HTTP contract

Management routes relative to the auth base path:

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

The plugin kernel accepts the standard unsafe methods required by SCIM.
Trusted-origin enforcement applies to POST, PUT, PATCH, and DELETE by default.
Only explicitly marked bearer-authenticated SCIM protocol endpoints may skip
browser origin checks; management endpoints never skip them.

### Provider connection schema and tokens

The plugin contributes `scimProvider` with:

- `id`, unique `providerId`, unique `tokenHash`;
- optional `organizationId` and required owner `userId` for personal
  connections;
- `createdAt`, `updatedAt`, `lastUsedAt`, and optional `expiresAt`.

Raw SCIM tokens are returned once. Persistence contains only SHA-256 hashes.
The wire token is a URL-safe base64 encoding of:

`random-secret:providerId[:organizationId]`

The claims select a candidate provider row; the random secret is compared to
the stored hash in constant time. Provider IDs containing `:` or colliding with
credential, built-in, social, SSO, or other account-producing provider IDs are
rejected. Regeneration atomically replaces the prior credential, and deletion
invalidates it immediately.

Default plaintext tokens from Better Auth are not a production mode. Test
fixtures may inject deterministic pre-hashed connections through a separate
construction option.

### Management authorization

Token generation requires an authenticated fresh session, trusted origin,
CSRF, and an application authorization hook. Personal connections are owned by
the creator and can only be listed, inspected, rotated, or deleted by that
owner.

Organization connections require membership plus an owner/admin-equivalent
result from the configured organization authorizer. Authorization is performed
against the stored provider target for get/delete/rotation, never against an
untrusted request organization ID. Hooks can further restrict issuance but
cannot loosen built-in ownership or organization checks.

### SCIM authentication and media types

Protocol routes require `Authorization: Bearer <token>`. Tokens are
length-bounded, parsed once, and compared in constant time. Authentication
failures use the SCIM error schema and do not distinguish malformed, unknown,
expired, or mismatched tokens.

Requests accept `application/scim+json` and `application/json`; unsupported
types return `415`. SCIM responses use `application/scim+json`, `Cache-Control:
no-store`, and structured RFC 7644 errors with `schemas`, string `status`,
optional `scimType`, and safe `detail`.

### User resource and account ownership

SCIM `User` maps:

- `id` to the core user ID;
- `userName` and primary `emails.value` to canonical email;
- `externalId` to the SCIM provider account ID;
- formatted/given/family name to the native user name;
- `active` to native disabled state plus session revocation.

Every managed user must have an account row whose `providerId` equals the SCIM
connection provider and whose `accountId` is the normalized external ID or
username. Reads and mutations first prove that account link. A matching global
email alone is not ownership.

Linking an existing user is disabled by default. Optional linking requires all
configured domain, existing organization membership, and application hook
constraints. Email changes clear `emailVerified`.

Create and update operations are transactional across user, account, and
organization membership. Idempotent repeated creates return a conflict unless
the same provider/external identity already owns the resource.

### Listing, filters, PUT, PATCH, and DELETE

List endpoints support bounded `startIndex`, `count`, and the safe filter subset
needed for Better Auth parity: `id`, `userName`, `externalId`, and
`emails.value` with `eq`, joined by bounded `and`. Unsupported or malformed
filters fail with `invalidFilter`; they never become raw adapter queries.

PUT replaces writable fields while preserving server-managed identity. PATCH
supports bounded `add`, `replace`, and `remove` operations for the same writable
field set. Unknown paths, duplicate primary emails, oversized operation lists,
and type mismatches fail before persistence.

For organization-scoped connections, DELETE removes the membership, subordinate
team memberships, and this SCIM account link in one transaction. It never
deletes the global user. For personal connections, DELETE removes only the SCIM
account when other identities exist; it deletes the global user only when this
SCIM account is the sole identity. Deactivation always revokes all active
sessions.

### Metadata and hooks

ServiceProviderConfig advertises only implemented capabilities. Schema and
ResourceType documents use the standard SCIM URNs and deterministic locations
under the configured auth base path.

Before/after hooks cover token generation and user create, update, deactivate,
and deprovision transitions. Hook inputs are immutable copies and contain no raw
token after the issuance callback completes. Durable audit events record every
management and provisioning mutation.

### Limits and concurrency

Token use, creation, filtering, patch operations, payloads, list counts, and
provider connections have explicit limits. Provider rotation and user
create/delete transitions use adapter transactions and unique indexes. No
request token, SCIM body, or user record is stored in shared mutable state.

## Consequences

- SCIM remains mountable through standard `net/http` and works with MongoDB,
  PostgreSQL, SQLite, and future adapters.
- The public route/resource vocabulary follows Better Auth v1.6.25 while token
  storage and tenant deprovisioning are intentionally stricter.
- SSO can be merged, disabled, or replaced without changing SCIM's core API.
- Applications must supply organization authorization to enable
  organization-scoped connections.

## Verification

The implementation requires:

- black-box management and complete User CRUD tests;
- standard metadata, media type, pagination, filter, PUT, PATCH, and error
  fixtures;
- provider collision, cross-owner, cross-tenant, email-linking, and global-user
  deletion failure cases;
- constant-time hash fixtures and raw-token non-persistence assertions;
- concurrent rotation/create/delete tests with exactly one safe outcome;
- fuzz tests for bearer tokens, filters, patch paths, and SCIM JSON;
- adapter migration/conformance, race, vet, static, and vulnerability checks.
