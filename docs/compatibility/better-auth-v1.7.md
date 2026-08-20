# Better Auth 1.7 migration contract

This repository targets Better Auth TypeScript **v1.7.0** for the migration
described here. The primary references are the v1.7.0 release, the official
1.7 upgrade guide, and upstream tag commit
`c3688ba88edff12dfcb1ced007e332711509ac29`. This document records implemented
behavior and explicit gaps; it is not a blanket parity claim.

## Account identity migration

`account.issuer` is required in the final schema and account identity is unique
by `(issuer, accountId)`. `providerId` remains presentation/routing metadata; it
is not an identity namespace.

Use `migration/v17.Backfill` between a nullable staging schema and the final
core schema:

1. Take a database backup and stop all writers that can create or link accounts.
2. Apply `v17.StagingSchema()` so `issuer` is nullable and do **not** create the
   final unique index yet.
3. Export every account and review the provider-to-issuer mapping. Credentials
   use `local:credential`; plain OAuth uses `local:oauth:<escaped-provider-id>`;
   OIDC uses its exact verified issuer.
4. Supply `ProviderIssuers` only after review. Use `Resolve` for rows
   whose subject changes, including Microsoft `sub` to verified `oid` and any
   SSO mapping-derived subject. The resolver must use a trusted provider export
   or cryptographically verified token; the migration cannot infer these IDs.
5. Run with `DryRun: true`. Any duplicate `(issuer, accountId)` is a hard stop
   and produces zero writes. Resolve ownership manually; never select a winner
   by timestamp.
6. Run the same plan without `DryRun`, verify row counts and collision reports,
   then finalize the physical schema as described below. Applying
   `betterauth.CoreSchema()` installs the compound index for additive adapters,
   but deliberately does not rewrite an existing SQL column.
7. Start one canary writer, exercise sign-in and account linking for every
   configured provider, then restore normal traffic.

Rollback before step 6 is a restore of the account table or clearing the staged
issuer values while writers remain stopped. After the final index is active,
rollback requires restoring the backup and the pre-1.7 binary together. Do not
drop `issuer` while a 1.7 binary can write.

MongoDB must backfill before `EnsureIndexes`; the staging schema deliberately
suppresses the fallback unique index. SQLite and PostgreSQL follow the same
staging/backfill/final-schema order, followed by explicit SQL finalization.
Memory adapter conformance covers
same-subject/different-issuer acceptance and same-issuer/same-subject collision.
The repository has no MySQL adapter; MySQL execution remains external adapter
work, not an inferred support claim.

### SQL finalization

The SQL adapter's `Migrate` method is additive: it never tightens or rewrites an
existing column. After applying the final schema, call
`v17.FinalizeSQL(ctx, db, dialect, finalSchema)` while writers remain stopped.
It repeats the null/collision checks inside its transaction, removes the legacy
identity indexes, and tightens the column. First independently assert that no row
has a null/empty issuer and that this query returns no rows:

```sql
SELECT issuer, accountId, COUNT(*)
FROM account
GROUP BY issuer, accountId
HAVING COUNT(*) > 1;
```

For PostgreSQL, run the following in one transaction after those checks (quote
custom table/field names from the deployment's merged schema):

```sql
BEGIN;
DROP INDEX IF EXISTS uniq_provider_account;
DROP INDEX IF EXISTS account_provider_account_unique;
ALTER TABLE account ALTER COLUMN issuer SET NOT NULL;
CREATE UNIQUE INDEX account_issuer_accountId_uidx
  ON account (issuer, accountId);
COMMIT;
```

SQLite cannot add `NOT NULL` to an existing column. `FinalizeSQL` therefore uses
one maintenance transaction to create a replacement account table from the
deployment's final merged schema, copy every column with an explicit column
list, drop the old table, rename the replacement, then recreate the final
indexes and verify foreign-key/integrity checks. The replacement includes
`issuer TEXT NOT NULL` and only `UNIQUE (issuer, accountId)` for identity; do
not carry forward `uniq_provider_account` or
`account_provider_account_unique`. The helper refuses to run if live columns do
not exactly match the reviewed merged schema, so application-defined account
columns cannot be silently dropped.

## Runtime behavior

| Area | Go migration state |
| --- | --- |
| OIDC identity | Verified `iss` and `sub`; shared signature, audience, nonce and expiry checks |
| SAML identity | Signed assertion `NameID`; mutable mapping fields cannot select identity |
| Microsoft identity | Verified `oid`, with tenant/issuer validation |
| Other providers | Built-ins use immutable provider subjects; custom non-OIDC providers must configure `AccountSubject` |
| Dynamic base URL | Not exposed. `PublicURL` is static; forwarded headers are ignored unless `TrustProxyHeaders` is explicitly enabled for remote-IP attribution |
| Origins | HTTPS scheme and exact authority are canonicalized; wildcard hosts remain scheme-bound; arbitrary custom schemes are rejected |
| Transactions | Database after-hooks and secondary effects queue until the outer transaction commits and are discarded on rollback |
| Two factor | `method` accepts `totp` (default) or `otp`; responses are discriminated by `method` |
| Passkey | Registration accepts `createSession`; passkey and initial session persistence share one transaction |
| OAuth consumer | PKCE remains enabled, token/unlink routes accept the v1.7 Better Auth account row ID, refresh parameters are supported with protected keys, accumulated scopes are preserved, and validated RP-initiated logout is optional |
| Provider email | Go continues its stricter verified-email gate unless the application explicitly declares a trusted provider; it never issues a social session for an unverified identity |
| SSO transactionality | Account/user/session resolution uses the core transactional OAuth transition; application callbacks must use the supplied transaction adapter where documented |

The Go server intentionally has no request-derived dynamic base URL. This
meets the 1.7 hardening outcome without adding a proxy-header attack surface.

## SCIM cutover

The 1.7 SCIM persistence model is not compatible with the former
organization/account-backed representation. The Go plugin now stores directory
bindings in `scimUser`, separate from authentication `account` rows. Existing
organization membership hooks are an optional application projection only;
they do not define SCIM identity.

This draft implements the isolated User-binding boundary and safe
deprovision/connection lifecycle on the existing Go routes. It does **not** yet
claim wire/config/client parity with the complete upstream 1.7 SCIM package:
opaque multi-credential connections, provisioning domains, subject/profile
coordination, tombstones, native Groups, and the upstream decommission API are
still absent. The existing hash-only Go connection API remains in place until
those models can be ported together; mapping only the option names onto the old
single-token storage would create a false security boundary.

There is no safe in-place conversion of provisioning state. Cut over as a new
directory:

1. Disable provisioning at the identity provider and retain the old database
   and connection-token inventory for rollback/audit only.
2. Deploy the new `scimUser` schema with no copied account-derived bindings.
3. Create or rotate a new connection credential. Never reuse the old bearer
   token or copy token hashes.
4. Reset/restart provisioning in the directory and require a complete User
   reprovision. Reconcile counts and external IDs before enabling destructive
   deprovision operations.
5. If group provisioning is required, do not enable the Go SCIM endpoint yet:
   native SCIM Group resources and direct membership edges are future work in
   this repository. Organization roles are not a substitute for SCIM Groups.
6. After the reconciliation window, archive old provider/account markers. Do
   not turn them into authentication accounts with synthetic issuers.

Rollback means disabling the new connection and re-enabling the old deployment
and its database snapshot. Provisioning writes made on both sides cannot be
merged automatically; rerun a full directory reprovision after choosing the
authoritative side.

## Separately tracked future compatibility

MCP, CIMD, OAuth-provider resources, DPoP, device authorization, API-key
changes, native SCIM Groups, and MySQL adapter certification are not present in
the corresponding Go packages. They remain explicit future work. No shim or
unsupported architecture is introduced by this migration.
