# Better Auth 1.7 migration contract

This repository targets Better Auth TypeScript **v1.7.7**. It started from the
v1.7.0 release (tag commit `c3688ba88edff12dfcb1ced007e332711509ac29`); the
changes from v1.7.2 to v1.7.7 are listed in
[better-auth-v1.7.7.md](./better-auth-v1.7.7.md). This document records
implemented behavior and explicit gaps; it is not a blanket parity claim.

## Account identity

Better Auth 1.7.0 to 1.7.2 keyed accounts by a new required `issuer` column.
Better Auth 1.7.3 removed it again (#11153), and so does better-auth-go:
accounts are keyed by `(providerId, accountId)`, the same as in better-auth-go
v1.0.x. A row set where one key matches more than one account fails sign-in and
linking with `ErrAmbiguousAccount`. Go keeps the unique index
`uniq_provider_account`, so a Go-built database cannot hold such rows.

- Databases from released better-auth-go versions (v1.0.0 to v1.0.2) need no
  change.
- Databases built from unreleased `main` between the 1.7 port and this change
  have an `issuer` column. Follow `migration/v17/README.md`; it has tested
  PostgreSQL and SQLite clean-up scripts and the MongoDB steps.
- Microsoft accounts use the verified `oid` as the account ID, as upstream does.
  `migration/v17.RewriteAccountIDs` rewrites stored IDs (for example `sub` to
  `oid`) from a resolver you supply, and writes nothing if two rows would share
  a key.

The repository has no MySQL adapter.

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
