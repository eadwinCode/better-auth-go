# Production operations

This guide covers the operator responsibilities around a stable core
`better-auth-go` deployment. It complements the library's security invariants;
it does not make the experimental feature plugins part of the v1 stability
guarantee.

## Deployment preflight

Before serving traffic:

1. pin an exact released module version and verify the release notes;
2. run the application's tests and adapter migration against a restored copy of
   production data;
3. configure `PublicURL`, exact redirect URLs, and the narrowest practical
   trusted-origin policy;
4. configure a transactional database, a real rate limiter, mail delivery,
   application authorization, and provider-token encryption;
5. apply the fully merged `auth.Schema()` before starting the new binary;
6. verify TLS, cookie, proxy, origin, CSRF, recovery-mail, OAuth callback, and
   session-revocation behavior in a staging environment;
7. record the deployed module tag, schema baseline, key identifiers, and
   rollback decision point.

Do not deploy from an untagged branch or an unattested source archive.

## TLS, proxies, and cookies

Terminate TLS at the application or at a trusted reverse proxy. The client must
experience HTTPS even when the final internal hop is HTTP; `Secure` cookies
must never be stripped or rewritten.

The library issues host-only `__Host-` cookies with `Secure`, `HttpOnly`,
`Path=/`, and SameSite Lax or Strict. A proxy must not add a `Domain` attribute,
rename cookies, broaden their path, or convert SameSite to None. Route the
configured authentication base path to one logical deployment and preserve all
`Set-Cookie` headers.

`TrustProxyHeaders` is false by default. Enable it only when every request
passes through a controlled proxy that removes any client-supplied
`X-Forwarded-For` value and writes the authoritative client address. The
current implementation uses the first validated IP in that header for rate
limiting; it does not infer trusted origins or redirect destinations from proxy
headers.

Use the configured `PublicURL` as the canonical external origin. Do not derive
it from `Host`, `Forwarded`, or `X-Forwarded-Host`. Prefer exact trusted origins.
If multi-tenant deployment requires a wildcard or `TrustedOriginResolver`,
bind the result to authoritative tenant configuration rather than a request
header supplied by the browser.

## Database migration and upgrades

SQL applications call the adapter's `Migrate` with the server's fully merged
schema. MongoDB applications call `EnsureIndexes` with that same schema.
Include enabled plugin schemas even when a plugin is experimental.

For every upgrade:

1. read the changelog and compatibility matrix;
2. take and verify a transactionally consistent backup;
3. restore the backup into an isolated environment;
4. run the new migration twice to prove idempotency;
5. run sign-in, session, recovery, OAuth, and application-specific smoke tests;
6. deploy the migration before or with binaries that understand it;
7. monitor authentication errors, database conflicts, mail delivery, OAuth
   callbacks, and rate-limit decisions;
8. retain the backup until the rollback window closes.

First-party migrations are additive. That makes mixed-version rolling
deployments possible only when the release notes say the old binary tolerates
the new fields and indexes. Additive schema does not guarantee semantic
rollback: a new binary may write states an old binary does not understand.
When that risk exists, stop the rollout and restore the previous binary and
backup together according to the tested plan.

Never edit the frozen release-upgrade fixtures to make a migration pass. Add a
new fixture for the newly released baseline.

## Backup and restore

A backup is usable only when it contains every authentication model, index
definition, and the external key material needed to decrypt encrypted fields.
Do not back up raw logs or traces containing cookies, authorization headers,
mail tokens, OAuth codes, or provider responses.

### PostgreSQL

Use a transactionally consistent `pg_dump` or storage snapshot that covers the
entire authentication schema. Preserve database roles and extension
requirements separately. Restore into an empty database, apply current
migrations, and run the adapter and authentication smoke suites before
declaring the backup recoverable.

### MongoDB

Use replica-set-aware snapshots or `mongodump` procedures that provide a
consistent point in time across all authentication collections. Back up the
replica-set oplog or use your managed provider's point-in-time recovery when
required by the recovery objective. After restore, run `EnsureIndexes` and
verify unique, TTL, and lookup indexes before accepting traffic.

### SQLite

Use SQLite's online backup API, `VACUUM INTO`, or a storage snapshot that
captures the database and its WAL state consistently. Copying only the main
database file while writes continue is not a backup. Restore to a separate
path, run migrations, then perform integrity and application smoke checks.

### Restore drills

Define recovery-point and recovery-time objectives. At least once per release
line, restore a production-shaped backup into an isolated account, verify row
counts and indexes, exercise authentication and revocation, and record timing.
Access to restored authentication data must be as restricted and audited as
production access.

## Secrets and key rotation

Store database credentials, OAuth client secrets, SMTP credentials, SAML
private keys, and token-cipher keys in a dedicated secret manager. Never place
them in module configuration files, release archives, CI logs, or database
backups.

Provider tokens, SSO configuration, TOTP seeds, and recoverable backup-code
material rely on the injected `TokenCipher`. A production key ring should:

- seal new values with one active key identifier;
- open values with the active key and bounded retired keys;
- authenticate the key identifier as part of the ciphertext format;
- fail closed for unknown, disabled, or malformed key identifiers;
- keep key selection immutable and concurrency-safe for a running process.

Rotate encryption keys in stages:

1. deploy readers containing the current and new keys while writes still use
   the current key;
2. switch `Seal` to the new key after all instances can read it;
3. reissue or rewrite encrypted records through supported application
   management flows and verify decryptability;
4. monitor decryption failures and keep the old key through the maximum
   rollback and record-lifetime window;
5. remove the retired key only after a database scan or application audit
   proves no live record requires it.

The library does not silently re-encrypt every stored secret. Do not remove an
old key immediately after changing the active key. Rotating a session or
one-time-token secret means revoking the associated database records; those
bearer values are hash-only and cannot be decrypted or recovered.

Rotate database/provider credentials with an overlap period when the provider
supports it, then revoke the old credential and test a new connection.

## Monitoring and incident response

Monitor aggregate, redacted signals for:

- sign-in failures and rate-limit denials;
- origin/CSRF rejection;
- session rotation and revocation failures;
- recovery and verification delivery failures;
- OAuth/OIDC callback, discovery, JWKS, and token-refresh failures;
- database transaction, uniqueness, and migration errors;
- key-identifier and ciphertext-open failures.

Never use email addresses, bearer tokens, cookies, authorization headers,
OAuth codes, SAML assertions, SCIM tokens, or mail links as metric labels.
Keep durable audit and outbox consumers idempotent.

For suspected credential compromise, stop issuance where practical, rotate the
affected external credential or key ring, revoke relevant sessions/provider
accounts, preserve sanitized audit evidence, and follow the private security
reporting process in `SECURITY.md`.

## Release verification

Install the exact module tag:

```bash
go get github.com/eadwinCode/better-auth-go@v1.0.0
go list -m github.com/eadwinCode/better-auth-go
```

Verify downloaded release archives as described in
[Versioning and stability](./versioning.md). Release candidates use a tag such
as `v1.0.0-rc.1` and are not stable releases.
