# Better Auth 1.7 account identity

Better Auth 1.7.0 to 1.7.2 added a required `issuer` column to the `account`
table and keyed accounts by `(issuer, accountId)`. Better Auth 1.7.3 removed
it again (upstream #11153). Accounts are keyed by `(providerId, accountId)`, as
in Better Auth 1.6.

better-auth-go follows Better Auth 1.7.3 and later:

- The `account` schema is the same as in better-auth-go v1.0.x. It has no
  `issuer` field and keeps the unique index
  `uniq_provider_account (providerId, accountId)`.
- A database built by a released better-auth-go version (v1.0.0 to v1.0.2)
  needs **no schema change**.
- If more than one row has the same `(providerId, accountId)`, sign-in and
  linking fail with `betterauth.ErrAmbiguousAccount` instead of picking one
  row. The unique index stops this from happening in a Go-built database.

## Databases built from unreleased main

No release ever had the `issuer` column. Only a database that ran
better-auth-go from the `main` branch between the Better Auth 1.7 port and this
change has it. In such a database:

- `account.issuer` is `NOT NULL`, so every sign-up and account link now fails,
  because Go no longer writes the column.
- The unique indexes `account_issuer_accountId_uidx` and
  `account_issuer_account_unique` key accounts by issuer.
- `uniq_provider_account` may be missing (the old `FinalizeSQL` step dropped it,
  together with `account_provider_account_unique`).

If your account table or index names are mapped, use your names. The second
index is named `<account table>_issuer_account_unique`.

### 1. Check for duplicate keys

Under the issuer key, two providers could hold the same `accountId` and one
provider could hold the same `accountId` under two issuers (for example two
tenants). The second case is now a duplicate. Find it first:

```sql
SELECT "providerId", "accountId", COUNT(*) AS "rows"
FROM "account"
GROUP BY "providerId", "accountId"
HAVING COUNT(*) > 1;
```

Resolve every row this returns before you go on. Decide which user owns the
identity, and delete or change the other rows. Do not guess from email.

### 2. Relax or drop the column, then restore the provider key index

Stop the app first. Drop the issuer indexes before you touch the column.

- PostgreSQL: [`issuer_revert_postgresql.sql`](issuer_revert_postgresql.sql)
  makes `issuer` nullable. This is enough and can be undone. You can drop the
  column later with `ALTER TABLE "account" DROP COLUMN "issuer";`.
- SQLite: [`issuer_revert_sqlite.sql`](issuer_revert_sqlite.sql) drops the
  column, because SQLite has no `ALTER COLUMN`. It needs SQLite 3.35 or later.
- MongoDB has no `NOT NULL`, so inserts keep working. Drop the issuer index,
  then let the adapter create `uniq_provider_account` again:

  ```js
  db.account.dropIndex("account_issuer_accountId_uidx");
  // Optional cleanup:
  db.account.updateMany({}, { $unset: { issuer: "" } });
  ```

  ```go
  err := mongoAdapter.EnsureIndexes(ctx, server.Schema())
  ```

Each SQL file runs in one transaction. Creating `uniq_provider_account` fails
if a duplicate from step 1 is left, and then nothing is changed. Running Go's
`Migrate` with the current schema also creates the index.

### 3. Confirm

Sign up a new user and sign in with an existing social account.

## Provider account IDs that changed

The Better Auth 1.7 port changed some provider subjects. Microsoft accounts now
use the stable `oid` claim instead of the app-specific `sub` claim. Rows stored
by better-auth-go v1.0.x keep the old value, so the next sign-in would not find
them. Rewrite them before you accept traffic:

```go
report, err := v17.RewriteAccountIDs(ctx, database, v17.Options{
	Resolve: func(ctx context.Context, row betterauth.Record) (string, error) {
		if row["providerId"] != "microsoft" {
			return "", nil // keep the current value
		}
		return oidFromVerifiedStoredIDToken(ctx, row) // your code
	},
})
```

`database` must be the schema-mapped adapter (for example
`betterauth.WrapDatabaseAdapter(adapter, server.Schema())`). The helper plans
every row first. A resolver error or two rows that would share a key stops it
before any write; `report.Collisions` lists the shared keys. Use
`DryRun: true` to see the plan. Better Auth cannot derive `oid` from the old
row alone: take it from a verified stored ID token or a trusted Microsoft Entra
export.
