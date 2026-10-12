-- Undo the account issuer schema from unreleased better-auth-go main.
-- Run the duplicate check in README.md first and resolve every row it finds.
-- If a duplicate is left, the last statement fails; run ROLLBACK then.
-- SQLite has no ALTER COLUMN, so the column is dropped. Drop the indexes first.
BEGIN;
DROP INDEX IF EXISTS "account_issuer_accountId_uidx";
DROP INDEX IF EXISTS "account_issuer_account_unique";
ALTER TABLE "account" DROP COLUMN "issuer";
CREATE UNIQUE INDEX IF NOT EXISTS "uniq_provider_account" ON "account" ("providerId", "accountId");
COMMIT;
