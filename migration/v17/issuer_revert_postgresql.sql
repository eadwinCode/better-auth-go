-- Undo the account issuer schema from unreleased better-auth-go main.
-- Run the duplicate check in README.md first and resolve every row it finds.
-- If a duplicate is left, the last statement fails and nothing is changed.
BEGIN;
DROP INDEX IF EXISTS "account_issuer_accountId_uidx";
DROP INDEX IF EXISTS "account_issuer_account_unique";
ALTER TABLE "account" ALTER COLUMN "issuer" DROP NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS "uniq_provider_account" ON "account" ("providerId", "accountId");
COMMIT;
