import { getMigrations } from "better-auth/db/migration";
import { auth, database, twoFactorAuths } from "./auth.ts";

try {
  const { toBeCreated, toBeAdded, runMigrations } = await getMigrations(
    auth.options,
  );
  console.log(
    JSON.stringify({
      tablesToCreate: toBeCreated.length,
      columnsToAdd: toBeAdded.length,
    }),
  );
  await runMigrations();
  // The two-factor plugin adds its own table and user column.
  const twoFactorMigrations = await getMigrations(
    twoFactorAuths["-2fa"]!.options,
  );
  await twoFactorMigrations.runMigrations();
} finally {
  database.close();
}
