import { getMigrations } from "better-auth/db/migration";
import { auth, database } from "./auth.ts";

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
} finally {
  database.close();
}
