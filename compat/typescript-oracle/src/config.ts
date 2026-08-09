import { dirname, resolve } from "node:path";
import { mkdirSync } from "node:fs";

export const betterAuthVersion = "1.6.26";

function required(name: string): string {
  const value = Bun.env[name]?.trim();
  if (!value) {
    throw new Error(`${name} is required`);
  }
  return value;
}

function booleanEnv(name: string, fallback: boolean): boolean {
  const value = Bun.env[name]?.trim().toLowerCase();
  if (!value) return fallback;
  if (value === "true") return true;
  if (value === "false") return false;
  throw new Error(`${name} must be "true" or "false"`);
}

function integerEnv(name: string, fallback: number): number {
  const value = Bun.env[name]?.trim();
  if (!value) return fallback;
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 1 || parsed > 65535) {
    throw new Error(`${name} must be an integer between 1 and 65535`);
  }
  return parsed;
}

function commaSeparatedEnv(name: string, fallback: string[]): string[] {
  const value = Bun.env[name]?.trim();
  if (!value) return fallback;
  return value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

export const referenceConfig = (() => {
  const baseURL = Bun.env.BETTER_AUTH_URL?.trim() || "http://127.0.0.1:3100";
  const parsedBaseURL = new URL(baseURL);
  const databasePath = resolve(
    Bun.env.BETTER_AUTH_DB?.trim() || "./data/reference.sqlite",
  );
  mkdirSync(dirname(databasePath), { recursive: true });

  return {
    secret: required("BETTER_AUTH_SECRET"),
    testControlSecret: required("BETTER_AUTH_TEST_CONTROL_SECRET"),
    baseURL,
    basePath: Bun.env.BETTER_AUTH_BASE_PATH?.trim() || "/api/auth",
    trustedOrigins: commaSeparatedEnv("BETTER_AUTH_TRUSTED_ORIGINS", [
      parsedBaseURL.origin,
    ]),
    secureCookies: booleanEnv("BETTER_AUTH_SECURE_COOKIES", false),
    databasePath,
    hostname: Bun.env.HOST?.trim() || "127.0.0.1",
    port: integerEnv(
      "PORT",
      parsedBaseURL.port ? Number(parsedBaseURL.port) : 3100,
    ),
  };
})();
