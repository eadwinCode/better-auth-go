import { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import type { BetterAuthPlugin } from "better-auth";
import { admin, genericOAuth, oneTimeToken } from "better-auth/plugins";
import { referenceConfig } from "./config.ts";

export type CapturedMail = {
  kind: "password-reset" | "email-verification" | "account-deletion";
  email: string;
  token: string;
  url: string;
};

export const capturedMails: CapturedMail[] = [];

export const database = new Database(referenceConfig.databasePath, {
  create: true,
});

const createAuth = (
  basePath: string,
  verifyAccountDeletion: boolean,
  allowImpersonatingAdmins = false,
  trustedOrigins:
    | string[]
    | ((request?: Request) => (string | undefined | null)[]) =
    referenceConfig.trustedOrigins,
  extra: {
    plugins?: BetterAuthPlugin[];
    sessionExpiresIn?: number;
  } = {},
) =>
  betterAuth({
  appName: "better-auth-go compatibility oracle",
  secret: referenceConfig.secret,
  baseURL: referenceConfig.baseURL,
  basePath,
  trustedOrigins,
  database,
  emailAndPassword: {
    enabled: true,
    autoSignIn: true,
    requireEmailVerification: false,
    async sendResetPassword({ user, url, token }) {
      capturedMails.push({
        kind: "password-reset",
        email: user.email,
        token,
        url,
      });
    },
  },
  emailVerification: {
    async sendVerificationEmail({ user, url, token }) {
      capturedMails.push({
        kind: "email-verification",
        email: user.email,
        token,
        url,
      });
    },
  },
  user: {
    changeEmail: {
      enabled: true,
    },
    deleteUser: {
      enabled: true,
      ...(verifyAccountDeletion
        ? {
            async sendDeleteAccountVerification({ user, url, token }) {
              capturedMails.push({
                kind: "account-deletion" as const,
                email: user.email,
                token,
                url,
              });
            },
          }
        : {}),
    },
  },
  account: {
    accountLinking: {
      allowDifferentEmails: true,
    },
  },
  databaseHooks: {
    user: {
      create: {
        async before(user) {
          return {
            data: {
              ...user,
              role: user.name === "Admin" ? "admin" : "user",
            },
          };
        },
      },
    },
  },
  session: {
    ...(extra.sessionExpiresIn
      ? { expiresIn: extra.sessionExpiresIn, updateAge: 0 }
      : {}),
    additionalFields: {
      label: {
        type: "string",
        required: false,
        input: true,
      },
    },
  },
  advanced: {
    useSecureCookies: referenceConfig.secureCookies,
  },
  plugins: [
    admin({
      impersonationSessionDuration: 60 * 60,
      allowImpersonatingAdmins,
    }),
    genericOAuth({
      config: [
        {
          providerId: "test",
          clientId: "test-client",
          clientSecret: "test-secret",
          authorizationUrl:
            referenceConfig.baseURL + "/__better_auth_test/oauth/authorize",
          tokenUrl: referenceConfig.baseURL + "/__better_auth_test/oauth/token",
          authentication: "post",
          scopes: ["openid", "profile"],
          async getUserInfo(tokens) {
            const fixtureCode = tokens.accessToken?.startsWith(
              "fixture-access-token:",
            )
              ? tokens.accessToken.slice("fixture-access-token:".length)
              : "default";
            const identity = fixtureCode.replace(/[^a-zA-Z0-9_-]/g, "-");
            return {
              id: "test-provider-user-" + identity,
              email: "provider-" + identity.toLowerCase() + "@example.com",
              emailVerified: true,
              name: "Provider Fixture " + identity,
            };
          },
        },
      ],
    }),
    ...(extra.plugins ?? []),
  ],
  });

export const auth = createAuth(referenceConfig.basePath, false);
export const deletionVerificationAuth = createAuth(
  referenceConfig.basePath + "-delete",
  true,
);
export const adminImpersonationAuth = createAuth(
  referenceConfig.basePath + "-admin-allow",
  false,
  true,
);
export const wildcardOriginsAuth = createAuth(
  referenceConfig.basePath + "-origin-wildcard",
  false,
  false,
  ["https://*.example.com"],
);
export const dynamicOriginsAuth = createAuth(
  referenceConfig.basePath + "-origin-dynamic",
  false,
  false,
  (request) => [request?.headers.get("x-tenant-origin")],
);

const ottAuth = (suffix: string, extra: Parameters<typeof createAuth>[4]) =>
  createAuth(
    referenceConfig.basePath + suffix,
    false,
    false,
    referenceConfig.trustedOrigins,
    extra,
  );

// One-time-token instances. Each one isolates a single plugin option so the
// Go differential suite can compare the option's HTTP effect on its own.
export const oneTimeTokenAuths: Record<string, ReturnType<typeof createAuth>> =
  {
    "-ott": ottAuth("-ott", { plugins: [oneTimeToken()] }),
    "-ott-hashed": ottAuth("-ott-hashed", {
      plugins: [oneTimeToken({ storeToken: "hashed" })],
    }),
    "-ott-no-cookie": ottAuth("-ott-no-cookie", {
      plugins: [oneTimeToken({ disableSetSessionCookie: true })],
    }),
    "-ott-server-only": ottAuth("-ott-server-only", {
      plugins: [oneTimeToken({ disableClientRequest: true })],
    }),
    "-ott-header": ottAuth("-ott-header", {
      plugins: [oneTimeToken({ setOttHeaderOnNewSession: true })],
    }),
    // One second, so the suite can wait for real expiry.
    "-ott-short-token": ottAuth("-ott-short-token", {
      plugins: [oneTimeToken({ expiresIn: 1 / 60 })],
    }),
    "-ott-short-session": ottAuth("-ott-short-session", {
      plugins: [oneTimeToken()],
      sessionExpiresIn: 2,
    }),
  };
