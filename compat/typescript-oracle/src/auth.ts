import { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { admin, genericOAuth } from "better-auth/plugins";
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
) =>
  betterAuth({
  appName: "better-auth-go compatibility oracle",
  secret: referenceConfig.secret,
  baseURL: referenceConfig.baseURL,
  basePath,
  trustedOrigins: referenceConfig.trustedOrigins,
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
