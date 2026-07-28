import { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { admin, genericOAuth } from "better-auth/plugins";
import { referenceConfig } from "./config.ts";

export type CapturedMail = {
  kind: "password-reset" | "email-verification";
  email: string;
  token: string;
  url: string;
};

export const capturedMails: CapturedMail[] = [];

export const database = new Database(referenceConfig.databasePath, {
  create: true,
});

export const auth = betterAuth({
  appName: "better-auth-go compatibility oracle",
  secret: referenceConfig.secret,
  baseURL: referenceConfig.baseURL,
  basePath: referenceConfig.basePath,
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
          async getUserInfo() {
            return {
              id: "test-provider-user",
              email: "provider-fixture@example.com",
              emailVerified: true,
              name: "Provider Fixture",
            };
          },
        },
      ],
    }),
  ],
});
