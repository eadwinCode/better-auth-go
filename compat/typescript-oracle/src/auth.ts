import { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
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
});
