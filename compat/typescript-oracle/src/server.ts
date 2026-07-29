import {
  auth,
  adminImpersonationAuth,
  capturedMails,
  database,
  deletionVerificationAuth,
  dynamicOriginsAuth,
  wildcardOriginsAuth,
} from "./auth.ts";
import { betterAuthVersion, referenceConfig } from "./config.ts";

function authorizedTestControl(request: Request): boolean {
  return (
    request.headers.get("x-better-auth-test-secret") ===
    referenceConfig.testControlSecret
  );
}

async function oauthTokenFixture(
  request: Request,
  url: URL,
): Promise<Response | undefined> {
  if (
    request.method !== "POST" ||
    url.pathname !== "/__better_auth_test/oauth/token"
  ) {
    return undefined;
  }
  const body = await request.formData();
  if (
    body.get("client_id") !== "test-client" ||
    body.get("client_secret") !== "test-secret"
  ) {
    return Response.json(
      { error: "invalid_client", error_description: "Invalid client" },
      { status: 401 },
    );
  }
  if (
    body.get("grant_type") === "refresh_token" &&
    body.get("refresh_token") !== "fixture-refresh-token"
  ) {
    return Response.json(
      { error: "invalid_grant", error_description: "Invalid refresh token" },
      { status: 400 },
    );
  }
  if (body.get("grant_type") === "authorization_code") {
    const code = String(body.get("code") || "missing");
    if (code === "invalid-code") {
      return Response.json(
        { error: "invalid_grant", error_description: "Invalid code" },
        { status: 400 },
      );
    }
    return Response.json({
      access_token: "fixture-access-token:" + code,
      refresh_token: "fixture-refresh-token",
      id_token: "fixture-id-token:" + code,
      token_type: "Bearer",
      scope: "openid profile",
      expires_in: 3600,
    });
  }
  return Response.json({
    access_token: "fixture-refreshed-access-token",
    refresh_token: "fixture-refresh-token",
    id_token: "fixture-refreshed-id-token",
    token_type: "Bearer",
    scope: "openid profile",
    expires_in: 3600,
  });
}

async function testControl(
  request: Request,
  url: URL,
): Promise<Response | undefined> {
  if (!url.pathname.startsWith("/__better_auth_test/")) return undefined;
  if (!authorizedTestControl(request)) {
    return Response.json({ code: "UNAUTHORIZED" }, { status: 401 });
  }
  if (
    request.method === "DELETE" &&
    url.pathname === "/__better_auth_test/mail"
  ) {
    capturedMails.length = 0;
    return Response.json({ status: true });
  }
  if (
    request.method === "GET" &&
    url.pathname === "/__better_auth_test/mail/latest"
  ) {
    const kind = url.searchParams.get("kind");
    const email = url.searchParams.get("email")?.toLowerCase();
    const mail = capturedMails
      .slice()
      .reverse()
      .find(
        (candidate) =>
          (!kind || candidate.kind === kind) &&
          (!email || candidate.email.toLowerCase() === email),
      );
    return mail
      ? Response.json(mail)
      : Response.json({ code: "NOT_FOUND" }, { status: 404 });
  }
  return Response.json({ code: "NOT_FOUND" }, { status: 404 });
}

const server = Bun.serve({
  hostname: referenceConfig.hostname,
  port: referenceConfig.port,
  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname === "/healthz") {
      return Response.json({
        status: "ok",
        implementation: "better-auth-typescript",
        betterAuthVersion,
        basePath: referenceConfig.basePath,
      });
    }
    const oauthToken = await oauthTokenFixture(request, url);
    if (oauthToken) return oauthToken;
    const controlled = await testControl(request, url);
    if (controlled) return controlled;
    if (
      url.pathname === referenceConfig.basePath + "-admin-allow" ||
      url.pathname.startsWith(referenceConfig.basePath + "-admin-allow/")
    ) {
      return adminImpersonationAuth.handler(request);
    }
    if (
      url.pathname === referenceConfig.basePath + "-delete" ||
      url.pathname.startsWith(referenceConfig.basePath + "-delete/")
    ) {
      return deletionVerificationAuth.handler(request);
    }
    if (
      url.pathname === referenceConfig.basePath + "-origin-wildcard" ||
      url.pathname.startsWith(referenceConfig.basePath + "-origin-wildcard/")
    ) {
      return wildcardOriginsAuth.handler(request);
    }
    if (
      url.pathname === referenceConfig.basePath + "-origin-dynamic" ||
      url.pathname.startsWith(referenceConfig.basePath + "-origin-dynamic/")
    ) {
      return dynamicOriginsAuth.handler(request);
    }
    return auth.handler(request);
  },
});

console.log(
  `Better Auth ${betterAuthVersion} reference server listening on ${server.url}`,
);

function shutdown() {
  server.stop();
  database.close();
}

process.once("SIGINT", shutdown);
process.once("SIGTERM", shutdown);
