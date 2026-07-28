import { auth, capturedMails, database } from "./auth.ts";
import { betterAuthVersion, referenceConfig } from "./config.ts";

function authorizedTestControl(request: Request): boolean {
  return (
    request.headers.get("x-better-auth-test-secret") ===
    referenceConfig.testControlSecret
  );
}

function testControl(request: Request, url: URL): Response | undefined {
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
    const controlled = testControl(request, url);
    if (controlled) return controlled;
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
