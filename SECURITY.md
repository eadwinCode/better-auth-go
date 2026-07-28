# Security Policy

## Supported versions

Until the first stable release, only the latest tagged minor release receives
security fixes. After v1.0, the current major release and the previous major
release will receive coordinated fixes according to published release notes.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability.

Use GitHub private vulnerability reporting for
`eadwinCode/better-auth-go`. Include:

- affected version or commit;
- deployment assumptions;
- a minimal reproducer;
- impact and expected security invariant;
- whether you believe exploitation is active.

Maintainers should acknowledge a complete report within five business days.
Timelines depend on severity and coordination needs. Reporters may request
credit.

## Security contract

- Raw session, reset, verification, OAuth state, and CSRF tokens are never
  persisted or logged.
- Provider access, refresh, and ID tokens are encrypted before persistence.
- Passwords use bounded Argon2id parameters and strict PHC parsing.
- Cookie-authenticated state changes require trusted origin and CSRF validation.
- OAuth state is single-use and PKCE is S256 where supported.
- OIDC ID tokens validate signature, issuer, audience, expiry, and nonce.
- Redirect destinations are exact configured allowlist values.
- Automatic email linking requires verified-email evidence.
- Impersonation requires authorization, expires within one hour, rotates the
  browser session, and durably records an audit event.
- Security-critical multi-record operations require database transactions.
- Adapter atomic consume and guarded increment operations have one-winner
  concurrency semantics.
- WebAuthn responses are bound to configured exact origins and RP IDs;
  challenge handles are hashed, ceremony-bound, expiring, and single-use.
- Passkey discoverable user handles are opaque and never returned by the HTTP
  API; non-zero signature counter regressions fail closed.

## Deployment checklist

1. Serve only over TLS and preserve Secure cookies.
2. Use exact HTTPS origins and callback URLs; do not use wildcards.
3. Store MongoDB and OAuth credentials in a secret manager.
4. Use a 32-byte random provider-token encryption key or an application key-ring
   implementing `TokenCipher`.
5. Run MongoDB with transaction support and call `EnsureIndexes` with the
   server's fully merged schema.
6. Configure a real rate limiter for sign-in, sign-up, recovery, verification,
   OAuth, and impersonation actions.
7. Keep application authorization independent of client-provided roles/claims.
8. Redact request bodies, cookies, authorization headers, query tokens, and mail
   objects from logs and traces.
9. Run `go test -race ./...` and `govulncheck ./...` for every release.
