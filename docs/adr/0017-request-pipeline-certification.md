# ADR 0017: Request-pipeline and policy certification

- Status: Accepted
- Date: 2026-07-29
- Better Auth reference: `better-auth` v1.6.25
- Scope: PR #21

## Context

PR #20 closed the bounded OAuth callback, account-linking, sign-out/session,
and impersonation option gaps. The shared HTTP/plugin pipeline is already
implemented, but the production tracker still records several core surfaces as
partial because their v1.6 option contract or release evidence is incomplete:

1. static trusted origins cannot express the wildcard patterns supported by
   v1.6.25, and applications cannot resolve additional origins per request;
2. request-size and endpoint-validator behavior is not certified across
   malformed, oversized, early-response, and panic paths;
3. `onRequest`, middleware, before/after, `onResponse`, database hooks, and
   rate-limit rules need a single adversarial ordering and failure matrix;
4. session refresh/revocation and provider-token routes have implementations
   but their remaining failure and concurrency cases are not release evidence.

The Go server intentionally uses stronger browser protections than the pinned
TypeScript server: every unsafe browser route requires a trusted `Origin`, and
authenticated mutations additionally require a double-submit CSRF token.
Those guarantees must not be weakened to reproduce permissive upstream edge
cases.

## Decision

### Trusted-origin policy

Add a request-scoped `TrustedOriginResolver` port. Static origins and resolved
origins are additive, immutable for the lifetime of one request, and never
written back to shared server configuration. The resolver is invoked at most
once per request, is panic-contained, and its errors fail closed.

Accept Better Auth v1.6-style `*` and `?` wildcard host patterns in addition to
exact origins. Patterns are compiled during construction for static
configuration and during request resolution for dynamic configuration.
Wildcard policies:

- match only HTTP-origin hostnames, never credentials, paths, queries, or
  fragments;
- require HTTPS and an explicit scheme for production wildcard patterns;
- canonicalize literal hostname labels using IDNA lookup rules;
- reject malformed labels, wildcard ports, IP-address patterns, and patterns
  whose registrable suffix is itself controlled by a wildcard;
- compare the normalized scheme, hostname, and optional port without substring
  matching.

This deliberately does not reproduce v1.6.25 custom-scheme patterns such as
`exp://`: this repository is an embeddable HTTP authentication server and its
production trust boundary remains HTTPS, with the existing loopback HTTP
exception for exact development origins.

Resolved origin lists have fixed count and item-length bounds and pass the same
compiler as static policy. `HookContext.TrustedOrigins` and
`HookContext.IsTrustedOrigin` expose only the policy resolved for that request.

### Pipeline order and failure contract

Preserve the existing fail-closed order:

1. resolve route and enforce origin for unsafe methods;
2. build a bounded request context;
3. run `onRequest`;
4. run matching rate-limit rules;
5. validate plugin endpoint input;
6. run global and endpoint middleware;
7. run before hooks;
8. synchronize hook mutations and execute the endpoint;
9. run after hooks only after an endpoint is reached;
10. run `onResponse` for every request that produced a hook context.

Origin rejection remains earlier than application/plugin code. Validators
remain earlier than middleware and endpoints. Hook, matcher, validator,
rate-limit-key, endpoint, and database-hook panics become controlled failures.
Mandatory cache and content-type security headers are restored after every
response hook.

The project keeps the injected `RateLimiter` port rather than adding Better
Auth's JavaScript memory/database rate-limit storage implementation. This
satisfies the server-side policy contract without coupling authentication code
to one storage strategy. Limiter errors and panics fail closed, retry metadata
is bounded, and request credentials are never included in limiter input.

### Remaining core evidence

Add black-box evidence for:

- wildcard and dynamic-origin acceptance, malicious suffix rejection,
  resolver failure/panic, and concurrent request isolation;
- origin/CSRF, malformed JSON, unknown fields, duplicate values, oversized
  bodies/responses, lifecycle ordering, early responses, error responses,
  database rollback, rate-limit denial/error/panic, and concurrent requests;
- session refresh one-winner rotation, ownership-bound revocation, repeated
  revocation, and post-revocation authentication;
- provider-token missing/unsupported/expired/failed refresh, automatic refresh,
  encrypted persistence, replacement-token preservation, redaction, ownership,
  and concurrent refresh behavior.

Where the pinned TypeScript runtime exposes the same HTTP surface, extend the
checked-in oracle differential suite. Go-only security behavior remains an
explicit compatibility difference rather than being normalized away.

## Consequences

`Config` gains one optional resolver port and static trusted-origin strings gain
a bounded wildcard form. Existing exact-origin configurations remain source
compatible. Request-specific policy is immutable and concurrency-safe.

PR #21 certifies the shared kernel used by core and existing plugins. It does
not add OpenAPI generation, instrumentation, a built-in rate-limit database,
or any missing Better Auth feature plugin. Enterprise SSO/SCIM certification
and release-candidate evidence remain subsequent work.
