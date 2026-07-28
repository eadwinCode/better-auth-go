# Better Auth Feature Gap Register

This is the release-planning register for parity with the TypeScript Better
Auth server. It is intentionally separate from the plugin-kernel implementation
checklist so a kernel primitive is not confused with a shipped feature plugin.

Baseline: Better Auth 1.6 documentation as reviewed on 2026-07-28. Every item
requires black-box HTTP tests, adapter conformance tests, threat-model review,
and client-contract documentation before its status can become complete.

## Server plugin contract gaps

| Capability | Current state | Planned work |
| --- | --- | --- |
| endpoint body/query validation | `EndpointValidator`, `EndpointValidatorFunc`, and strict `ObjectValidator` run before middleware/endpoint code | implemented |
| endpoint metadata | validators are implemented, but endpoints do not yet declare OpenAPI metadata | add operation IDs, tags, response schemas, and documentation generation |
| plugin initialization context extension | initialization can add schema and exact origins | add typed, immutable plugin context values without exposing secrets or mutable global state |
| wildcard trusted origins | rejected fail-closed | add a compiled, IDNA-aware matcher with public-suffix and scheme tests |
| request-derived trusted origins | not implemented | add a bounded resolver port whose results pass the same validation and cannot weaken static policy |
| direct in-process endpoint invocation | HTTP handler only | decide whether a typed Go service API is useful; hooks must have identical semantics if added |
| plugin error-code registry | structured errors exist, but plugins have no construction-time registry | add namespaced collision validation and documentation generation |
| generated client actions and reactive atoms | not a server-library concern | implement in `better-auth-sdk-go` where a Go equivalent is useful |
| endpoint OpenAPI generation | not implemented | build on endpoint validation/metadata after that contract stabilizes |
| instrumentation spans for plugin lifecycle | not implemented | add an OpenTelemetry-neutral observer port for endpoints, middleware, hooks, and database operations |

Exact HTTPS origins are the production default today. Wildcards and dynamic
resolvers remain listed rather than silently approximated because mistakes in
either feature expand the CSRF trust boundary.

## Built-in plugin implementation backlog

The kernel in this PR makes these possible; it does not implement them. Each
plugin should be its own package or a small cohesive PR series.

### Authentication

- two-factor authentication — implemented in the dedicated ADR 0005 PR;
- passkeys/WebAuthn — implemented in the dedicated ADR 0004 PR;
- magic link;
- email OTP;
- phone number;
- anonymous users;
- username;
- Google One Tap;
- Sign In with Ethereum;
- multi-session;
- last-login-method tracking.

Generic OAuth consumer support is already part of the core social-provider
layer rather than a plugin.

### Authorization and identity management

- full admin user-management parity beyond the existing bounded impersonation
  flow;
- organizations, members, invitations, teams, roles, and permissions
  (ADR/schema/access foundation in progress);
- SSO with OIDC and SAML;
- SCIM provisioning (ADR/schema/token/filter/metadata foundation in progress).

### API and tokens

- agent authentication;
- API keys;
- JWT issuance and verification;
- bearer authentication;
- one-time tokens;
- OAuth proxy.

### OAuth and OIDC servers

- OAuth 2.1 authorization server;
- OpenID Connect provider;
- MCP provider authentication;
- device authorization grant.

### Security and utilities

- CAPTCHA provider integration;
- Have I Been Pwned password checks;
- internationalized public errors;
- OpenAPI reference generation;
- reusable integration/E2E test utilities.

### External integration plugins

Payment, billing, analytics, and other vendor integrations should live outside
the security core. The upstream catalog currently includes Stripe, Polar,
Autumn Billing, Creem, Dodo Payments, Commet, and Dub. They still need
compatibility entries, but are lower priority than authentication,
authorization, and token features.

## Proposed delivery order

1. passkeys/WebAuthn and two-factor authentication — implemented;
2. organizations, expanded admin, and authorization policies;
3. enterprise SSO and SCIM;
4. endpoint metadata/error registries and instrumentation;
5. magic link, email OTP, username, anonymous, and bearer;
6. API key, JWT, one-time-token, and multi-session;
7. OAuth/OIDC provider, MCP, device authorization, utilities, and external
   integrations.

Order may change when a consuming application needs a feature sooner, but no
feature skips its security contract or adapter-independent tests.
