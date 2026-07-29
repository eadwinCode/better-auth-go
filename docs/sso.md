# Enterprise SSO

> **Experimental:** `plugin/sso` is not included in the better-auth-go v1
> compatibility or production-support guarantee. Pin an exact version and run
> interoperability tests against every configured IdP before deployment. See
> [Versioning and stability](./versioning.md).

The `plugin/sso` package is the isolated enterprise SSO integration for Better
Auth v1.6.25-shaped OIDC, OAuth 2.0, and SAML providers.

## Implemented runtime

The plugin implements the construction-time boundary and the Better Auth
v1.6-shaped HTTP runtime:

- adapter-independent `ssoProvider` schema;
- encrypted-at-rest OIDC and SAML configuration contract;
- session/CSRF-protected provider management with personal or organization
  authorization;
- bounded, no-redirect discovery with public-address dialing and an explicit
  outbound URL policy;
- OIDC authorization code with PKCE S256, single-use hash-at-rest state,
  nonce, RS256 ID-token/JWKS validation, verified-email/domain enforcement,
  bounded token exchange, and fixation-safe core session completion;
- DNS domain verification and organization/user provisioning hooks;
- SAML service-provider metadata, SP-initiated login, HTTP POST ACS, signed
  response/assertion validation, issuer/audience/recipient/time/request
  correlation, durable assertion replay rejection, bounded bodies, and
  deprecated-algorithm rejection;
- optional SP-initiated SAML single logout with local session revocation.

The protocol suite is black-box tested with deterministic OIDC/JWKS fixtures
and a locally signed SAML IdP response. Provider secrets, state, access tokens,
refresh tokens, and SAML assertion IDs are never persisted in raw form.

## Endpoints

- `POST /sso/register`
- `GET /sso/providers`
- `GET /sso/get-provider`
- `POST /sso/update-provider`
- `POST /sso/delete-provider`
- `POST /sign-in/sso`
- `GET|POST /sso/callback/:providerId`
- `GET|POST /sso/callback`
- `GET /sso/saml2/sp/metadata`
- `GET|POST /sso/saml2/callback/:providerId`
- `POST /sso/saml2/sp/acs/:providerId`
- `GET|POST /sso/saml2/sp/slo/:providerId`
- `POST /sso/saml2/logout/:providerId`
- `POST /sso/request-domain-verification`
- `POST /sso/verify-domain`

## Construction

Provider configuration contains client secrets and SAML private material, so a
token cipher is mandatory:

```go
cipher, err := betterauth.NewAESGCMTokenCipher(key)
if err != nil {
	log.Fatal(err)
}

ssoPlugin, err := sso.New(sso.Config{
	Cipher: cipher,
})
if err != nil {
	log.Fatal(err)
}
```

The server receives `ssoPlugin` through its normal plugin configuration.
Configuration is cloned and immutable after construction.

The built-in discovery client rejects redirects and dials only public IP
addresses. Private enterprise IdPs require an explicit application-owned
`HTTPClient` and `OutboundURLPolicy`; enabling private discovery is never
inferred from a request.

## Organization-scoped providers

Organization providers require an `OrganizationAuthorizer`. The port is
responsible for authorizing management against the stored organization target
and for bounded membership provisioning. SSO never treats a request-supplied
organization ID as proof of authority.

## Security contract

See [ADR 0007](./adr/0007-enterprise-sso.md). In particular:

- OIDC uses authorization code, PKCE S256, state, nonce, and exact issuer and
  audience verification;
- SAML assertions are correlated, signed, audience/recipient/issuer/timestamp
  checked, and replay-protected;
- callback and RelayState destinations must be same-origin or exact trusted
  origins;
- provider secrets are encrypted and omitted from public records;
- successful SSO sessions use only the core fixation-safe session issuer.
- IdP-initiated SAML is disabled unless explicitly enabled; durable assertion
  IDs still prevent replay when it is enabled.
