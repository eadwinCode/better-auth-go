# Enterprise SSO

The `plugin/sso` package is the isolated enterprise SSO integration for Better
Auth v1.6.25-shaped OIDC, OAuth 2.0, and SAML providers.

## Current foundation

The current branch freezes and implements the construction-time security
boundary:

- adapter-independent `ssoProvider` schema;
- encrypted-at-rest OIDC and SAML configuration contract;
- provider ID, domain, provider-limit, redirect, and SAML-policy validation;
- organization authorization and provisioning ports;
- bounded, no-redirect default discovery client with public-address dialing;
- issuer-pinned OIDC discovery with endpoint, flow, algorithm, authentication,
  response-size, and outbound URL validation;
- domain verification and provisioning configuration;
- Better Auth-compatible public provider/configuration types.

Provider management, sign-in/callback handling, ID-token/JWKS verification,
domain verification endpoints, SAML ceremonies, logout, and provisioning hooks
remain release-gated on this branch. Applications must not treat the schema-only
foundation as an enabled SSO login flow.

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
