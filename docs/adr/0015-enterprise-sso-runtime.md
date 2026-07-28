# ADR 0015: Enterprise SSO runtime

## Status

Accepted.

## Context

ADR 0007 established the enterprise SSO schema and security boundary but left
provider management and OIDC/SAML ceremonies disabled. Better Auth 1.6.25
compatibility requires those ceremonies without allowing plugins to duplicate
core account, token-encryption, event, or session logic.

## Decision

The plugin owns provider configuration, discovery, protocol state, OIDC and
SAML verification, domain policy, and organization provisioning. A narrow
`HookContext.AuthenticateOAuth` capability hands an already verified provider
profile to the core. The core alone encrypts provider tokens, upserts the
account/user, persists the user-created outbox event, rotates any browser
session, and emits host-only cookies.

OIDC requires authorization code, PKCE S256, single-use hash-at-rest state,
nonce, a signed ID token, exact issuer/audience validation, a verified email,
and a configured provider domain match. Every discovered endpoint passes the
application's outbound URL policy before use.

SAML parsing and XML signature validation use `github.com/crewjam/saml`.
Responses remain bounded and are correlated to a durable single-use
RelayState/AuthnRequest pair. Signed issuer, destination, audience, recipient,
timestamps, and subject confirmation are validated. Assertion IDs are stored
only as hashes and are unique for the replay window. SHA-1 and deprecated XML
encryption algorithms fail closed unless the application explicitly selects
the compatibility policy.

Provider configurations are encrypted as a single authenticated value. Public
management responses contain only non-secret metadata and the last four client
ID characters.

## Consequences

- SSO uses the same account/session security invariants as built-in social
  OAuth.
- Private IdPs require both an application-owned HTTP client and explicit
  outbound URL policy.
- IdP-initiated SAML and SAML single logout remain opt-in.
- SSO and SCIM stay independent packages and PRs.
