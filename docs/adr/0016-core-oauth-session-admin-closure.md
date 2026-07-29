# ADR 0016: Core OAuth, session, and admin partial closure

- Status: Accepted
- Date: 2026-07-29
- Better Auth reference: `better-auth` v1.6.25
- Scope: PR #20

## Context

The core-management differential suite certifies user management, account
listing/unlinking, provider-token routes, session management, and bounded
impersonation. The remaining Partial rows are narrower but security-sensitive:

1. OAuth callback errors, callback-state replay, and new-user/error redirects
   are not characterized against the pinned TypeScript server;
2. implicit verified-email linking and explicit account-link collisions do not
   expose all v1.6.25 account-linking controls;
3. anonymous/authenticated session retrieval and sign-out need a dedicated
   differential matrix, including the deliberate Go CSRF requirement; and
4. impersonation has no native equivalent for the v1.6.25 options that select
   administrators and prohibit impersonating another administrator.

Better Auth's complete admin plugin also contains user CRUD, roles, bans,
session administration, and permission endpoints. Those endpoints are not a
core partial and are not implicitly authorized by this decision.

## Decision

### OAuth callback lifecycle

Store the allowlisted success, error, and new-user redirect destinations plus
`requestSignUp` in the existing single-use, hash-at-rest OAuth state record.
Every callback, including a provider-declared error, must first consume valid
state. Invalid, expired, or replayed state never redirects to a request-supplied
location.

After valid state is consumed, provider errors and safe internal callback
failures redirect to the stored error destination with a bounded public error
code. Provider descriptions are neither reflected to the browser nor logged as
trusted data. New accounts use the stored new-user destination; existing users
use the normal callback destination. POST callbacks retain bounded form parsing
and the same one-winner state contract as GET callbacks.

The pinned v1.6.25 generic OAuth callback handles a provider-declared error
before parsing state, so it uses the global error URL, reflects
`error_description`, and leaves state reusable. Go deliberately does not match
that behavior because it conflicts with the pre-existing safe-provider-error
and single-use-state requirements. The differential suite characterizes both
sides so a future upstream correction is visible.

`requestSignUp` is honored only for providers that explicitly disable implicit
signup. The provider capability is optional so existing third-party provider
implementations remain source compatible.

### Account-linking policy and collisions

Add v1.6.25-shaped controls for:

- enabling/disabling account linking;
- disabling implicit same-email linking;
- selecting static or request-resolved trusted provider IDs;
- requiring the local same-email account to be verified before implicit
  linking (secure default: true); and
- copying non-identity profile fields after a successful link.

Returning-provider sign-in also honors the account-level
`updateAccountOnSignIn` option (default true) when deciding whether to replace
stored provider tokens.

Explicit linking requires a verified provider email unless the provider is in
the immutable trusted-provider set. Different-email linking remains opt-in.
Linking an identity already owned by the same user is idempotent and refreshes
provider tokens. Linking an identity owned by a different user returns the
v1.6.25 collision code without revealing that user's identity. The account
`(providerId, accountId)` pair is globally unique in the core schema.

Implicit same-email linking additionally requires the local email to be
verified by default. Disabling implicit linking does not disable creation of a
genuinely new user. Identity fields (`id`, `email`, and `emailVerified`) are
never overwritten by profile synchronization.

The v1.6.25 `requireLocalEmailVerified:false` migration opt-out is supported:
when a provider supplies verified evidence for the exact same normalized email,
the newly linked local row is promoted to verified. This is an identity-proof
transition, not part of optional profile synchronization.

### Session and sign-out certification

Add a pinned black-box matrix for anonymous and authenticated `get-session`,
authenticated and repeated sign-out, post-sign-out session retrieval, cookie
clearing, wrong-origin rejection, and missing/wrong CSRF rejection. Go keeps
its deliberate security difference: authenticated mutations, including
sign-out, require both trusted origin and the double-submit CSRF token.
Consequently, a browser with no CSRF cookie receives `FORBIDDEN` from Go's
anonymous sign-out while v1.6.25 returns success; once a valid CSRF cookie has
been issued, repeated sign-out remains safely idempotent.

### Remaining impersonation options

Add an immutable `AdminConfig` with the v1.6.25 administrator-selection inputs:
default role, admin roles, and explicit admin user IDs. A request-scoped role
resolver supplies application-owned roles without adding role columns to the
core user model. Configuration fails closed when role-based selection is
enabled without a resolver, or when role names/IDs are invalid.

The existing `ImpersonationAuthorizer` remains mandatory and is evaluated in
addition to administrator selection. By default, an administrator cannot
impersonate another administrator. `AllowImpersonatingAdmins` is an explicit
compatibility option; applications needing richer permissions keep that policy
inside the authorizer. Impersonation sessions remain capped at one hour,
fixation-safe, and durably audited.

The full Better Auth admin CRUD/ban/session-administration plugin remains in
the plugin inventory rather than being mislabeled as core parity.

## Implementation plan

1. Extend OAuth state and account/admin configuration, with fail-closed
   normalization and additive adapter migrations.
2. Implement safe callback-error/new-user routing, provider signup policy,
   verified-email implicit linking, idempotent same-user linking, and explicit
   cross-user collision errors.
3. Add pinned TypeScript-oracle fixtures and cross-runtime tests for callback
   errors/replay, linking controls/collisions, session/sign-out, and
   impersonation options.
4. Add direct security tests for malicious redirects, unverified identities,
   local-email verification, provider error sanitization, callback replay,
   and concurrent account collision attempts.
5. Update compatibility/progress documents and the release evidence matrix.
6. Run formatting, all Go tests, vet, race, fuzz smoke, staticcheck,
   govulncheck, TypeScript differential tests, and available adapter suites.

## Consequences

OAuth state metadata grows additively and remains adapter-independent. The
public configuration grows only where v1.6.25 has a corresponding option.
Secure defaults are stricter than upstream where necessary and every such
difference is recorded. Closing these core Partial rows does not by itself
declare the repository production-ready; enterprise interoperability and the
release-candidate evidence in ADR 0014 remain separate gates.
