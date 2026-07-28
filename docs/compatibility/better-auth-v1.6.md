# Better Auth v1.6 Compatibility Contract

This document tracks behavioral compatibility between Better Auth TypeScript
v1.6 and `better-auth-go`. It is a living release gate, not a claim that Go and
TypeScript APIs are source-compatible.

Reference snapshot audited on 2026-07-28:

- Better Auth documentation version: v1.6;
- upstream repository: `better-auth/better-auth`;
- built-in provider export:
  `packages/core/src/social-providers/index.ts`;
- database adapter contract:
  `packages/core/src/db/adapter/index.ts`.

## Compatibility principles

1. Preserve default base path and endpoint names where the server contract is
   runtime-independent.
2. Preserve core model and field semantics for user, session, account, and
   verification records.
3. Preserve provider IDs and provider-specific identity semantics.
4. Preserve adapter operations, predicate vocabulary, capability declarations,
   transactions, atomic consumption, and guarded increments.
5. Provide Go interfaces for Better Auth hooks and plugins rather than emulating
   JavaScript objects.
6. Prefer native Go security formats for new data. Better Auth password/session
   formats are opt-in migration bridges.
7. Security fixes may intentionally differ and must be documented.

## Core endpoint map

| Better Auth endpoint | better-auth-go | Status |
| --- | --- | --- |
| `POST /sign-up/email` | same | implemented |
| `POST /sign-in/email` | same | implemented |
| `POST /sign-in/social` | same | implemented |
| `GET\|POST /callback/:provider` | `/callback/{provider}` | implemented |
| `POST /sign-out` | same | implemented |
| `GET /get-session` | same | implemented |
| `POST /refresh-session` | same | implemented Go rotation endpoint |
| `GET /list-sessions` | same | implemented; returns session IDs, never bearer tokens |
| `POST /revoke-session` | same | implemented; accepts an owned session ID |
| `POST /revoke-other-sessions` | same | implemented |
| `POST /revoke-sessions` | same | implemented |
| `POST /update-session` | same | implemented for schema input fields |
| `POST /update-user` | same | implemented |
| `POST /change-email` | same | implemented; opt-in |
| `POST /delete-user` | same | implemented; opt-in password/fresh-session flow |
| `POST /change-password` | same | implemented |
| `GET /list-accounts` | same | implemented with credential/token redaction |
| `POST /link-social` | same | implemented |
| `POST /unlink-account` | same | implemented |
| `POST /get-access-token` | same | implemented with account ownership binding |
| `POST /refresh-token` | same | implemented for refresh-capable providers |
| `POST /forget-password` | same | implemented |
| `POST /reset-password` | same | implemented |
| `POST /send-verification-email` | same | implemented |
| `GET /verify-email` | same | implemented |
| `POST /admin/impersonate-user` | same | implemented |
| `POST /admin/stop-impersonating` | same | implemented |

The Go server uses stable session IDs for session-management requests because
raw bearer tokens are hash-at-rest and never returned after issuance. A client
compatibility test suite freezes exact JSON, status, cookie, and redirect
behavior.

## Adapter map

| Upstream adapter operation | Go operation |
| --- | --- |
| `create` | `Create` |
| `findOne` | `FindOne` |
| `findMany` | `FindMany` |
| `count` | `Count` |
| `update` | `Update` |
| `updateMany` | `UpdateMany` |
| `delete` | `Delete` |
| `deleteMany` | `DeleteMany` |
| `consumeOne` | `ConsumeOne` |
| `incrementOne` | `IncrementOne` |
| `transaction` | `Transaction` |

The Go conformance suite checks empty-where safety, projections, sorting,
pagination, AND/OR predicates, case sensitivity, joins where advertised, atomic
single-use consumption, guarded counters, and rollback.

## Built-in social provider IDs

The following provider IDs are release-gated:

- apple
- atlassian
- cognito
- discord
- dropbox
- facebook
- figma
- github
- gitlab
- google
- huggingface
- kakao
- kick
- line
- linear
- linkedin
- microsoft
- naver
- notion
- paybin
- paypal
- polar
- railway
- reddit
- roblox
- salesforce
- slack
- spotify
- tiktok
- twitch
- twitter
- vercel
- vk
- wechat
- zoom

The generic OAuth/OIDC provider API is also release-gated, so providers outside
this list do not require a library release.

All 34 IDs above have built-in presets and catalog contract tests. Live
credential interoperability remains an integration responsibility for each
release because provider payloads and policies can change independently.

## Deliberate differences

- Native password hashes are Argon2id. Better Auth scrypt verification is an
  optional migration bridge with rehash-on-success.
- Session cookies contain opaque random tokens and persistence contains only
  token hashes.
- OAuth state and one-time credentials are hashed at rest and consumed
  atomically.
- Automatic email account linking requires a verified-email assertion and an
  explicit local policy.
- Cross-site `SameSite=None` cookie mode is not enabled by default and requires a
  future security ADR.
- Adapter fallbacks may not weaken an enabled feature's required atomicity.

## Not yet in the initial release gate

Feature plugins outside the requested initial scope—such as organizations,
username, magic links, anonymous users, SSO, SCIM, and API keys—use the server
kernel tracked in
[the plugin compatibility checklist](./plugin-kernel.md). Their full endpoint
implementations are tracked in the [feature gap register](./missing-features.md)
as separate parity milestones.

Passkeys/WebAuthn are specified in ADR 0004 and implemented as the first
dedicated high-risk plugin PR.

Two-factor authentication is specified in ADR 0005 and implemented as the
second dedicated high-risk plugin PR.

Organizations are specified in ADR 0006 with their schema and authorization
foundation isolated from the protocol plugins.

Enterprise SSO is specified in ADR 0007. Its provider schema, configuration
boundary, organization ports, and hardened OIDC discovery are implemented as a
separate foundation; SSO HTTP ceremonies remain release-gated until the
black-box protocol matrix passes.

SCIM is specified in ADR 0008. Its provider schema, hash-only bearer boundary,
bounded filter parser, standard metadata resources, and required plugin HTTP
method/origin primitives are implemented as an independent foundation. User
provisioning and connection-management routes remain release-gated until the
black-box RFC 7644 matrix passes.

## Passkey plugin endpoint map

| Better Auth endpoint | better-auth-go | Status |
| --- | --- | --- |
| `GET /passkey/generate-register-options` | same | implemented |
| `POST /passkey/verify-registration` | same | implemented |
| `GET /passkey/generate-authenticate-options` | same | implemented |
| `POST /passkey/verify-authentication` | same | implemented |
| `GET /passkey/list-user-passkeys` | same | implemented |
| `POST /passkey/update-passkey` | same | implemented |
| `POST /passkey/delete-passkey` | same | implemented |

The Go model preserves Better Auth's public passkey fields and adds a private
opaque user handle, full verifier record, and update timestamp. The challenge
cookie uses a host-only `__Host-` name and persistence contains only its hash.
User verification defaults to `required`; Better Auth's `preferred` behavior is
an explicit compatibility option. Registration user resolution, optional
sessionless enrollment, authenticator selection, extensions, schema mapping,
and post-verification hooks have Go request-scoped equivalents.

## Two-factor plugin endpoint map

| Better Auth endpoint | better-auth-go | Status |
| --- | --- | --- |
| `POST /two-factor/enable` | same | implemented |
| `POST /two-factor/disable` | same | implemented |
| `POST /two-factor/get-totp-uri` | same | implemented |
| `POST /two-factor/verify-totp` | same | implemented |
| `POST /two-factor/send-otp` | same | implemented |
| `POST /two-factor/verify-otp` | same | implemented |
| `POST /two-factor/generate-backup-codes` | same | implemented |
| `POST /two-factor/verify-backup-code` | same | implemented |
| server-only backup-code viewing | `twofactor.Manager.ViewBackupCodes` | implemented |

The plugin also enriches user-bearing sign-up, sign-in, session, refresh, and
verification responses with `twoFactorEnabled`. Credential sign-in returns
`twoFactorRedirect` and the available `twoFactorMethods`, while revoking the
provisional first-factor session before response commit.

Native Go differences are security-hardening choices: encryption is mandatory,
backup codes cannot be stored in plaintext, secret-bearing management requires
a fresh session and CSRF, pending/trusted bearer values are hash-only at rest,
and backup-code viewing has no HTTP route.
