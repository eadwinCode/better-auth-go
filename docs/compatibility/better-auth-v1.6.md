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

Feature plugins outside the requested initial scope—such as passkeys, two-factor
authentication, organizations, username, magic links, anonymous users, SSO,
SCIM, and API keys—use the server kernel tracked in
[the plugin compatibility checklist](./plugin-kernel.md). Their full endpoint
implementations are tracked in the [feature gap register](./missing-features.md)
as separate parity milestones.
