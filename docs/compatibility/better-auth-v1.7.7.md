# Better Auth v1.7.2 to v1.7.7

This file records every server-relevant change in Better Auth v1.7.2 through
v1.7.7 and what better-auth-go does with it. The source is the
`packages/*/CHANGELOG.md` files and the commits between tags `v1.7.1` and
`v1.7.7` (tag commit `db02f233`). The TypeScript oracle now pins
`better-auth@1.7.7`, and `scripts/check-upstream-v1.7.7.sh` checks the
upstream inventory.

Status words:

- **Ported**: implemented in Go with tests.
- **Already matches**: Go already behaved this way.
- **Not shipped**: the Better Auth component does not exist in Go yet.
- **Not applicable**: TypeScript client, bundler, ORM or database code with no
  Go server equivalent.

## Ported

| Version | Change | Go |
| --- | --- | --- |
| 1.7.3 | #11153 accounts keyed by `(providerId, accountId)`; `issuer` column removed; ambiguous keys rejected | `issuer` removed from the schema, `uniq_provider_account` restored, `FindAccountByKey` and `ErrAmbiguousAccount`. v1.0.x databases need no change. See `migration/v17/README.md` for databases built from unreleased `main`. |
| 1.7.3 | SSO provider IDs share the account provider namespace once `issuer` is gone (upstream `sso.ts` reserved IDs) | SSO registration rejects built-in, social, trusted and default SSO provider IDs with upstream's 422 message. Go also refuses SSO sign-in for such an ID, so a provider stored earlier cannot sign in as a social provider's users. |
| 1.7.3 | #11037 TOTP re-enrollment cannot replace an active authenticator | `TOTP_ALREADY_ENABLED`; a pending enrollment can still be replaced |
| 1.7.6 | #11324 over-long passwords rejected with `PASSWORD_TOO_LONG` before any lookup or hash | sign-in, change-password, delete-user, `Server.VerifyPassword` and the two-factor password checks |
| 1.7.6 | #11333 model identity kept when a renamed model matches another schema key | memory adapter builds unique rules from the stored schema; MongoDB rejects `Collections` mixed with model renames |
| 1.7.2 | #10959 `Origin: null` accepted when `Sec-Fetch-Site: same-origin` | `InferNullOrigin`; core origin check and one-time-token verify |
| 1.7.2 | #10979, #10041, #10983 relative callback URLs with query, fragment and `~` | SSO return paths use the 1.7.7 safe-relative rule and resolve against the site origin (they used to resolve under the auth base path) |
| 1.7.2 | #10982 namespaced placeholder emails | Reddit, Roblox, TikTok, Twitter and WeChat use `CreatePlaceholderEmail`; placeholders are never marked verified |
| 1.7.3 | #9908 Cloudflare provider | 36 built-in providers |
| 1.7.3 | #11101 custom token request authentication | `TokenAuthCustom` and `Options.CustomizeTokenRequest` |
| 1.7.3 | #11102, #11129, #11134 TikTok, PayPal and Reddit token requests | RFC 6749 form-encoded Basic auth with the client only in the header; per-provider auth method matches upstream; PKCE for PayPal and Zoom; TikTok sends the code verifier; Reddit headers |
| 1.7.3 | #11178, #11179 live schema check | `SchemaChecker`, `Server.CheckSchema`, request gate with `SCHEMA_MISMATCH`, `Config.DisableSchemaValidation` |
| 1.7.5 | #11203 PostgreSQL `schemaName` | `postgresql.NewWithOptions(db, Options{SchemaName})`; every statement is schema-qualified and `Migrate` creates the schema |
| 1.7.5 | #11270 PostgreSQL migrations ignore other schemas and views | only tables in the target schema count; a view or other relation with a Better Auth table name stops `Migrate` with a clear error |

## Already matches

| Version | Change | Why |
| --- | --- | --- |
| 1.7.7 | #11469 rate-limit errors use a JSON Content-Type | every Go error response is JSON |
| 1.7.7 | #11494 purpose-specific verification identifiers and encryption keys | Go stores every flow under its own identifier with a hashed value, and keeps no OAuth or SAML state in cookies |
| 1.7.2 | #10983 error parameters placed before a URL fragment | Go builds error redirects with `net/url` |

## Not shipped in Go

| Version | Change | Component |
| --- | --- | --- |
| 1.7.2, 1.7.6 | #10823, #11325 bans | admin user management |
| 1.7.3, 1.7.6 | #10988, #11268 OAuth proxy | OAuth proxy plugin |
| 1.7.3 | #11147 `isPasswordCompromised` | Have I Been Pwned plugin |
| 1.7.3 | #10963 last-login method for email OTP | last-login-method and email OTP plugins |
| 1.7.3 | #11188 Auth0 domain helper | generic-oauth provider helpers (Go uses `social.NewOIDC`) |
| 1.7.5, 1.7.7 | #11283, #11476 CAPTCHA | CAPTCHA plugin |
| 1.7.7 | #11491 ID-token sign-in honours `disableSignUp` | ID-token social sign-in; if added, it must reuse the redirect callback's sign-up policy |
| 1.7.7 | #11494 magic-link record isolation | magic link plugin |
| 1.7.2 to 1.7.7 | #11010, #11090, #8686, #11402 | `@better-auth/oauth-provider` |

## Not applicable

TypeScript clients and frameworks (#10907, #11084, #11085, #11316, #11376,
#11375), Cloudflare D1 (#10875, #11366), MySQL (#10877, #11272), Prisma and
Drizzle checks (#11179 for ORMs), Zod and OpenAPI (#11066), test utilities
(#10879, #11205, #11217), OpenTelemetry (#11210, #11224), Vercel BotID (#11016),
packaging (#11209, #11290), async context and logger plumbing (#10855, #10938,
#10939), cookie cache (#10934, #11120), custom-scheme URL parsing (#11060; Go
rejects custom schemes), optional atomic adapter methods (#11189; Go requires
them), generic OAuth discovery at start-up (#10978; the application calls
`social.NewOIDC` and decides), IP and role-permission performance (#11068,
#11069).

## Differences kept

New in this port:

- **Unique provider-account index.** Go keeps
  `uniq_provider_account (providerId, accountId)`, as v1.0.x did. Upstream has
  no unique index and rejects ambiguous rows when it reads them. Go does both.
- **PayPal environment.** Go still uses the live PayPal API unless `BaseURL`
  points at the sandbox. Upstream defaults to the sandbox. Changing the default
  would break production sign-ins without warning.
- **Roblox PKCE.** Go keeps PKCE on for every provider that supports it.
- **Schema check timing.** Go has no start-up hook with a context, so the check
  runs on the first request or on `Server.CheckSchema`. Only success is cached:
  after a failure the next request checks again, so running `Migrate` fixes the
  server without a restart. A mismatch returns a JSON `500` with
  `SCHEMA_MISMATCH`; details stay on the Go error.
- **Schema name checks.** Go also rejects names longer than 63 bytes, invalid
  UTF-8 and NUL bytes, which PostgreSQL would cut or refuse.
- **Views at migration.** Go stops `Migrate` with a clear error. Upstream skips
  the relation and fails later.

Older Go rules that still apply here:

- **Verified provider email.** Go refuses a social sign-in whose email is not
  verified unless the provider is in `TrustedProviders`. Upstream signs the user
  up with `emailVerified: false`. Providers that return no email (Reddit,
  Roblox, TikTok, WeChat, Twitter without a confirmed email) therefore work
  only when the application trusts them. Their placeholder address is still
  stored as unverified.
- **Password length** is counted in bytes; upstream counts UTF-16 units.
- **Rate-limit responses** use `Retry-After` and `{code, message}`; upstream
  sends `X-Retry-After` and only `message`.
- **Relative callback URLs in the core** must match `AllowedRedirectURLs`
  exactly. Only SSO accepts any safe relative path, as upstream does.
