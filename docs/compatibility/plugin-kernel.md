# Better Auth Server Plugin Compatibility

This checklist tracks the Go server-side equivalent of Better Auth's plugin
contract.

| Better Auth capability | Go contract | Status |
| --- | --- | --- |
| plugin `id` | `Plugin.ID` | in this PR |
| plugin dependencies/order | `Plugin.Dependencies` | in this PR |
| plugin schema | `Plugin.Schema` | in this PR |
| plugin endpoints | `Plugin.Endpoints` | in this PR |
| endpoint body/query validation | `BodyValidator`, `QueryValidator`, `ObjectValidator` | implemented |
| route middleware | `Plugin.Middlewares` | in this PR |
| before hooks and matchers | `Plugin.Before` | in this PR |
| after hooks and matchers | `Plugin.After` | in this PR |
| global `onRequest` | `Plugin.OnRequest` | in this PR |
| global `onResponse` | `Plugin.OnResponse` | in this PR |
| exact/wildcard trusted-origin contribution | `Plugin.TrustedOrigins` | certified |
| request-derived trusted origins | `Config.TrustedOriginResolver` and request-local `HookContext` policy | certified |
| custom rate-limit rule | `Plugin.RateLimits` | in this PR |
| database lifecycle hooks | `Plugin.DatabaseHooks` | in this PR |
| request auth/adapter/cookie context | `HookContext` | in this PR |
| session and double-submit CSRF middleware | `SessionMiddleware`, `CSRFMiddleware` | in this PR |
| secure plugin cookie creation | `PluginResponse.SetCookie` | in this PR |
| background tasks | `BackgroundTaskRunner` | in this PR |
| client action inference | no direct Go equivalent | not applicable |
| client atoms/listeners | client SDK concern | separate project |
| built-in plugin implementations | feature packages | future PRs |

## Deliberate Go boundaries

- `Plugin.Init` can contribute schema and static trusted origins, but cannot replace
  the already validated `Config` or access the application's secret.
- `HookContext` is capability-scoped and request-local. It does not expose
  shared mutable server state.
- The default `InlineBackgroundTasks` runner waits for completion with request
  cancellation detached. Production applications can inject a durable queue or
  asynchronous runner.
- Server endpoint invocation is HTTP-only. TypeScript client inference,
  reactive atoms, and direct in-process Better Call invocation belong to the
  separate client SDK or have no Go equivalent.

## Built-in plugin backlog

The kernel does not itself implement Better Auth's feature plugins. Each needs
its own threat model, schema, endpoints, client contract, and interoperability
tests. The complete categorized backlog and delivery order are maintained in
[the feature gap register](./missing-features.md).
