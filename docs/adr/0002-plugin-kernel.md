# ADR 0002: Server Plugin Kernel

- Status: accepted
- Date: 2026-07-28
- Depends on: ADR 0001

## Context

ADR 0001 created extension ports for storage, mail, rate limiting, password
verification, OAuth, authorization, and durable events. It did not implement
Better Auth's server plugin lifecycle. Better Auth plugins can contribute
endpoints, schema, route middleware, before/after hooks, global request/response
hooks, trusted origins, rate-limit rules, and database lifecycle hooks.

Applications need those facilities without giving plugins access to shared
mutable request state or allowing extension code to bypass core security
invariants.

## Decision

`Config.Plugins` accepts immutable `Plugin` descriptors. Construction:

1. validates plugin IDs, dependencies, routes, methods, and callback presence;
2. topologically orders plugins, using configuration order as the stable
   tie-breaker;
3. rejects dependency cycles, duplicate IDs, endpoint collisions, and core-route
   collisions;
4. merges plugin schema before wrapping the database adapter;
5. merges exact plugin trusted origins through the same HTTPS/loopback
   validation as application origins;
6. decorates the schema-aware adapter with ordered database hooks.

The HTTP lifecycle is:

1. resolve the core or plugin endpoint and validate its method;
2. enforce trusted origin for state-changing API requests;
3. capture and bound JSON request bodies;
4. run global `OnRequest` hooks;
5. run matching plugin rate-limit rules;
6. run matching route middleware;
7. run matching before hooks;
8. execute the endpoint;
9. run matching after hooks;
10. run global `OnResponse` hooks in reverse plugin order;
11. commit one bounded response to `http.ResponseWriter`.

OAuth callbacks retain their provider-facing GET/POST behavior and are not
treated as ordinary same-origin API mutations.

Every hook receives a request-scoped `HookContext`. It exposes cloned headers
and query values, a mutable JSON body, the schema-aware database adapter, clock,
ID generation, exact-origin checking, optional authenticated session data, and
an injected background-task port. Hook context is never stored on `Server` or a
plugin descriptor.

Hooks may return an early `PluginResponse` or an error. Errors fail closed and
are normalized through the public structured-error contract. Response hooks may
replace status, headers, or body subject to the configured response limit.

Database hooks apply to logical model names and execute inside the adapter call,
including inside transactions. Before hooks may replace mutation data. After
hooks observe a cloned result. A before-hook failure aborts the adapter
operation. An after-hook failure is returned to the caller and rolls back when
the operation is inside a transaction; an adapter mutation that has already
committed cannot be retroactively undone.

## Security invariants

- Origin enforcement precedes all plugin callbacks for state-changing API
  requests. Plugins can add exact trusted origins but cannot remove core origins
  or override a failed check.
- Plugin endpoints may use only GET and POST; state-changing endpoints must use
  POST.
- Core routes cannot be shadowed.
- Request and response bodies remain bounded.
- Hook panics are recovered and converted to internal errors without exposing
  panic values.
- Registration order is deterministic; response unwinding is deterministic.
- Records, headers, query values, and bodies are cloned at plugin boundaries.
- Background work runs only through an injected port. The default runner waits
  inline with request cancellation detached; applications may inject a durable
  asynchronous runner.
- Plugin descriptors and compiled runtime state are immutable after `New`.

## Compatibility boundary

This ADR implements the server-side plugin kernel. JavaScript client inference,
reactive atoms, and Better Call types have no direct Go equivalent. Individual
built-in plugins such as passkeys, two-factor authentication, organizations,
SSO, SCIM, and API keys remain separate feature packages and release gates.
Initialization may contribute schema and trusted origins; it cannot replace the
validated server configuration. Plugins receive capability-scoped context
rather than the application's secret or a mutable global context.

## Consequences

Applications can implement Better Auth-style server extensions without forking
the router or persistence layer. The lifecycle increases public API surface and
requires strict conformance tests for ordering, early returns, collisions,
origin behavior, response mutation, transactions, and concurrency.
