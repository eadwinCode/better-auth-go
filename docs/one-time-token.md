# One-time tokens

`plugin/onetimetoken` ports Better Auth's `one-time-token` plugin. The routes,
JSON bodies, error messages, `set-ott` header and options follow Better Auth
1.7.0. The plugin source is the same from v1.6.25 through v1.7.7.

A signed-in user asks for a short-lived token. Whoever holds the token can
trade it **once** for the user's session. The usual use is handing a session
to an app on another domain or subdomain that never sees the session cookie.

Status: experimental, like the other packages under `plugin/`.

## Routes

| Route | Needs | Result |
| --- | --- | --- |
| `GET /one-time-token/generate` | a session cookie | `{"token":"..."}` |
| `POST /one-time-token/verify` | JSON body `{"token":"..."}` | `{"session":{...},"user":{...}}`, and the session cookie unless disabled |

Verify errors are `400` with these messages, as in Better Auth:

- `Invalid token`: unknown, already used, or expired token.
- `Session not found`: the session was revoked (for example by sign-out) or
  the user is disabled.
- `Session expired`: the session itself has expired.

## Options

| Better Auth option | Go field | Default |
| --- | --- | --- |
| `expiresIn` (minutes) | `ExpiresIn` (`time.Duration`) | 3 minutes |
| `disableClientRequest` | `DisableClientRequest` | off |
| `generateToken` | `GenerateToken` | 32 random URL-safe characters |
| `disableSetSessionCookie` | `DisableSetSessionCookie` | off |
| `storeToken: "plain" \| "hashed" \| custom-hasher` | `StoreToken` + `HashToken` | `TokenStoragePlain` |
| `setOttHeaderOnNewSession` | `SetOTTHeaderOnNewSession` | off |

Use `TokenStorageHashed` in production. The default stays `plain` only to
match Better Auth.

`DisableClientRequest` turns off the HTTP generate route. Server code can then
create tokens with `Manager.Generate`, the Go form of calling
`auth.api.generateOneTimeToken` on the server:

```go
manager, err := onetimetoken.NewManager(onetimetoken.Config{
	DisableClientRequest: true,
	StoreToken:           onetimetoken.TokenStorageHashed,
})
// ... add manager.Plugin() to Config.Plugins ...

session, err := authServer.ResolveSession(r.Context(), r)
cookie, _ := r.Cookie("__Host-better_auth_session")
token, err := manager.Generate(r.Context(), database, session, cookie.Value)
```

## Cross-subdomain sign-in

Session cookies use the `__Host-` prefix, so the browser never sends them to
another subdomain. To sign a user in to `domains.example.com` from
`example.com`:

1. On `example.com`, while signed in, call
   `GET /api/auth/one-time-token/generate`.
2. Redirect the browser to `https://domains.example.com/auth/callback?token=...`.
3. The domains app calls `POST https://example.com/api/auth/one-time-token/verify`
   from its server and gets the user back.

Configure the auth server:

```go
ott, err := onetimetoken.New(onetimetoken.Config{
	StoreToken:              onetimetoken.TokenStorageHashed,
	DisableSetSessionCookie: true,
})
if err != nil {
	return err
}
config.Plugins = append(config.Plugins, ott)
```

Redeem the token in the domains app:

```go
body, _ := json.Marshal(map[string]string{"token": token})
request, err := http.NewRequestWithContext(ctx, http.MethodPost,
	"https://example.com/api/auth/one-time-token/verify", bytes.NewReader(body))
if err != nil {
	return err
}
request.Header.Set("Content-Type", "application/json")
response, err := http.DefaultClient.Do(request)
if err != nil {
	return err
}
defer response.Body.Close()
if response.StatusCode != http.StatusOK {
	return errSignInFailed
}
var result struct {
	Session struct {
		ID        string    `json:"id"`
		ExpiresAt time.Time `json:"expiresAt"`
	} `json:"session"`
	User struct {
		ID    string `json:"id"`
		Email string `json:"email"`
	} `json:"user"`
}
if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
	return err
}
// Create the domains app's own session for result.User.ID.
```

Points to get right:

- **Turn on `DisableSetSessionCookie`** for this flow. Otherwise verify sends
  the main site's session cookie to the domains app's server.
- **Bind the redirect to the browser that started it.** Without this, an
  attacker can send a victim a link with the attacker's own token and sign the
  victim in to the attacker's account (login CSRF). Have the domains app start
  the flow: it sets a short-lived random `state` cookie and sends the browser
  to `example.com` with that `state`. `example.com` passes `state` back with
  the token, and the domains app checks that it matches the cookie before it
  redeems the token.
- **Keep the token out of logs and referrers.** Serve the callback page with
  `Referrer-Policy: no-referrer`, redeem the token at once, and redirect to a
  clean URL.
- **Keep the expiry short.** The 3-minute default is enough for a redirect.
- Verify needs no `Origin` header when the request has no cookies, like Better
  Auth. If the request does carry cookies, its `Origin` must be a trusted
  origin.

## Differences from Better Auth

These are recorded in `PROGRESS.md` and ADR 0021.

- **Session token at rest.** Better Auth stores the raw session token next to
  the one-time token. Go never stores raw session tokens. It seals the session
  token with AES-256-GCM under a key derived from the one-time token, so only
  the token holder can open it. In `hashed` mode the database alone reveals
  neither the one-time token nor the session token.
- **Storage layout.** Go stores `identifier = "one-time-token"`,
  `value = <stored token>` and the sealed session in `metadata`. Better Auth
  stores `identifier = "one-time-token:<stored token>"` and
  `value = <session token>`. The Go session table keeps only token hashes,
  so the two cannot share session rows anyway.
- **No session token in JSON.** As with `get-session`, the verify body omits
  `session.token`. The cookie, when set, carries the same session.
- **Expired session.** Better Auth sets the expired session's cookie and then
  returns `Session expired`. Go returns the same error without a cookie.
- **Error body.** Errors also carry a `code` (`BAD_REQUEST`), as all Go errors
  do. The `message` values match Better Auth.
- **Revoked sessions and disabled users** return `Session not found`. Better
  Auth deletes revoked sessions, so it returns the same message.
