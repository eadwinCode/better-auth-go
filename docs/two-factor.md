# Two-factor authentication

`plugin/twofactor` implements the Better Auth v1.6 TOTP, delivered OTP,
backup-code, and trusted-device server contract. It intercepts successful
email/password sign-in before the provisional first-factor session reaches the
browser.

## Configure

```go
import (
	"os"

	betterauth "github.com/eadwinCode/better-auth-go"
	"github.com/eadwinCode/better-auth-go/plugin/twofactor"
)

cipher, err := betterauth.NewAESGCMTokenCipher(
	[]byte(os.Getenv("BETTER_AUTH_2FA_KEY")), // exactly 32 random bytes
)
if err != nil {
	return err
}

twoFactor, err := twofactor.New(twofactor.Config{
	Issuer: "Example",
	Cipher: cipher,
	DeliverOTP: func(
		ctx *betterauth.HookContext,
		user betterauth.User,
		code string,
	) error {
		// Deliver through an email/SMS port. Never log code.
		return deliverSecondFactor(ctx.Context, user, code)
	},
})
if err != nil {
	return err
}

config.Plugins = append(config.Plugins, twoFactor)
```

Run the normal SQL migration with `auth.Schema()`, or call MongoDB
`EnsureIndexes(ctx, auth.Schema())`, after adding the plugin.

The cipher is mandatory. TOTP secrets and backup codes are always encrypted;
pending-login, delivered-OTP, and trusted-device bearer values are only stored
as hashes.

## HTTP endpoints

| Endpoint | Authentication |
| --- | --- |
| `POST /two-factor/enable` | fresh session, CSRF, password for credential users |
| `POST /two-factor/disable` | fresh session, CSRF, password for credential users |
| `POST /two-factor/get-totp-uri` | fresh session, CSRF, password for credential users |
| `POST /two-factor/verify-totp` | pending-login cookie, or session plus CSRF |
| `POST /two-factor/send-otp` | pending-login cookie, or session plus CSRF |
| `POST /two-factor/verify-otp` | pending-login cookie, or session plus CSRF |
| `POST /two-factor/generate-backup-codes` | fresh session, CSRF, password for credential users |
| `POST /two-factor/verify-backup-code` | pending-login cookie, or session plus CSRF |

The enable request accepts `method: "totp"` (the default) or `method: "otp"`.
TOTP returns `{"method":"totp","totpURI":...,"backupCodes":[...]}` and
`twoFactorEnabled` remains false until the first code succeeds. OTP requires a
configured delivery callback, enables the gate immediately, and returns only
`{"method":"otp"}`. Enrollment responses are discriminated by `method`.
TOTP enrollment and backup-code responses are the only time plaintext recovery
codes are returned.

## Sign-in

After the password is correct, a user with 2FA enabled receives:

```json
{
  "twoFactorRedirect": true,
  "twoFactorMethods": ["totp", "otp"]
}
```

The password-created session is revoked in the same transaction that creates
the pending challenge. The browser receives only the short-lived
`__Host-better_auth_two_factor` cookie. A successful verification atomically
consumes that challenge before issuing a rotated opaque session.

TOTP accepts the current RFC 6238 period and one period on either side. OTP and
backup-code verification share the pending challenge's attempt budget with
TOTP. Consecutive failures across new challenges also produce a durable,
bounded account lockout.

## Trusted devices

Passing `"trustDevice": true` after a successful second factor creates a
server-backed trusted-device record and secure opaque cookie. The record is
user-bound, expires after 30 days by default, and rotates every time it bypasses
a challenge. Disabling 2FA revokes the current trusted-device record and clears
its cookie.

## Server-only backup-code viewing

Viewing recoverable codes is intentionally unavailable over HTTP:

```go
manager, err := twofactor.NewManager(config)
if err != nil {
	return err
}
config.Plugins = append(config.Plugins, manager.Plugin())

codes, err := manager.ViewBackupCodes(ctx, database, userID)
```

Only call this from trusted server code after applying your own authorization
and fresh-session policy. Prefer regeneration when users need recovery material.

## Compatibility and stricter defaults

The endpoint paths and primary bodies follow Better Auth v1.6. The Go plugin is
stricter by requiring encryption, fresh sessions for secret-bearing management,
host-only `__Host-` cookies, hash-only bearer storage, and server-only recovery
code viewing. `AllowPasswordless` never bypasses a password for an account that
has credential login enabled.

See [ADR 0005](./adr/0005-two-factor-authentication.md) for the complete threat
model and failure semantics.
