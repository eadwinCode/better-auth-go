// Package onetimetoken provides a Better Auth-shaped one-time-token plugin.
//
// A signed-in user asks for a short-lived token with
// GET /one-time-token/generate. Whoever holds the token can trade it once with
// POST /one-time-token/verify for the user's session. A common use is handing
// a session to an app on another domain or subdomain that cannot see the
// session cookie.
package onetimetoken

import (
	"context"
	"errors"
	"fmt"
	"time"

	betterauth "github.com/eadwinCode/better-auth-go"
)

const (
	// DefaultExpiresIn matches Better Auth's default of three minutes.
	DefaultExpiresIn = 3 * time.Minute

	maxTokenLength = 512
)

// TokenStorage selects how a token is kept in the verification table. It
// never changes the token that is sent to the client.
type TokenStorage string

const (
	// TokenStoragePlain stores the token as is. It is the default, as in
	// Better Auth. Prefer TokenStorageHashed in production.
	TokenStoragePlain TokenStorage = "plain"
	// TokenStorageHashed stores the SHA-256 hash of the token, encoded the
	// same way as Better Auth's "hashed" mode.
	TokenStorageHashed TokenStorage = "hashed"
	// TokenStorageCustom stores the result of Config.HashToken.
	TokenStorageCustom TokenStorage = "custom-hasher"
)

// TokenGenerator returns a custom token for a session. It must return a
// value with enough randomness to resist guessing; the token is also used to
// derive the key that protects the stored session reference.
type TokenGenerator func(context.Context, betterauth.SessionResult) (string, error)

// TokenHasher turns a token into its stored form for TokenStorageCustom. It
// must be deterministic.
type TokenHasher func(context.Context, string) (string, error)

// Config is immutable after construction. Field names follow Better Auth's
// OneTimeTokenOptions.
type Config struct {
	// ExpiresIn is how long a token stays valid. Zero means
	// DefaultExpiresIn. Better Auth takes minutes; Go takes a Duration.
	ExpiresIn time.Duration
	// DisableClientRequest rejects GET /one-time-token/generate. Server code
	// can still create tokens with Manager.Generate.
	DisableClientRequest bool
	// GenerateToken replaces the default 32-character random token.
	GenerateToken TokenGenerator
	// DisableSetSessionCookie stops verify from setting the session cookie.
	DisableSetSessionCookie bool
	// StoreToken selects how tokens are stored. Zero means
	// TokenStoragePlain.
	StoreToken TokenStorage
	// HashToken is required with TokenStorageCustom and not allowed
	// otherwise.
	HashToken TokenHasher
	// SetOTTHeaderOnNewSession adds a fresh token in a "set-ott" response
	// header whenever a response sets a new session cookie.
	SetOTTHeaderOnNewSession bool
	// Clock is used only by Manager.Generate. HTTP endpoints use the
	// server's clock. Nil means the system clock.
	Clock betterauth.Clock
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now().UTC() }

func normalizeConfig(config Config) (Config, error) {
	switch {
	case config.ExpiresIn == 0:
		config.ExpiresIn = DefaultExpiresIn
	case config.ExpiresIn < 0:
		return Config{}, errors.New("onetimetoken: ExpiresIn must be positive")
	}
	if config.StoreToken == "" {
		config.StoreToken = TokenStoragePlain
	}
	switch config.StoreToken {
	case TokenStorageHashed, TokenStoragePlain:
		if config.HashToken != nil {
			return Config{}, errors.New("onetimetoken: HashToken requires TokenStorageCustom")
		}
	case TokenStorageCustom:
		if config.HashToken == nil {
			return Config{}, errors.New("onetimetoken: TokenStorageCustom requires HashToken")
		}
	default:
		return Config{}, fmt.Errorf("onetimetoken: unknown StoreToken %q", config.StoreToken)
	}
	if config.Clock == nil {
		config.Clock = systemClock{}
	}
	return config, nil
}
