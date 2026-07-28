package betterauth

import (
	"context"
	"errors"
	"time"
)

var (
	// ErrNotFound is returned by adapters for absent records.
	ErrNotFound = errors.New("betterauth: not found")
	// ErrConflict is returned when a unique identity already exists.
	ErrConflict = errors.New("betterauth: conflict")
	// ErrReplay is returned when a single-use value was already consumed.
	ErrReplay = errors.New("betterauth: replay")
)

// Clock enables deterministic expiry and audit tests.
type Clock interface {
	Now() time.Time
}

// TokenSource creates cryptographically unpredictable URL-safe opaque values.
type TokenSource interface {
	Token(byteLength int) (string, error)
}

// TokenCipher encrypts provider credentials before persistence.
type TokenCipher interface {
	Seal(context.Context, string) (string, error)
	Open(context.Context, string) (string, error)
}

// Mailer delivers transactional authentication mail.
type Mailer interface {
	Send(context.Context, Mail) error
}

// RateLimitRequest is intentionally small so limiters can map it to local
// policies without receiving credentials.
type RateLimitRequest struct {
	Action     string
	IP         string
	AccountKey string
	Window     time.Duration
	Max        int
}

type RateLimitDecision struct {
	Allowed    bool
	RetryAfter time.Duration
}

// RateLimiter is called before expensive or abuse-sensitive work. Errors fail
// closed.
type RateLimiter interface {
	Allow(context.Context, RateLimitRequest) (RateLimitDecision, error)
}

// ImpersonationAuthorizer decides whether an authenticated actor may
// impersonate a subject. Returning an error denies the operation.
type ImpersonationAuthorizer interface {
	CanImpersonate(context.Context, User, User) error
}

// PasswordVerifier supports native formats and optional migration bridges.
type PasswordVerifier interface {
	Hash(context.Context, string) (string, error)
	Verify(context.Context, string, string) (PasswordVerification, error)
}

type PasswordVerification struct {
	Valid           bool
	ReplacementHash string
}

// OAuthProvider performs provider communication behind bounded contexts.
type OAuthProvider interface {
	AuthorizationURL(state, codeChallenge, nonce, redirectURI string) (string, error)
	Exchange(context.Context, string, string, string, string) (OAuthResult, error)
}

// authStore is the typed internal persistence contract built over the public
// generic DatabaseAdapter.
type authStore interface {
	CreateEmailUser(context.Context, CreateEmailUserParams) (User, error)
	FindUserByEmail(context.Context, string) (User, error)
	FindUserByID(context.Context, string) (User, error)
	PasswordCredential(context.Context, string) (PasswordCredential, error)
	ReplacePasswordHash(context.Context, string, string, string, time.Time) error

	CreateSession(context.Context, Session) (Session, error)
	SessionByTokenHash(context.Context, string) (Session, User, error)
	RotateSession(context.Context, string, Session) (Session, error)
	RevokeSession(context.Context, string, time.Time) error
	RevokeUserSessions(context.Context, string, time.Time) error

	PutOneTimeToken(context.Context, OneTimeToken) error
	ConsumePasswordReset(context.Context, string, string, Session) (User, Session, error)
	ConsumeEmailVerification(context.Context, string, time.Time) (User, error)

	PutOAuthState(context.Context, OAuthState) error
	ConsumeOAuthState(context.Context, string, time.Time) (OAuthState, error)
	UpsertOAuthUser(context.Context, OAuthProfile, ProviderTokens, Session, DomainEvent) (User, Session, bool, error)

	RotateSessionWithAudit(context.Context, string, Session, AuditEvent) (Session, error)
}

type CreateEmailUserParams struct {
	User         User
	PasswordHash string
	Session      Session
	Event        DomainEvent
}

// NopRateLimiter permits every request.
type NopRateLimiter struct{}

func (NopRateLimiter) Allow(context.Context, RateLimitRequest) (RateLimitDecision, error) {
	return RateLimitDecision{Allowed: true}, nil
}
