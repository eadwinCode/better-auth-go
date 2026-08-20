package betterauth

import (
	"context"
	"errors"
	"net/http"
	"time"
)

var (
	// ErrNotFound is returned by adapters for absent records.
	ErrNotFound = errors.New("betterauth: not found")
	// ErrConflict is returned when a unique identity already exists.
	ErrConflict = errors.New("betterauth: conflict")
	// ErrReplay is returned when a single-use value was already consumed.
	ErrReplay = errors.New("betterauth: replay")
	// ErrAccountNotLinked is returned when a same-email OAuth identity exists
	// but the configured implicit-linking policy denies attaching it.
	ErrAccountNotLinked = errors.New("betterauth: account not linked")
	// ErrSignUpDisabled is returned when an OAuth provider is allowed to sign
	// in existing identities but not create a new user for this request.
	ErrSignUpDisabled = errors.New("betterauth: oauth sign up disabled")
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

// UserDeletionHook runs application cleanup or policy immediately before or
// after durable account deletion. Implementations must be concurrency-safe.
type UserDeletionHook func(context.Context, User) error

// UserLifecycleHook observes a Better Auth lifecycle transition.
// Implementations must be concurrency-safe.
type UserLifecycleHook func(context.Context, User) error

// SyntheticUserInput contains only public signup fields. AdditionalFields is
// reserved for application-declared user schema fields and is an independent
// map that a factory may safely retain or mutate.
type SyntheticUserInput struct {
	CoreFields       Record
	AdditionalFields Record
	ID               string
}

// SyntheticUserFactory builds an enumeration-resistant duplicate-signup user
// shape, including application fields needed to match a real signup response.
type SyntheticUserFactory func(SyntheticUserInput) Record

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

// AdminRoleResolver returns application-owned roles for one user. It is
// invoked per request and must be concurrency-safe; roles are never cached on
// the shared server.
type AdminRoleResolver interface {
	Roles(context.Context, User) ([]string, error)
}

// TrustedProviderResolver resolves Better Auth v1.6's request-dependent
// trustedProviders option without retaining request state on the server.
type TrustedProviderResolver interface {
	TrustedProviders(context.Context, *http.Request) ([]string, error)
}

// TrustedProviderResolverFunc adapts a function to TrustedProviderResolver.
type TrustedProviderResolverFunc func(context.Context, *http.Request) ([]string, error)

func (resolver TrustedProviderResolverFunc) TrustedProviders(
	ctx context.Context,
	request *http.Request,
) ([]string, error) {
	return resolver(ctx, request)
}

// TrustedOriginResolver returns additional Better Auth v1.6 trusted-origin
// policies for one request. Results are bounded, validated, and never retained
// on the shared server. Implementations must be concurrency-safe.
type TrustedOriginResolver interface {
	TrustedOrigins(context.Context, *http.Request) ([]string, error)
}

// TrustedOriginResolverFunc adapts a function to TrustedOriginResolver.
type TrustedOriginResolverFunc func(context.Context, *http.Request) ([]string, error)

func (resolver TrustedOriginResolverFunc) TrustedOrigins(
	ctx context.Context,
	request *http.Request,
) ([]string, error) {
	return resolver(ctx, request)
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

// OAuthProviderSignUpPolicy is an optional provider capability matching Better
// Auth v1.6's per-provider signup controls. Implementations that do not expose
// it retain the historical behavior of allowing implicit signup.
type OAuthProviderSignUpPolicy interface {
	DisableImplicitSignUp() bool
	DisableSignUp() bool
}

// OAuthTokenRefresher is implemented by providers that can exchange a refresh
// token for a new token set.
type OAuthTokenRefresher interface {
	Refresh(context.Context, string) (ProviderTokens, error)
}

type OAuthEndSessionRequest struct {
	IDToken               string
	PostLogoutRedirectURI string
	State                 string
}

// OAuthEndSessionProvider optionally supports OpenID Connect RP-initiated logout.
type OAuthEndSessionProvider interface {
	EndSessionURL(OAuthEndSessionRequest) (string, error)
}

// authStore is the typed internal persistence contract built over the public
// generic DatabaseAdapter.
type authStore interface {
	CreateEmailUser(context.Context, CreateEmailUserParams) (User, error)
	FindUserByEmail(context.Context, string) (User, error)
	FindUserByID(context.Context, string) (User, error)
	PasswordCredential(context.Context, string) (PasswordCredential, error)
	ReplacePasswordHash(context.Context, string, string, string, time.Time) error
	SetPasswordHash(context.Context, string, string, time.Time) error
	ChangePasswordAndRotate(context.Context, ChangePasswordParams) (Session, error)
	UpdateUser(context.Context, string, Record, time.Time) (User, error)
	ListAccounts(context.Context, string) ([]OAuthAccount, error)
	UnlinkAccount(context.Context, string, string, string, bool) error
	UnlinkAccountByID(context.Context, string, string, bool) error
	DeleteUser(context.Context, string) error
	ConsumeUserDeletion(context.Context, string, string, time.Time) error
	ConsumeEmailChange(context.Context, string, time.Time) (User, string, error)
	ConsumeEmailChangeConfirmation(context.Context, string, time.Time) (User, string, string, error)
	LinkOAuthAccount(context.Context, string, string, OAuthProfile, ProviderTokens, time.Time) error
	OAuthAccountTokens(context.Context, string, string, string) (StoredOAuthAccount, error)
	OAuthAccountTokensByID(context.Context, string, string) (StoredOAuthAccount, error)
	UpdateOAuthAccountTokens(context.Context, string, string, ProviderTokens, time.Time) error

	CreateSession(context.Context, Session) (Session, error)
	SessionByTokenHash(context.Context, string) (Session, User, error)
	RotateSession(context.Context, string, Session) (Session, error)
	RevokeSession(context.Context, string, time.Time) error
	RevokeUserSessions(context.Context, string, time.Time) error
	ListSessions(context.Context, string, time.Time) ([]Session, error)
	RevokeSessionByID(context.Context, string, string, time.Time) (bool, error)
	RevokeOtherSessions(context.Context, string, string, time.Time) error
	UpdateSession(context.Context, string, string, Record, time.Time) (Session, error)

	PutOneTimeToken(context.Context, OneTimeToken) error
	HasOneTimeToken(context.Context, OneTimePurpose, string, time.Time) (bool, error)
	ConsumePasswordReset(context.Context, string, string, time.Time) (User, error)
	ConsumeEmailVerification(context.Context, string, time.Time) (User, error)
	VerifyUserEmail(context.Context, string, time.Time) (User, error)

	PutOAuthState(context.Context, OAuthState) error
	ConsumeOAuthState(context.Context, string, time.Time) (OAuthState, error)
	UpsertOAuthUser(context.Context, OAuthProfile, ProviderTokens, Session, DomainEvent, OAuthUpsertPolicy) (User, Session, bool, error)

	RotateSessionWithAudit(context.Context, string, Session, AuditEvent) (Session, error)
}

type CreateEmailUserParams struct {
	User          User
	PasswordHash  string
	Session       Session
	CreateSession bool
	Event         DomainEvent
}

type ChangePasswordParams struct {
	UserID              string
	PreviousHash        string
	ReplacementHash     string
	CurrentTokenHash    string
	ReplacementSession  Session
	RevokeOtherSessions bool
}

type StoredOAuthAccount struct {
	Account OAuthAccount
	Tokens  ProviderTokens
}

// OAuthUpsertPolicy is the immutable store policy for an OAuth callback. It is
// evaluated inside the same transaction that creates or links the account.
type OAuthUpsertPolicy struct {
	AllowImplicitLink        bool
	RequireLocalVerification bool
	UpdateUserInfoOnLink     bool
	UpdateAccountOnSignIn    bool
	AllowSignUp              bool
}

// NopRateLimiter permits every request.
type NopRateLimiter struct{}

func (NopRateLimiter) Allow(context.Context, RateLimitRequest) (RateLimitDecision, error) {
	return RateLimitDecision{Allowed: true}, nil
}
