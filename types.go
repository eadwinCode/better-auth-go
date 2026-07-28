package betterauth

import (
	"encoding/json"
	"time"
)

// User is the adapter-independent authenticated identity.
type User struct {
	ID            string     `json:"id"`
	Email         string     `json:"email"`
	Name          string     `json:"name,omitempty"`
	ImageURL      string     `json:"image,omitempty"`
	EmailVerified bool       `json:"emailVerified"`
	CreatedAt     time.Time  `json:"createdAt"`
	UpdatedAt     time.Time  `json:"updatedAt"`
	DisabledAt    *time.Time `json:"-"`
}

// MarshalJSON preserves the native Go string field while matching Better
// Auth's nullable public image field.
func (user User) MarshalJSON() ([]byte, error) {
	var image any
	if user.ImageURL != "" {
		image = user.ImageURL
	}
	return json.Marshal(struct {
		ID            string    `json:"id"`
		Email         string    `json:"email"`
		Name          string    `json:"name"`
		Image         any       `json:"image"`
		EmailVerified bool      `json:"emailVerified"`
		CreatedAt     time.Time `json:"createdAt"`
		UpdatedAt     time.Time `json:"updatedAt"`
	}{
		ID: user.ID, Email: user.Email, Name: user.Name, Image: image,
		EmailVerified: user.EmailVerified, CreatedAt: user.CreatedAt, UpdatedAt: user.UpdatedAt,
	})
}

// Session is a server-side session. TokenHash is never serialized to clients.
type Session struct {
	ID              string     `json:"id"`
	UserID          string     `json:"userId"`
	TokenHash       string     `json:"-"`
	ExpiresAt       time.Time  `json:"expiresAt"`
	CreatedAt       time.Time  `json:"createdAt"`
	UpdatedAt       time.Time  `json:"updatedAt"`
	LastSeenAt      time.Time  `json:"lastSeenAt"`
	RevokedAt       *time.Time `json:"-"`
	ImpersonatorID  string     `json:"impersonatedBy,omitempty"`
	ImpersonationID string     `json:"impersonationId,omitempty"`
}

// PasswordCredential contains a user's encoded password hash.
type PasswordCredential struct {
	UserID       string
	PasswordHash string
	UpdatedAt    time.Time
}

// OAuthAccount binds a provider identity to a user.
type OAuthAccount struct {
	ID                string    `json:"id"`
	UserID            string    `json:"userId"`
	Provider          string    `json:"providerId"`
	ProviderAccountID string    `json:"accountId"`
	Scope             string    `json:"scope,omitempty"`
	CreatedAt         time.Time `json:"createdAt"`
	UpdatedAt         time.Time `json:"updatedAt"`
}

// OAuthProfile is the provider-neutral verified profile used for account
// creation and linking.
type OAuthProfile struct {
	Provider          string
	ProviderAccountID string
	Email             string
	EmailVerified     bool
	Name              string
	ImageURL          string
}

type ProviderTokens struct {
	AccessToken           string
	RefreshToken          string
	IDToken               string
	Scope                 string
	AccessTokenExpiresAt  time.Time
	RefreshTokenExpiresAt time.Time
}

type OAuthResult struct {
	Profile OAuthProfile
	Tokens  ProviderTokens
}

// RequestMetadata is safe, bounded request context for security audits.
type RequestMetadata struct {
	RequestID string
	IP        string
	UserAgent string
}

// AuditEvent is an append-only security record.
type AuditEvent struct {
	ID            string
	SchemaVersion int
	Action        string
	ActorUserID   string
	SubjectUserID string
	SessionID     string
	OccurredAt    time.Time
	Request       RequestMetadata
	Details       map[string]string
}

// DomainEvent is persisted to an outbox for idempotent consumers.
type DomainEvent struct {
	ID            string
	SchemaVersion int
	Name          string
	AggregateID   string
	OccurredAt    time.Time
	Payload       map[string]string
}

// OneTimePurpose prevents token use across recovery flows.
type OneTimePurpose string

const (
	PurposePasswordReset           OneTimePurpose = "password_reset"
	PurposeEmailVerify             OneTimePurpose = "email_verify"
	PurposeEmailChange             OneTimePurpose = "email_change"
	PurposeEmailChangeConfirmation OneTimePurpose = "email_change_confirmation"
	PurposeUserDeletion            OneTimePurpose = "user_deletion"
	PurposeOAuthState              OneTimePurpose = "oauth_state"
	ProviderGoogle                                = "google"
	EventUserCreated                              = "user.created"
	AuditImpersonationStart                       = "admin.impersonation.started"
	AuditImpersonationStop                        = "admin.impersonation.stopped"
)

// OneTimeToken is a hash-at-rest, expiring, single-use token record.
type OneTimeToken struct {
	ID        string
	UserID    string
	Hash      string
	Purpose   OneTimePurpose
	ExpiresAt time.Time
	CreatedAt time.Time
	Metadata  map[string]string
}

// OAuthState is a purpose-specific single-use authorization transaction.
type OAuthState struct {
	ID           string
	Hash         string
	PKCEVerifier string
	Nonce        string
	RedirectURI  string
	ReturnTo     string
	LinkUserID   string
	ExpiresAt    time.Time
	CreatedAt    time.Time
}

// Mail contains a transactional authentication message. Implementations should
// render their own templates; Token and ActionURL are secrets and must not be
// logged.
type Mail struct {
	Kind      string
	To        string
	Token     string
	ActionURL string
	ExpiresAt time.Time
}
