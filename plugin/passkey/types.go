package passkey

import (
	"time"

	"github.com/go-webauthn/webauthn/webauthn"

	betterauth "github.com/eadwinCode/better-auth-go"
)

// RegistrationUser is the account bound to a registration ceremony.
type RegistrationUser struct {
	ID          string
	Name        string
	DisplayName string
}

// RegistrationResolution may rebind a sessionless verified registration and
// supply a default label. A session-authenticated registration cannot be
// rebound to another user.
type RegistrationResolution struct {
	UserID string
	Name   string
}

// RegistrationVerification is public-safe data for an application callback
// after cryptographic verification and before credential persistence.
type RegistrationVerification struct {
	User         RegistrationUser
	Context      string
	CredentialID string
	AAGUID       string
	DeviceType   string
	BackedUp     bool
	ClientData   map[string]any
}

// AuthenticationVerification is public-safe data for an application callback
// after assertion verification and before counter/session persistence.
type AuthenticationVerification struct {
	UserID       string
	CredentialID string
	NewCounter   uint32
	BackedUp     bool
	ClientData   map[string]any
}

// ExtensionsResolver returns WebAuthn client extension inputs for one request.
// It must be concurrency-safe and must not retain HookContext.
type ExtensionsResolver func(*betterauth.HookContext) (map[string]any, error)

// RegistrationConfig controls registration-only compatibility hooks.
type RegistrationConfig struct {
	AllowWithoutSession bool
	ResolveUser         func(*betterauth.HookContext, string) (RegistrationUser, error)
	AfterVerification   func(
		*betterauth.HookContext,
		RegistrationVerification,
	) (RegistrationResolution, error)
	Extensions ExtensionsResolver
}

// AuthenticationConfig controls authentication-only compatibility hooks.
type AuthenticationConfig struct {
	AfterVerification func(*betterauth.HookContext, AuthenticationVerification) error
	Extensions        ExtensionsResolver
}

// Passkey is the Better Auth-compatible public credential record. The opaque
// WebAuthn user handle and complete verifier record are never serialized.
type Passkey struct {
	ID           string    `json:"id"`
	Name         string    `json:"name,omitempty"`
	PublicKey    string    `json:"publicKey"`
	UserID       string    `json:"userId"`
	CredentialID string    `json:"credentialID"`
	Counter      uint32    `json:"counter"`
	DeviceType   string    `json:"deviceType"`
	BackedUp     bool      `json:"backedUp"`
	Transports   string    `json:"transports,omitempty"`
	CreatedAt    time.Time `json:"createdAt"`
	UpdatedAt    time.Time `json:"updatedAt,omitempty"`
	AAGUID       string    `json:"aaguid,omitempty"`

	userHandle []byte
	credential webauthn.Credential
}

type webAuthnUser struct {
	id          string
	handle      []byte
	name        string
	displayName string
	credentials []webauthn.Credential
}

func (user webAuthnUser) WebAuthnID() []byte          { return user.handle }
func (user webAuthnUser) WebAuthnName() string        { return user.name }
func (user webAuthnUser) WebAuthnDisplayName() string { return user.displayName }
func (user webAuthnUser) WebAuthnCredentials() []webauthn.Credential {
	return user.credentials
}

type storedChallenge struct {
	Type        string               `json:"type"`
	UserID      string               `json:"userId,omitempty"`
	UserName    string               `json:"userName,omitempty"`
	DisplayName string               `json:"displayName,omitempty"`
	Context     string               `json:"context,omitempty"`
	Session     webauthn.SessionData `json:"session"`
}
