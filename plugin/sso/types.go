package sso

import (
	"context"
	"net/http"
	"net/url"
	"time"

	betterauth "github.com/eadwinCode/better-auth-go"
)

const ModelSSOProvider = "ssoProvider"

// HTTPDoer is the bounded network port used for OIDC discovery, token, JWKS,
// user-info, and SAML metadata requests.
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// OutboundURLPolicy validates every configured or discovered provider URL.
// Returning an error rejects the provider.
type OutboundURLPolicy func(context.Context, *url.URL) error

// OrganizationAuthorizer enforces organization-scoped provider management and
// provisioning. Implementations must derive authority from the stored target,
// not from an untrusted request identifier.
type OrganizationAuthorizer interface {
	AuthorizeSSOProvider(*betterauth.HookContext, string) error
	ProvisionSSOUser(*betterauth.HookContext, string, string, string) error
}

// DNSResolver is used for optional provider-domain verification.
type DNSResolver interface {
	LookupTXT(context.Context, string) ([]string, error)
}

type OIDCMapping struct {
	Email         string            `json:"email,omitempty"`
	EmailVerified string            `json:"emailVerified,omitempty"`
	Name          string            `json:"name,omitempty"`
	Image         string            `json:"image,omitempty"`
	ExtraFields   map[string]string `json:"extraFields,omitempty"`
}

// OIDCConfig follows Better Auth's stored provider vocabulary. PKCE S256 is
// mandatory and therefore is not a disable-able option.
type OIDCConfig struct {
	Issuer                      string      `json:"issuer"`
	ClientID                    string      `json:"clientId"`
	ClientSecret                string      `json:"clientSecret"`
	AuthorizationEndpoint       string      `json:"authorizationEndpoint,omitempty"`
	DiscoveryEndpoint           string      `json:"discoveryEndpoint,omitempty"`
	TokenEndpoint               string      `json:"tokenEndpoint,omitempty"`
	UserInfoEndpoint            string      `json:"userInfoEndpoint,omitempty"`
	JWKSEndpoint                string      `json:"jwksEndpoint,omitempty"`
	TokenEndpointAuthentication string      `json:"tokenEndpointAuthentication,omitempty"`
	Scopes                      []string    `json:"scopes,omitempty"`
	OverrideUserInfo            bool        `json:"overrideUserInfo,omitempty"`
	Mapping                     OIDCMapping `json:"mapping,omitempty"`
}

type SAMLMapping struct {
	Email         string            `json:"email,omitempty"`
	EmailVerified string            `json:"emailVerified,omitempty"`
	Name          string            `json:"name,omitempty"`
	FirstName     string            `json:"firstName,omitempty"`
	LastName      string            `json:"lastName,omitempty"`
	ExtraFields   map[string]string `json:"extraFields,omitempty"`
}

type SAMLConfig struct {
	Issuer                  string            `json:"issuer"`
	EntryPoint              string            `json:"entryPoint"`
	LogoutEndpoint          string            `json:"logoutEndpoint,omitempty"`
	Certificate             string            `json:"cert"`
	Audience                string            `json:"audience,omitempty"`
	SPEntityID              string            `json:"spEntityId"`
	SPPrivateKey            string            `json:"spPrivateKey,omitempty"`
	EncryptionPrivateKey    string            `json:"encryptionPrivateKey,omitempty"`
	WantAssertionsSigned    bool              `json:"wantAssertionsSigned"`
	AuthnRequestsSigned     bool              `json:"authnRequestsSigned,omitempty"`
	IdentifierFormat        string            `json:"identifierFormat,omitempty"`
	IDPInitiatedCallbackURL string            `json:"idpInitiatedCallbackUrl,omitempty"`
	AdditionalParams        map[string]string `json:"additionalParams,omitempty"`
	Mapping                 SAMLMapping       `json:"mapping,omitempty"`
}

// ProviderRegistration is accepted by configured default providers and the
// management layer. Exactly one protocol config must be present.
type ProviderRegistration struct {
	Issuer         string      `json:"issuer"`
	Domain         string      `json:"domain"`
	ProviderID     string      `json:"providerId"`
	OrganizationID string      `json:"organizationId,omitempty"`
	OIDC           *OIDCConfig `json:"oidcConfig,omitempty"`
	SAML           *SAMLConfig `json:"samlConfig,omitempty"`
}

// Provider is the non-secret public provider representation.
type Provider struct {
	ID             string    `json:"id"`
	Issuer         string    `json:"issuer"`
	Domain         string    `json:"domain"`
	ProviderID     string    `json:"providerId"`
	UserID         string    `json:"userId"`
	OrganizationID string    `json:"organizationId,omitempty"`
	Type           string    `json:"type"`
	DomainVerified bool      `json:"domainVerified,omitempty"`
	CreatedAt      time.Time `json:"createdAt"`
	UpdatedAt      time.Time `json:"updatedAt"`
}

type UserInfo struct {
	ID            string
	Issuer        string
	Email         string
	EmailVerified bool
	Name          string
	Image         string
	Attributes    map[string]any
}

type Tokens struct {
	AccessToken  string
	RefreshToken string
	IDToken      string
	TokenType    string
	Scope        string
	ExpiresAt    time.Time
}

type ProvisionUser func(
	*betterauth.HookContext,
	betterauth.User,
	UserInfo,
	*Tokens,
	Provider,
) error

type OrganizationProvisioning struct {
	Disabled    bool
	DefaultRole string
	GetRole     func(*betterauth.HookContext, betterauth.User, UserInfo, Provider) (string, error)
}

type SAMLPolicy struct {
	EnableInResponseToValidation bool
	AllowIDPInitiated            bool
	RequestTTL                   time.Duration
	ClockSkew                    time.Duration
	RequireTimestamps            bool
	DeprecatedAlgorithms         string
	MaxResponseSize              int64
	MaxMetadataSize              int64
	EnableSingleLogout           bool
	LogoutRequestTTL             time.Duration
	WantLogoutRequestSigned      bool
	WantLogoutResponseSigned     bool
	IDPInitiatedCallbackURL      string
}
