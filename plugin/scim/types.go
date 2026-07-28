package scim

import (
	"time"

	betterauth "github.com/eadwinCode/better-auth-go"
)

const (
	ModelSCIMProvider = "scimProvider"

	SchemaUser         = "urn:ietf:params:scim:schemas:core:2.0:User"
	SchemaSchema       = "urn:ietf:params:scim:schemas:core:2.0:Schema"
	SchemaResourceType = "urn:ietf:params:scim:schemas:core:2.0:ResourceType"
	SchemaListResponse = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	SchemaPatch        = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	SchemaError        = "urn:ietf:params:scim:api:messages:2.0:Error"
)

type OrganizationAuthorizer interface {
	AuthorizeSCIMConnection(*betterauth.HookContext, string) error
	IsSCIMMember(*betterauth.HookContext, string, string) (bool, error)
	// AddSCIMMember and RemoveSCIMMember receive a request copy whose Database
	// is the active provisioning transaction. Implementations must use that
	// adapter for membership persistence and must not retain the context.
	AddSCIMMember(*betterauth.HookContext, string, string) error
	RemoveSCIMMember(*betterauth.HookContext, string, string) error
}

// OrganizationRoleAuthorizer is the role-aware extension used when available.
// The base OrganizationAuthorizer remains supported for applications whose
// authorization port already encapsulates the same role policy.
type OrganizationRoleAuthorizer interface {
	AuthorizeSCIMConnectionRoles(*betterauth.HookContext, string, []string) error
}

type ProviderConnection struct {
	ID             string     `json:"id"`
	ProviderID     string     `json:"providerId"`
	OrganizationID string     `json:"organizationId,omitempty"`
	UserID         string     `json:"userId,omitempty"`
	CreatedAt      time.Time  `json:"createdAt"`
	UpdatedAt      time.Time  `json:"updatedAt"`
	LastUsedAt     *time.Time `json:"lastUsedAt,omitempty"`
	ExpiresAt      *time.Time `json:"expiresAt,omitempty"`
}

// DefaultConnection is for deterministic test and migration fixtures. TokenHash
// must already be a core HashToken value; raw tokens are never accepted here.
type DefaultConnection struct {
	ProviderID     string
	TokenHash      string
	OrganizationID string
	UserID         string
	ExpiresAt      *time.Time
}

type Name struct {
	Formatted  string `json:"formatted,omitempty"`
	GivenName  string `json:"givenName,omitempty"`
	FamilyName string `json:"familyName,omitempty"`
}

type Email struct {
	Value   string `json:"value,omitempty"`
	Primary bool   `json:"primary,omitempty"`
}

type UserInput struct {
	Schemas    []string `json:"schemas,omitempty"`
	UserName   string   `json:"userName"`
	ExternalID string   `json:"externalId,omitempty"`
	Name       *Name    `json:"name,omitempty"`
	Emails     []Email  `json:"emails,omitempty"`
	Active     *bool    `json:"active,omitempty"`
}

type ResourceMeta struct {
	ResourceType string    `json:"resourceType"`
	Created      time.Time `json:"created"`
	LastModified time.Time `json:"lastModified"`
	Location     string    `json:"location"`
}

type UserResource struct {
	Schemas     []string     `json:"schemas"`
	ID          string       `json:"id"`
	ExternalID  string       `json:"externalId,omitempty"`
	UserName    string       `json:"userName"`
	Name        *Name        `json:"name,omitempty"`
	DisplayName string       `json:"displayName,omitempty"`
	Active      bool         `json:"active"`
	Emails      []Email      `json:"emails,omitempty"`
	Meta        ResourceMeta `json:"meta"`
}

type PatchOperation struct {
	Operation string `json:"op"`
	Path      string `json:"path,omitempty"`
	Value     any    `json:"value,omitempty"`
}

type PatchRequest struct {
	Schemas    []string         `json:"schemas"`
	Operations []PatchOperation `json:"Operations"`
}

type SCIMError struct {
	Schemas  []string `json:"schemas"`
	Status   string   `json:"status"`
	SCIMType string   `json:"scimType,omitempty"`
	Detail   string   `json:"detail,omitempty"`
}

type TokenGeneratedHook func(
	*betterauth.HookContext,
	betterauth.User,
	ProviderConnection,
) error

type UserHook func(
	*betterauth.HookContext,
	betterauth.User,
	ProviderConnection,
) error

type Hooks struct {
	BeforeTokenGenerated TokenGeneratedHook
	AfterTokenGenerated  TokenGeneratedHook
	BeforeUserCreate     UserHook
	AfterUserCreate      UserHook
	BeforeUserUpdate     UserHook
	AfterUserUpdate      UserHook
	BeforeUserDelete     UserHook
	AfterUserDelete      UserHook
}

type ExistingUserLinkPolicy struct {
	Enabled                      bool
	TrustedDomains               []string
	RequireExistingOrgMembership bool
	Allow                        func(*betterauth.HookContext, betterauth.User, string, ProviderConnection) (bool, error)
}

type Filter struct {
	Path  string
	Field string
	Value string
}
