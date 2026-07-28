package organization

import "time"

type Organization struct {
	ID        string         `json:"id"`
	Name      string         `json:"name"`
	Slug      string         `json:"slug"`
	Logo      string         `json:"logo,omitempty"`
	Metadata  map[string]any `json:"metadata,omitempty"`
	CreatedAt time.Time      `json:"createdAt"`
	UpdatedAt time.Time      `json:"updatedAt"`
}

type Member struct {
	ID             string    `json:"id"`
	OrganizationID string    `json:"organizationId"`
	UserID         string    `json:"userId"`
	Role           string    `json:"role"`
	CreatedAt      time.Time `json:"createdAt"`
	UpdatedAt      time.Time `json:"updatedAt"`
}

type Invitation struct {
	ID             string    `json:"id"`
	OrganizationID string    `json:"organizationId"`
	Email          string    `json:"email"`
	Role           string    `json:"role"`
	TeamID         string    `json:"teamId,omitempty"`
	Status         string    `json:"status"`
	InviterID      string    `json:"inviterId"`
	ExpiresAt      time.Time `json:"expiresAt"`
	CreatedAt      time.Time `json:"createdAt"`
	UpdatedAt      time.Time `json:"updatedAt"`
}

type Team struct {
	ID             string    `json:"id"`
	OrganizationID string    `json:"organizationId"`
	Name           string    `json:"name"`
	CreatedAt      time.Time `json:"createdAt"`
	UpdatedAt      time.Time `json:"updatedAt"`
}

type TeamMember struct {
	ID        string    `json:"id"`
	TeamID    string    `json:"teamId"`
	UserID    string    `json:"userId"`
	CreatedAt time.Time `json:"createdAt"`
}

type OrganizationRole struct {
	ID             string     `json:"id"`
	OrganizationID string     `json:"organizationId"`
	Role           string     `json:"role"`
	Permission     Permission `json:"permission"`
	CreatedAt      time.Time  `json:"createdAt"`
	UpdatedAt      time.Time  `json:"updatedAt"`
}

// FullOrganization is returned by get-full-organization. User records are
// intentionally not embedded; applications can join public profile data at
// their boundary without expanding this plugin's disclosure surface.
type FullOrganization struct {
	Organization
	Members []Member `json:"members"`
	Teams   []Team   `json:"teams"`
}

// MutationEvent is passed to the generic organization lifecycle hooks.
// Data is a detached copy and must not be used as an authorization signal.
type MutationEvent struct {
	Action         string         `json:"action"`
	OrganizationID string         `json:"organizationId,omitempty"`
	SubjectID      string         `json:"subjectId,omitempty"`
	Data           map[string]any `json:"data,omitempty"`
}
