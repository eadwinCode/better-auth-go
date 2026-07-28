// Package organization provides Better Auth-shaped multi-tenant organization
// management and authorization.
package organization

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	betterauth "github.com/eadwinCode/better-auth-go"
)

const (
	ModelOrganization     = "organization"
	ModelMember           = "member"
	ModelInvitation       = "invitation"
	ModelTeam             = "team"
	ModelTeamMember       = "teamMember"
	ModelOrganizationRole = "organizationRole"
)

type Permission map[string][]string

type Role struct {
	Permission Permission
}

type InvitationDelivery func(
	*betterauth.HookContext,
	Invitation,
	Organization,
	betterauth.User,
) error

type Hooks struct {
	BeforeOrganizationCreate func(*betterauth.HookContext, *Organization) error
	AfterOrganizationCreate  func(*betterauth.HookContext, Organization) error
	BeforeMemberCreate       func(*betterauth.HookContext, *Member) error
	AfterMemberCreate        func(*betterauth.HookContext, Member) error
	BeforeInvitationCreate   func(*betterauth.HookContext, *Invitation) error
	AfterInvitationCreate    func(*betterauth.HookContext, Invitation) error
}

type Config struct {
	CreatorRole                   string
	Roles                         map[string]Role
	Statements                    map[string][]string
	InvitationTTL                 time.Duration
	MaxOrganizationsPerUser       int
	MaxMembersPerOrganization     int
	MaxInvitationsPerOrganization int
	MaxTeamsPerOrganization       int
	MaxRolesPerOrganization       int
	DeliverInvitation             InvitationDelivery
	Hooks                         Hooks
	Schema                        betterauth.Schema
}

type runtime struct {
	config Config
	schema betterauth.Schema
	roles  map[string]Role
}

func New(config Config) (betterauth.Plugin, error) {
	normalized, roles, err := normalizeConfig(config)
	if err != nil {
		return betterauth.Plugin{}, err
	}
	schema, err := betterauth.MergeSchema(baseSchema(), normalized.Schema)
	if err != nil {
		return betterauth.Plugin{}, fmt.Errorf("organization: schema: %w", err)
	}
	return (&runtime{config: normalized, schema: schema, roles: roles}).plugin(), nil
}

func normalizeConfig(config Config) (Config, map[string]Role, error) {
	config.CreatorRole = strings.ToLower(strings.TrimSpace(config.CreatorRole))
	if config.CreatorRole == "" {
		config.CreatorRole = "owner"
	}
	if !validRoleName(config.CreatorRole) {
		return config, nil, errors.New("organization: invalid creator role")
	}
	if config.InvitationTTL == 0 {
		config.InvitationTTL = 48 * time.Hour
	}
	if config.InvitationTTL < time.Hour || config.InvitationTTL > 30*24*time.Hour {
		return config, nil, errors.New("organization: invitation TTL is out of bounds")
	}
	defaultLimit(&config.MaxOrganizationsPerUser, 100)
	defaultLimit(&config.MaxMembersPerOrganization, 1000)
	defaultLimit(&config.MaxInvitationsPerOrganization, 1000)
	defaultLimit(&config.MaxTeamsPerOrganization, 100)
	defaultLimit(&config.MaxRolesPerOrganization, 100)
	for _, limit := range []int{
		config.MaxOrganizationsPerUser, config.MaxMembersPerOrganization,
		config.MaxInvitationsPerOrganization, config.MaxTeamsPerOrganization,
		config.MaxRolesPerOrganization,
	} {
		if limit < 1 || limit > 100_000 {
			return config, nil, errors.New("organization: configured limit is out of bounds")
		}
	}
	statements := defaultStatements()
	for resource, actions := range config.Statements {
		resource = strings.ToLower(strings.TrimSpace(resource))
		if !validRoleName(resource) || len(actions) == 0 || len(actions) > 100 {
			return config, nil, errors.New("organization: invalid access-control statement")
		}
		values := make([]string, len(actions))
		for index, action := range actions {
			action = strings.ToLower(strings.TrimSpace(action))
			if !validRoleName(action) {
				return config, nil, errors.New("organization: invalid access-control action")
			}
			values[index] = action
		}
		slices.Sort(values)
		statements[resource] = slices.Compact(values)
	}
	config.Statements = statements
	roles := defaultRoles(statements)
	for name, role := range config.Roles {
		name = strings.ToLower(strings.TrimSpace(name))
		if !validRoleName(name) {
			return config, nil, errors.New("organization: invalid static role")
		}
		normalized, err := normalizePermission(role.Permission, statements)
		if err != nil {
			return config, nil, err
		}
		roles[name] = Role{Permission: normalized}
	}
	if _, exists := roles[config.CreatorRole]; !exists {
		return config, nil, errors.New("organization: creator role is not defined")
	}
	config.Roles = cloneRoles(roles)
	config.Schema = cloneSchema(config.Schema)
	return config, roles, nil
}

func defaultLimit(value *int, fallback int) {
	if *value == 0 {
		*value = fallback
	}
}

func validRoleName(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, character := range value {
		if character != '-' && character != '_' &&
			(character < 'a' || character > 'z') &&
			(character < '0' || character > '9') {
			return false
		}
	}
	return true
}

func cloneRoles(input map[string]Role) map[string]Role {
	result := make(map[string]Role, len(input))
	for name, role := range input {
		result[name] = Role{Permission: clonePermission(role.Permission)}
	}
	return result
}

func clonePermission(input Permission) Permission {
	result := make(Permission, len(input))
	for resource, actions := range input {
		result[resource] = slices.Clone(actions)
	}
	return result
}

func cloneSchema(input betterauth.Schema) betterauth.Schema {
	if input == nil {
		return nil
	}
	result := make(betterauth.Schema, len(input))
	for name, model := range input {
		fields := make(map[string]betterauth.FieldSchema, len(model.Fields))
		for field, definition := range model.Fields {
			fields[field] = definition
		}
		model.Fields = fields
		indexes := make([]betterauth.IndexSchema, len(model.Indexes))
		for index, definition := range model.Indexes {
			definition.Fields = slices.Clone(definition.Fields)
			indexes[index] = definition
		}
		model.Indexes = indexes
		result[name] = model
	}
	return result
}

func baseSchema() betterauth.Schema {
	return betterauth.Schema{
		betterauth.ModelSession: {
			Fields: map[string]betterauth.FieldSchema{
				"activeOrganizationId": {Type: betterauth.FieldString},
				"activeTeamId":         {Type: betterauth.FieldString},
			},
		},
		ModelOrganization: {
			Fields: map[string]betterauth.FieldSchema{
				"id":        {Type: betterauth.FieldString, Required: true, Unique: true, Returned: true},
				"name":      {Type: betterauth.FieldString, Required: true, Returned: true},
				"slug":      {Type: betterauth.FieldString, Required: true, Unique: true, Returned: true},
				"logo":      {Type: betterauth.FieldString, Returned: true},
				"metadata":  {Type: betterauth.FieldJSON, Returned: true},
				"createdAt": {Type: betterauth.FieldDate, Required: true, Returned: true},
				"updatedAt": {Type: betterauth.FieldDate, Required: true, Returned: true},
			},
		},
		ModelMember: {
			Fields: map[string]betterauth.FieldSchema{
				"id":             {Type: betterauth.FieldString, Required: true, Unique: true, Returned: true},
				"organizationId": {Type: betterauth.FieldString, Required: true, Index: true, References: ModelOrganization, Returned: true},
				"userId":         {Type: betterauth.FieldString, Required: true, Index: true, References: betterauth.ModelUser, Returned: true},
				"role":           {Type: betterauth.FieldString, Required: true, Returned: true},
				"createdAt":      {Type: betterauth.FieldDate, Required: true, Returned: true},
				"updatedAt":      {Type: betterauth.FieldDate, Required: true, Returned: true},
			},
			Indexes: []betterauth.IndexSchema{{
				Name:   "member_organization_user_unique",
				Fields: []string{"organizationId", "userId"}, Unique: true,
			}},
		},
		ModelInvitation: {
			Fields: map[string]betterauth.FieldSchema{
				"id":             {Type: betterauth.FieldString, Required: true, Unique: true, Returned: true},
				"organizationId": {Type: betterauth.FieldString, Required: true, Index: true, References: ModelOrganization, Returned: true},
				"email":          {Type: betterauth.FieldString, Required: true, Index: true, Returned: true},
				"role":           {Type: betterauth.FieldString, Required: true, Returned: true},
				"teamId":         {Type: betterauth.FieldString, Returned: true},
				"status":         {Type: betterauth.FieldString, Required: true, Returned: true},
				"inviterId":      {Type: betterauth.FieldString, Required: true, References: betterauth.ModelUser, Returned: true},
				"expiresAt":      {Type: betterauth.FieldDate, Required: true, Returned: true},
				"createdAt":      {Type: betterauth.FieldDate, Required: true, Returned: true},
				"updatedAt":      {Type: betterauth.FieldDate, Required: true, Returned: true},
			},
			Indexes: []betterauth.IndexSchema{{
				Name:   "invitation_organization_email_unique",
				Fields: []string{"organizationId", "email"}, Unique: true,
			}},
		},
		ModelTeam: {
			Fields: map[string]betterauth.FieldSchema{
				"id":             {Type: betterauth.FieldString, Required: true, Unique: true, Returned: true},
				"organizationId": {Type: betterauth.FieldString, Required: true, Index: true, References: ModelOrganization, Returned: true},
				"name":           {Type: betterauth.FieldString, Required: true, Returned: true},
				"createdAt":      {Type: betterauth.FieldDate, Required: true, Returned: true},
				"updatedAt":      {Type: betterauth.FieldDate, Required: true, Returned: true},
			},
			Indexes: []betterauth.IndexSchema{{
				Name:   "team_organization_name_unique",
				Fields: []string{"organizationId", "name"}, Unique: true,
			}},
		},
		ModelTeamMember: {
			Fields: map[string]betterauth.FieldSchema{
				"id":        {Type: betterauth.FieldString, Required: true, Unique: true, Returned: true},
				"teamId":    {Type: betterauth.FieldString, Required: true, Index: true, References: ModelTeam, Returned: true},
				"userId":    {Type: betterauth.FieldString, Required: true, Index: true, References: betterauth.ModelUser, Returned: true},
				"createdAt": {Type: betterauth.FieldDate, Required: true, Returned: true},
			},
			Indexes: []betterauth.IndexSchema{{
				Name:   "team_member_team_user_unique",
				Fields: []string{"teamId", "userId"}, Unique: true,
			}},
		},
		ModelOrganizationRole: {
			Fields: map[string]betterauth.FieldSchema{
				"id":             {Type: betterauth.FieldString, Required: true, Unique: true, Returned: true},
				"organizationId": {Type: betterauth.FieldString, Required: true, Index: true, References: ModelOrganization, Returned: true},
				"role":           {Type: betterauth.FieldString, Required: true, Returned: true},
				"permission":     {Type: betterauth.FieldJSON, Required: true, Returned: true},
				"createdAt":      {Type: betterauth.FieldDate, Required: true, Returned: true},
				"updatedAt":      {Type: betterauth.FieldDate, Required: true, Returned: true},
			},
			Indexes: []betterauth.IndexSchema{{
				Name:   "organization_role_name_unique",
				Fields: []string{"organizationId", "role"}, Unique: true,
			}},
		},
	}
}
