// Package organization provides Better Auth-shaped multi-tenant organization
// management and authorization.
package organization

import (
	"context"
	"crypto/rand"
	"encoding/base64"
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
	BeforeMutation           func(*betterauth.HookContext, MutationEvent) error
	AfterMutation            func(*betterauth.HookContext, MutationEvent) error
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

// Manager exposes the plugin descriptor and trusted server-only operations.
type Manager struct {
	runtime *runtime
}

type AddMemberInput struct {
	Database       betterauth.DatabaseAdapter
	OrganizationID string
	UserID         string
	Roles          []string
	ActorUserID    string
	Clock          betterauth.Clock
	GenerateID     func() (string, error)
}

type wallClock struct{}

func (wallClock) Now() time.Time { return time.Now() }

func New(config Config) (betterauth.Plugin, error) {
	manager, err := NewManager(config)
	if err != nil {
		return betterauth.Plugin{}, err
	}
	return manager.Plugin(), nil
}

func NewManager(config Config) (*Manager, error) {
	normalized, roles, err := normalizeConfig(config)
	if err != nil {
		return nil, err
	}
	schema, err := betterauth.MergeSchema(baseSchema(), normalized.Schema)
	if err != nil {
		return nil, fmt.Errorf("organization: schema: %w", err)
	}
	return &Manager{runtime: &runtime{
		config: normalized, schema: schema, roles: roles,
	}}, nil
}

func (manager *Manager) Plugin() betterauth.Plugin {
	if manager == nil || manager.runtime == nil {
		return betterauth.Plugin{}
	}
	return manager.runtime.plugin()
}

// AddMember creates a membership from trusted server code. It is deliberately
// not exposed over HTTP. The caller is responsible for its own authorization.
func (manager *Manager) AddMember(
	ctx context.Context,
	input AddMemberInput,
) (Member, error) {
	if manager == nil || manager.runtime == nil || input.Database == nil {
		return Member{}, errors.New("organization: manager and database are required")
	}
	input.OrganizationID = strings.TrimSpace(input.OrganizationID)
	input.UserID = strings.TrimSpace(input.UserID)
	input.ActorUserID = strings.TrimSpace(input.ActorUserID)
	role, err := canonicalRoles(input.Roles)
	if input.OrganizationID == "" || input.UserID == "" ||
		input.ActorUserID == "" || err != nil {
		return Member{}, errors.New(
			"organization: valid organization, user, actor, and role are required",
		)
	}
	now := time.Now().UTC()
	if input.Clock != nil {
		now = input.Clock.Now().UTC()
	} else {
		input.Clock = wallClock{}
	}
	generateID := input.GenerateID
	if generateID == nil {
		generateID = randomID
	}
	id, err := generateID()
	if err != nil {
		return Member{}, fmt.Errorf("organization: generate member id: %w", err)
	}
	auditID, err := generateID()
	if err != nil {
		return Member{}, fmt.Errorf("organization: generate audit id: %w", err)
	}
	member := Member{
		ID: id, OrganizationID: input.OrganizationID, UserID: input.UserID,
		Role: role, CreatedAt: now, UpdatedAt: now,
	}
	var created Member
	err = input.Database.Transaction(ctx, func(tx betterauth.DatabaseAdapter) error {
		if organization, findErr := tx.FindOne(ctx, betterauth.FindOneQuery{
			Model:  ModelOrganization,
			Where:  []betterauth.Where{betterauth.Eq("id", input.OrganizationID)},
			Select: []string{"id"},
		}); findErr != nil || organization == nil {
			if findErr == nil {
				findErr = betterauth.ErrNotFound
			}
			return findErr
		}
		if user, findErr := tx.FindOne(ctx, betterauth.FindOneQuery{
			Model:  betterauth.ModelUser,
			Where:  []betterauth.Where{betterauth.Eq("id", input.UserID)},
			Select: []string{"id"},
		}); findErr != nil || user == nil {
			if findErr == nil {
				findErr = betterauth.ErrNotFound
			}
			return findErr
		}
		count, countErr := tx.Count(ctx, betterauth.CountQuery{
			Model: ModelMember,
			Where: []betterauth.Where{
				betterauth.Eq("organizationId", input.OrganizationID),
			},
		})
		if countErr != nil {
			return countErr
		}
		if count >= int64(manager.runtime.config.MaxMembersPerOrganization) {
			return errors.New("organization: member limit reached")
		}
		for _, name := range strings.Split(role, ",") {
			if _, exists := manager.runtime.roles[name]; exists {
				continue
			}
			dynamic, findErr := tx.FindOne(ctx, betterauth.FindOneQuery{
				Model: ModelOrganizationRole,
				Where: []betterauth.Where{
					betterauth.Eq("organizationId", input.OrganizationID),
					betterauth.Eq("role", name),
				},
				Select: []string{"id"},
			})
			if findErr != nil || dynamic == nil {
				if findErr == nil {
					findErr = errors.New("organization: role is not defined")
				}
				return findErr
			}
		}
		hookContext := &betterauth.HookContext{
			Context: ctx, Database: tx, Clock: input.Clock, GenerateID: generateID,
			User: &betterauth.User{ID: input.ActorUserID},
		}
		event := MutationEvent{
			Action:         "organization.member.added",
			OrganizationID: input.OrganizationID, SubjectID: input.UserID,
			Data: map[string]any{"memberId": member.ID, "role": member.Role},
		}
		if manager.runtime.config.Hooks.BeforeMutation != nil {
			if hookErr := manager.runtime.config.Hooks.BeforeMutation(
				hookContext, event,
			); hookErr != nil {
				return hookErr
			}
		}
		if manager.runtime.config.Hooks.BeforeMemberCreate != nil {
			if hookErr := manager.runtime.config.Hooks.BeforeMemberCreate(
				hookContext, &member,
			); hookErr != nil {
				return hookErr
			}
			member.ID = id
			member.OrganizationID = input.OrganizationID
			member.UserID = input.UserID
			member.Role = role
			member.CreatedAt = now
			member.UpdatedAt = now
		}
		row, createErr := tx.Create(ctx, betterauth.CreateQuery{
			Model: ModelMember, Data: memberRecord(member), ForceAllowID: true,
		})
		if createErr != nil {
			return createErr
		}
		created, createErr = memberFromRecord(row)
		if createErr != nil {
			return createErr
		}
		_, createErr = tx.Create(ctx, betterauth.CreateQuery{
			Model: betterauth.ModelAuditEvent,
			Data: betterauth.Record{
				"id": auditID, "schemaVersion": float64(1),
				"action":      "organization.member.added",
				"actorUserId": input.ActorUserID, "subjectUserId": input.UserID,
				"occurredAt": now, "request": map[string]any{},
				"details": map[string]any{
					"organizationId": input.OrganizationID, "memberId": created.ID,
				},
			},
			ForceAllowID: true,
		})
		if createErr != nil {
			return createErr
		}
		if manager.runtime.config.Hooks.AfterMemberCreate != nil {
			if hookErr := manager.runtime.config.Hooks.AfterMemberCreate(
				hookContext, created,
			); hookErr != nil {
				return hookErr
			}
		}
		if manager.runtime.config.Hooks.AfterMutation != nil {
			return manager.runtime.config.Hooks.AfterMutation(hookContext, event)
		}
		return nil
	})
	return created, err
}

func randomID() (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
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
