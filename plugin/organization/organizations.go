package organization

import (
	"errors"
	"net/http"
	"strings"

	betterauth "github.com/eadwinCode/better-auth-go"
)

func (instance *runtime) createOrganization(
	context *betterauth.HookContext,
) (*betterauth.PluginResponse, error) {
	now := context.Clock.Now().UTC()
	id, err := context.GenerateID()
	if err != nil {
		return nil, internalError(err)
	}
	organization := Organization{
		ID: id, Name: bodyString(context, "name"),
		Slug: strings.ToLower(bodyString(context, "slug")),
		Logo: bodyString(context, "logo"), Metadata: bodyObject(context, "metadata"),
		CreatedAt: now, UpdatedAt: now,
	}
	memberID, err := context.GenerateID()
	if err != nil {
		return nil, internalError(err)
	}
	member := Member{
		ID: memberID, OrganizationID: id, UserID: context.User.ID,
		Role: instance.config.CreatorRole, CreatedAt: now, UpdatedAt: now,
	}
	var created Organization
	err = context.Database.Transaction(context.Context, func(tx betterauth.DatabaseAdapter) error {
		count, countErr := tx.Count(context.Context, betterauth.CountQuery{
			Model: ModelMember,
			Where: []betterauth.Where{betterauth.Eq("userId", context.User.ID)},
		})
		if countErr != nil {
			return countErr
		}
		if count >= int64(instance.config.MaxOrganizationsPerUser) {
			return conflict("The organization limit has been reached.", nil)
		}
		hookContext := contextWithDatabase(context, tx)
		event := MutationEvent{
			Action: "organization.created", OrganizationID: id,
			SubjectID: id, Data: organizationData(organization),
		}
		if instance.config.Hooks.BeforeMutation != nil {
			if hookErr := instance.config.Hooks.BeforeMutation(hookContext, event); hookErr != nil {
				return hookErr
			}
		}
		if instance.config.Hooks.BeforeOrganizationCreate != nil {
			if hookErr := instance.config.Hooks.BeforeOrganizationCreate(hookContext, &organization); hookErr != nil {
				return hookErr
			}
			organization.ID = id
			organization.Slug = strings.ToLower(strings.TrimSpace(organization.Slug))
			organization.Name = strings.TrimSpace(organization.Name)
			organization.CreatedAt = now
			organization.UpdatedAt = now
			if organization.Name == "" || len(organization.Name) > 128 ||
				organization.Slug == "" || len(organization.Slug) > 128 {
				return badRequest("The organization hook produced invalid data.", nil)
			}
		}
		row, createErr := tx.Create(context.Context, betterauth.CreateQuery{
			Model: ModelOrganization, Data: organizationRecord(organization),
			ForceAllowID: true,
		})
		if createErr != nil {
			return createErr
		}
		created, createErr = organizationFromRecord(row)
		if createErr != nil {
			return createErr
		}
		if instance.config.Hooks.BeforeMemberCreate != nil {
			if hookErr := instance.config.Hooks.BeforeMemberCreate(hookContext, &member); hookErr != nil {
				return hookErr
			}
			member.ID = memberID
			member.OrganizationID = id
			member.UserID = context.User.ID
			member.Role = instance.config.CreatorRole
			member.CreatedAt = now
			member.UpdatedAt = now
		}
		memberRow, createErr := tx.Create(context.Context, betterauth.CreateQuery{
			Model: ModelMember, Data: memberRecord(member), ForceAllowID: true,
		})
		if createErr != nil {
			return createErr
		}
		member, createErr = memberFromRecord(memberRow)
		if createErr != nil {
			return createErr
		}
		if createErr = instance.audit(
			context, tx, "organization.created", id, id,
			map[string]any{"slug": created.Slug},
		); createErr != nil {
			return createErr
		}
		if instance.config.Hooks.AfterMemberCreate != nil {
			if hookErr := instance.config.Hooks.AfterMemberCreate(hookContext, member); hookErr != nil {
				return hookErr
			}
		}
		if instance.config.Hooks.AfterOrganizationCreate != nil {
			if hookErr := instance.config.Hooks.AfterOrganizationCreate(hookContext, created); hookErr != nil {
				return hookErr
			}
		}
		if instance.config.Hooks.AfterMutation != nil {
			event.Data = organizationData(created)
			if hookErr := instance.config.Hooks.AfterMutation(hookContext, event); hookErr != nil {
				return hookErr
			}
		}
		return nil
	})
	if err != nil {
		return nil, mapMutationError(err)
	}
	return betterauth.JSONResponse(http.StatusOK, created)
}

func (instance *runtime) checkSlug(
	context *betterauth.HookContext,
) (*betterauth.PluginResponse, error) {
	slug := strings.ToLower(bodyString(context, "slug"))
	row, err := context.Database.FindOne(context.Context, betterauth.FindOneQuery{
		Model:  ModelOrganization,
		Where:  []betterauth.Where{betterauth.Eq("slug", slug)},
		Select: []string{"id"},
	})
	if err != nil && !errors.Is(err, betterauth.ErrNotFound) {
		return nil, internalError(err)
	}
	return betterauth.JSONResponse(http.StatusOK, map[string]bool{"status": row == nil})
}

func (instance *runtime) updateOrganization(
	context *betterauth.HookContext,
) (*betterauth.PluginResponse, error) {
	organizationID := bodyString(context, "organizationId")
	if _, err := instance.authorize(
		context, context.Database, organizationID, "organization", "update",
	); err != nil {
		return nil, err
	}
	update := betterauth.Record{"updatedAt": context.Clock.Now().UTC()}
	if value, exists := body(context)["name"]; exists {
		update["name"] = strings.TrimSpace(value.(string))
	}
	if value, exists := body(context)["slug"]; exists {
		update["slug"] = strings.ToLower(strings.TrimSpace(value.(string)))
	}
	if value, exists := body(context)["logo"]; exists {
		update["logo"] = value
	}
	if value, exists := body(context)["metadata"]; exists {
		update["metadata"] = value
	}
	if len(update) == 1 {
		return nil, badRequest("At least one organization field must be updated.", nil)
	}
	var updated Organization
	err := context.Database.Transaction(context.Context, func(tx betterauth.DatabaseAdapter) error {
		if _, authorizeErr := instance.authorize(
			context, tx, organizationID, "organization", "update",
		); authorizeErr != nil {
			return authorizeErr
		}
		event := MutationEvent{
			Action: "organization.updated", OrganizationID: organizationID,
			SubjectID: organizationID, Data: cloneRecord(update),
		}
		hookContext := contextWithDatabase(context, tx)
		if instance.config.Hooks.BeforeMutation != nil {
			if err := instance.config.Hooks.BeforeMutation(hookContext, event); err != nil {
				return err
			}
		}
		if _, authorizeErr := instance.authorize(
			context, tx, organizationID, "organization", "update",
		); authorizeErr != nil {
			return authorizeErr
		}
		row, err := tx.Update(context.Context, betterauth.UpdateQuery{
			Model:  ModelOrganization,
			Where:  []betterauth.Where{betterauth.Eq("id", organizationID)},
			Update: update,
		})
		if err != nil || row == nil {
			if err == nil {
				err = betterauth.ErrNotFound
			}
			return err
		}
		updated, err = organizationFromRecord(row)
		if err != nil {
			return err
		}
		if err = instance.audit(
			context, tx, "organization.updated", organizationID, organizationID, nil,
		); err != nil {
			return err
		}
		if instance.config.Hooks.AfterMutation != nil {
			event.Data = organizationData(updated)
			return instance.config.Hooks.AfterMutation(hookContext, event)
		}
		return nil
	})
	if err != nil {
		return nil, mapMutationError(err)
	}
	return betterauth.JSONResponse(http.StatusOK, updated)
}

func (instance *runtime) deleteOrganization(
	context *betterauth.HookContext,
) (*betterauth.PluginResponse, error) {
	organizationID := bodyString(context, "organizationId")
	if _, err := instance.authorize(
		context, context.Database, organizationID, "organization", "delete",
	); err != nil {
		return nil, err
	}
	err := context.Database.Transaction(context.Context, func(tx betterauth.DatabaseAdapter) error {
		if _, authorizeErr := instance.authorize(
			context, tx, organizationID, "organization", "delete",
		); authorizeErr != nil {
			return authorizeErr
		}
		event := MutationEvent{
			Action: "organization.deleted", OrganizationID: organizationID,
			SubjectID: organizationID,
		}
		hookContext := contextWithDatabase(context, tx)
		if instance.config.Hooks.BeforeMutation != nil {
			if err := instance.config.Hooks.BeforeMutation(hookContext, event); err != nil {
				return err
			}
		}
		if _, authorizeErr := instance.authorize(
			context, tx, organizationID, "organization", "delete",
		); authorizeErr != nil {
			return authorizeErr
		}
		teams, err := findManyBounded(
			context, tx, ModelTeam,
			[]betterauth.Where{betterauth.Eq("organizationId", organizationID)},
			instance.config.MaxTeamsPerOrganization,
		)
		if err != nil {
			return err
		}
		for _, row := range teams {
			teamID, fieldErr := requiredString(row, "id")
			if fieldErr != nil {
				return fieldErr
			}
			if _, err = tx.DeleteMany(context.Context, betterauth.DeleteQuery{
				Model: ModelTeamMember,
				Where: []betterauth.Where{betterauth.Eq("teamId", teamID)},
			}); err != nil {
				return err
			}
		}
		for _, model := range []string{
			ModelInvitation, ModelMember, ModelTeam, ModelOrganizationRole,
		} {
			if _, err = tx.DeleteMany(context.Context, betterauth.DeleteQuery{
				Model: model,
				Where: []betterauth.Where{betterauth.Eq("organizationId", organizationID)},
			}); err != nil {
				return err
			}
		}
		if err = tx.Delete(context.Context, betterauth.DeleteQuery{
			Model: ModelOrganization,
			Where: []betterauth.Where{betterauth.Eq("id", organizationID)},
		}); err != nil {
			return err
		}
		if _, err = tx.UpdateMany(context.Context, betterauth.UpdateQuery{
			Model: betterauth.ModelSession,
			Where: []betterauth.Where{betterauth.Eq("activeOrganizationId", organizationID)},
			Update: betterauth.Record{
				"activeOrganizationId": nil, "activeTeamId": nil,
				"updatedAt": context.Clock.Now().UTC(),
			},
		}); err != nil {
			return err
		}
		if err = instance.audit(
			context, tx, "organization.deleted", organizationID, organizationID, nil,
		); err != nil {
			return err
		}
		if instance.config.Hooks.AfterMutation != nil {
			return instance.config.Hooks.AfterMutation(hookContext, event)
		}
		return nil
	})
	if err != nil {
		return nil, mapMutationError(err)
	}
	return betterauth.JSONResponse(http.StatusOK, map[string]bool{"success": true})
}

func (instance *runtime) getFullOrganization(
	context *betterauth.HookContext,
) (*betterauth.PluginResponse, error) {
	organizationID, err := instance.selectedOrganizationID(context)
	if err != nil {
		return nil, err
	}
	if _, err = instance.authorize(
		context, context.Database, organizationID, "organization", "read",
	); err != nil {
		return nil, err
	}
	row, err := context.Database.FindOne(context.Context, betterauth.FindOneQuery{
		Model: ModelOrganization,
		Where: []betterauth.Where{betterauth.Eq("id", organizationID)},
	})
	if err != nil || row == nil {
		return nil, notFound(err)
	}
	organization, err := organizationFromRecord(row)
	if err != nil {
		return nil, internalError(err)
	}
	memberRows, err := context.Database.FindMany(context.Context, betterauth.FindManyQuery{
		Model: ModelMember,
		Where: []betterauth.Where{betterauth.Eq("organizationId", organizationID)},
		Limit: adapterPageLimit(instance.config.MaxMembersPerOrganization),
	})
	if err != nil {
		return nil, internalError(err)
	}
	teamRows, err := context.Database.FindMany(context.Context, betterauth.FindManyQuery{
		Model: ModelTeam,
		Where: []betterauth.Where{betterauth.Eq("organizationId", organizationID)},
		Limit: adapterPageLimit(instance.config.MaxTeamsPerOrganization),
	})
	if err != nil {
		return nil, internalError(err)
	}
	members, err := rowsToMembers(memberRows)
	if err != nil {
		return nil, internalError(err)
	}
	teams, err := rowsToTeams(teamRows)
	if err != nil {
		return nil, internalError(err)
	}
	return betterauth.JSONResponse(http.StatusOK, FullOrganization{
		Organization: organization, Members: members, Teams: teams,
	})
}

func (instance *runtime) setActiveOrganization(
	context *betterauth.HookContext,
) (*betterauth.PluginResponse, error) {
	organizationID := bodyString(context, "organizationId")
	var organization Organization
	if organizationID != "" {
		if _, err := instance.member(
			context, context.Database, organizationID, context.User.ID,
		); err != nil {
			return nil, forbidden(err)
		}
		organizationRow, err := context.Database.FindOne(
			context.Context, betterauth.FindOneQuery{
				Model: ModelOrganization,
				Where: []betterauth.Where{betterauth.Eq("id", organizationID)},
			},
		)
		if err != nil || organizationRow == nil {
			return nil, notFound(err)
		}
		organization, err = organizationFromRecord(organizationRow)
		if err != nil {
			return nil, internalError(err)
		}
	}
	var value any
	if organizationID != "" {
		value = organization
	}
	response, err := betterauth.JSONResponse(http.StatusOK, value)
	if err != nil {
		return nil, err
	}
	if err = instance.rotateActiveSession(
		context, response, organizationID, "", "organization.active.changed",
	); err != nil {
		return nil, err
	}
	return response, nil
}

func (instance *runtime) listOrganizations(
	context *betterauth.HookContext,
) (*betterauth.PluginResponse, error) {
	limit, offset, err := queryPage(context, instance.config.MaxOrganizationsPerUser)
	if err != nil {
		return nil, err
	}
	memberRows, err := context.Database.FindMany(context.Context, betterauth.FindManyQuery{
		Model: ModelMember,
		Where: []betterauth.Where{betterauth.Eq("userId", context.User.ID)},
		Limit: limit, Offset: offset,
	})
	if err != nil {
		return nil, internalError(err)
	}
	result := make([]Organization, 0, len(memberRows))
	for _, memberRow := range memberRows {
		organizationID, fieldErr := requiredString(memberRow, "organizationId")
		if fieldErr != nil {
			return nil, internalError(fieldErr)
		}
		row, findErr := context.Database.FindOne(context.Context, betterauth.FindOneQuery{
			Model: ModelOrganization,
			Where: []betterauth.Where{betterauth.Eq("id", organizationID)},
		})
		if errors.Is(findErr, betterauth.ErrNotFound) || row == nil {
			continue
		}
		if findErr != nil {
			return nil, internalError(findErr)
		}
		organization, parseErr := organizationFromRecord(row)
		if parseErr != nil {
			return nil, internalError(parseErr)
		}
		result = append(result, organization)
	}
	return betterauth.JSONResponse(http.StatusOK, result)
}

func organizationRecord(value Organization) betterauth.Record {
	return betterauth.Record{
		"id": value.ID, "name": value.Name, "slug": value.Slug, "logo": value.Logo,
		"metadata": value.Metadata, "createdAt": value.CreatedAt, "updatedAt": value.UpdatedAt,
	}
}

func memberRecord(value Member) betterauth.Record {
	return betterauth.Record{
		"id": value.ID, "organizationId": value.OrganizationID,
		"userId": value.UserID, "role": value.Role,
		"createdAt": value.CreatedAt, "updatedAt": value.UpdatedAt,
	}
}

func organizationData(value Organization) map[string]any {
	return map[string]any{
		"id": value.ID, "name": value.Name, "slug": value.Slug,
		"logo": value.Logo, "metadata": value.Metadata,
	}
}

func cloneRecord(value betterauth.Record) map[string]any {
	result := make(map[string]any, len(value))
	for key, item := range value {
		result[key] = item
	}
	return result
}

func contextWithDatabase(
	context *betterauth.HookContext,
	database betterauth.DatabaseAdapter,
) *betterauth.HookContext {
	copyContext := *context
	copyContext.Database = database
	return &copyContext
}

func mapMutationError(err error) error {
	if err == nil {
		return nil
	}
	var public *betterauth.Error
	if errors.As(err, &public) {
		return err
	}
	if errors.Is(err, betterauth.ErrNotFound) {
		return notFound(err)
	}
	if errors.Is(err, betterauth.ErrConflict) {
		return conflict("The organization resource already exists.", err)
	}
	return internalError(err)
}

func (instance *runtime) rotateActiveSession(
	context *betterauth.HookContext,
	response *betterauth.PluginResponse,
	organizationID, teamID, action string,
) error {
	if context.IssueSession == nil {
		return internalError(errors.New("organization: session rotation is unavailable"))
	}
	event := MutationEvent{
		Action: action, OrganizationID: organizationID,
		SubjectID: context.User.ID, Data: map[string]any{"teamId": teamID},
	}
	if instance.config.Hooks.BeforeMutation != nil {
		if err := instance.config.Hooks.BeforeMutation(context, event); err != nil {
			return err
		}
	}
	issued, err := context.IssueSession(context.User.ID)
	if err != nil {
		return internalError(err)
	}
	update := betterauth.Record{
		"activeOrganizationId": nil, "activeTeamId": nil,
		"updatedAt": context.Clock.Now().UTC(),
	}
	if organizationID != "" {
		update["activeOrganizationId"] = organizationID
	}
	if teamID != "" {
		update["activeTeamId"] = teamID
	}
	err = context.Database.Transaction(context.Context, func(tx betterauth.DatabaseAdapter) error {
		if organizationID != "" {
			if _, membershipErr := instance.member(
				context, tx, organizationID, context.User.ID,
			); membershipErr != nil {
				return forbidden(membershipErr)
			}
		}
		if teamID != "" {
			teamRow, teamErr := tx.FindOne(context.Context, betterauth.FindOneQuery{
				Model: ModelTeam,
				Where: []betterauth.Where{
					betterauth.Eq("id", teamID),
					betterauth.Eq("organizationId", organizationID),
				},
				Select: []string{"id"},
			})
			if teamErr != nil || teamRow == nil {
				return forbidden(teamErr)
			}
			membershipRow, membershipErr := tx.FindOne(
				context.Context, betterauth.FindOneQuery{
					Model: ModelTeamMember,
					Where: []betterauth.Where{
						betterauth.Eq("teamId", teamID),
						betterauth.Eq("userId", context.User.ID),
					},
					Select: []string{"id"},
				},
			)
			if membershipErr != nil || membershipRow == nil {
				return forbidden(membershipErr)
			}
		}
		row, updateErr := tx.Update(context.Context, betterauth.UpdateQuery{
			Model: betterauth.ModelSession,
			Where: []betterauth.Where{
				betterauth.Eq("id", issued.Session.ID),
				betterauth.Eq("userId", context.User.ID),
				betterauth.Eq("revokedAt", nil),
			},
			Update: update,
		})
		if updateErr != nil || row == nil {
			if updateErr == nil {
				updateErr = betterauth.ErrNotFound
			}
			return updateErr
		}
		if auditErr := instance.audit(
			context, tx, action, context.User.ID, organizationID,
			map[string]any{"teamId": teamID, "newSessionId": issued.Session.ID},
		); auditErr != nil {
			return auditErr
		}
		if instance.config.Hooks.AfterMutation != nil {
			return instance.config.Hooks.AfterMutation(
				contextWithDatabase(context, tx), event,
			)
		}
		return nil
	})
	if err != nil {
		return internalError(err)
	}
	if err = issued.Apply(response); err != nil {
		return internalError(err)
	}
	return nil
}
