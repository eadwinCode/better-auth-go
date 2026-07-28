package organization

import (
	"errors"
	"net/http"
	"strings"

	betterauth "github.com/eadwinCode/better-auth-go"
)

func (instance *runtime) createTeam(
	context *betterauth.HookContext,
) (*betterauth.PluginResponse, error) {
	organizationID, err := instance.selectedOrganizationID(context)
	if err != nil {
		return nil, err
	}
	if _, err = instance.authorize(
		context, context.Database, organizationID, "team", "create",
	); err != nil {
		return nil, err
	}
	id, err := context.GenerateID()
	if err != nil {
		return nil, internalError(err)
	}
	now := context.Clock.Now().UTC()
	team := Team{
		ID: id, OrganizationID: organizationID, Name: bodyString(context, "name"),
		CreatedAt: now, UpdatedAt: now,
	}
	var created Team
	err = context.Database.Transaction(context.Context, func(tx betterauth.DatabaseAdapter) error {
		if _, authorizeErr := instance.authorize(
			context, tx, organizationID, "team", "create",
		); authorizeErr != nil {
			return authorizeErr
		}
		count, countErr := tx.Count(context.Context, betterauth.CountQuery{
			Model: ModelTeam,
			Where: []betterauth.Where{betterauth.Eq("organizationId", organizationID)},
		})
		if countErr != nil {
			return countErr
		}
		if count >= int64(instance.config.MaxTeamsPerOrganization) {
			return conflict("The organization team limit has been reached.", nil)
		}
		event := MutationEvent{
			Action: "organization.team.created", OrganizationID: organizationID,
			SubjectID: id, Data: map[string]any{"name": team.Name},
		}
		hookContext := contextWithDatabase(context, tx)
		if instance.config.Hooks.BeforeMutation != nil {
			if hookErr := instance.config.Hooks.BeforeMutation(hookContext, event); hookErr != nil {
				return hookErr
			}
		}
		if _, authorizeErr := instance.authorize(
			context, tx, organizationID, "team", "create",
		); authorizeErr != nil {
			return authorizeErr
		}
		row, createErr := tx.Create(context.Context, betterauth.CreateQuery{
			Model: ModelTeam,
			Data: betterauth.Record{
				"id": team.ID, "organizationId": team.OrganizationID,
				"name": team.Name, "createdAt": team.CreatedAt, "updatedAt": team.UpdatedAt,
			},
			ForceAllowID: true,
		})
		if createErr != nil {
			return createErr
		}
		created, createErr = teamFromRecord(row)
		if createErr != nil {
			return createErr
		}
		if createErr = instance.audit(
			context, tx, "organization.team.created", created.ID,
			organizationID, map[string]any{"name": created.Name},
		); createErr != nil {
			return createErr
		}
		if instance.config.Hooks.AfterMutation != nil {
			event.Data = map[string]any{"name": created.Name}
			return instance.config.Hooks.AfterMutation(hookContext, event)
		}
		return nil
	})
	if err != nil {
		return nil, mapMutationError(err)
	}
	return betterauth.JSONResponse(http.StatusOK, created)
}

func (instance *runtime) removeTeam(
	context *betterauth.HookContext,
) (*betterauth.PluginResponse, error) {
	teamID := bodyString(context, "teamId")
	team, err := findTeamByID(context, context.Database, teamID)
	if err != nil {
		return nil, notFound(err)
	}
	if _, err = instance.authorize(
		context, context.Database, team.OrganizationID, "team", "delete",
	); err != nil {
		return nil, err
	}
	err = context.Database.Transaction(context.Context, func(tx betterauth.DatabaseAdapter) error {
		if _, authorizeErr := instance.authorize(
			context, tx, team.OrganizationID, "team", "delete",
		); authorizeErr != nil {
			return authorizeErr
		}
		event := MutationEvent{
			Action: "organization.team.removed", OrganizationID: team.OrganizationID,
			SubjectID: team.ID, Data: map[string]any{"name": team.Name},
		}
		hookContext := contextWithDatabase(context, tx)
		if instance.config.Hooks.BeforeMutation != nil {
			if hookErr := instance.config.Hooks.BeforeMutation(hookContext, event); hookErr != nil {
				return hookErr
			}
		}
		if _, authorizeErr := instance.authorize(
			context, tx, team.OrganizationID, "team", "delete",
		); authorizeErr != nil {
			return authorizeErr
		}
		if _, deleteErr := tx.DeleteMany(context.Context, betterauth.DeleteQuery{
			Model: ModelTeamMember,
			Where: []betterauth.Where{betterauth.Eq("teamId", team.ID)},
		}); deleteErr != nil {
			return deleteErr
		}
		if deleteErr := tx.Delete(context.Context, betterauth.DeleteQuery{
			Model: ModelTeam,
			Where: []betterauth.Where{
				betterauth.Eq("id", team.ID),
				betterauth.Eq("organizationId", team.OrganizationID),
			},
		}); deleteErr != nil {
			return deleteErr
		}
		if _, updateErr := tx.UpdateMany(context.Context, betterauth.UpdateQuery{
			Model: betterauth.ModelSession,
			Where: []betterauth.Where{betterauth.Eq("activeTeamId", team.ID)},
			Update: betterauth.Record{
				"activeTeamId": nil, "updatedAt": context.Clock.Now().UTC(),
			},
		}); updateErr != nil {
			return updateErr
		}
		if auditErr := instance.audit(
			context, tx, "organization.team.removed", team.ID,
			team.OrganizationID, map[string]any{"name": team.Name},
		); auditErr != nil {
			return auditErr
		}
		if instance.config.Hooks.AfterMutation != nil {
			return instance.config.Hooks.AfterMutation(hookContext, event)
		}
		return nil
	})
	if err != nil {
		return nil, mapMutationError(err)
	}
	return betterauth.JSONResponse(http.StatusOK, team)
}

func (instance *runtime) updateTeam(
	context *betterauth.HookContext,
) (*betterauth.PluginResponse, error) {
	teamID := bodyString(context, "teamId")
	team, err := findTeamByID(context, context.Database, teamID)
	if err != nil {
		return nil, notFound(err)
	}
	if _, err = instance.authorize(
		context, context.Database, team.OrganizationID, "team", "update",
	); err != nil {
		return nil, err
	}
	var updated Team
	err = context.Database.Transaction(context.Context, func(tx betterauth.DatabaseAdapter) error {
		if _, authorizeErr := instance.authorize(
			context, tx, team.OrganizationID, "team", "update",
		); authorizeErr != nil {
			return authorizeErr
		}
		event := MutationEvent{
			Action: "organization.team.updated", OrganizationID: team.OrganizationID,
			SubjectID: team.ID, Data: map[string]any{"name": bodyString(context, "name")},
		}
		hookContext := contextWithDatabase(context, tx)
		if instance.config.Hooks.BeforeMutation != nil {
			if hookErr := instance.config.Hooks.BeforeMutation(hookContext, event); hookErr != nil {
				return hookErr
			}
		}
		if _, authorizeErr := instance.authorize(
			context, tx, team.OrganizationID, "team", "update",
		); authorizeErr != nil {
			return authorizeErr
		}
		row, updateErr := tx.Update(context.Context, betterauth.UpdateQuery{
			Model: ModelTeam,
			Where: []betterauth.Where{
				betterauth.Eq("id", team.ID),
				betterauth.Eq("organizationId", team.OrganizationID),
			},
			Update: betterauth.Record{
				"name":      bodyString(context, "name"),
				"updatedAt": context.Clock.Now().UTC(),
			},
		})
		if updateErr != nil || row == nil {
			if updateErr == nil {
				updateErr = betterauth.ErrNotFound
			}
			return updateErr
		}
		updated, updateErr = teamFromRecord(row)
		if updateErr != nil {
			return updateErr
		}
		if updateErr = instance.audit(
			context, tx, "organization.team.updated", updated.ID,
			updated.OrganizationID, map[string]any{"name": updated.Name},
		); updateErr != nil {
			return updateErr
		}
		if instance.config.Hooks.AfterMutation != nil {
			return instance.config.Hooks.AfterMutation(hookContext, event)
		}
		return nil
	})
	if err != nil {
		return nil, mapMutationError(err)
	}
	return betterauth.JSONResponse(http.StatusOK, updated)
}

func (instance *runtime) listTeams(
	context *betterauth.HookContext,
) (*betterauth.PluginResponse, error) {
	organizationID, err := instance.selectedOrganizationID(context)
	if err != nil {
		return nil, err
	}
	if _, err = instance.authorize(
		context, context.Database, organizationID, "team", "read",
	); err != nil {
		return nil, err
	}
	limit, offset, err := queryPage(context, instance.config.MaxTeamsPerOrganization)
	if err != nil {
		return nil, err
	}
	rows, err := context.Database.FindMany(context.Context, betterauth.FindManyQuery{
		Model: ModelTeam,
		Where: []betterauth.Where{betterauth.Eq("organizationId", organizationID)},
		Limit: limit, Offset: offset,
		Sort: &betterauth.Sort{Field: "createdAt", Direction: "asc"},
	})
	if err != nil {
		return nil, internalError(err)
	}
	teams, err := rowsToTeams(rows)
	if err != nil {
		return nil, internalError(err)
	}
	return betterauth.JSONResponse(http.StatusOK, teams)
}

func (instance *runtime) setActiveTeam(
	context *betterauth.HookContext,
) (*betterauth.PluginResponse, error) {
	teamID := bodyString(context, "teamId")
	var team Team
	if teamID != "" {
		var err error
		team, err = findTeamByID(context, context.Database, teamID)
		if err != nil {
			return nil, notFound(err)
		}
		if _, err = instance.member(
			context, context.Database, team.OrganizationID, context.User.ID,
		); err != nil {
			return nil, forbidden(err)
		}
		row, findErr := context.Database.FindOne(context.Context, betterauth.FindOneQuery{
			Model: ModelTeamMember,
			Where: []betterauth.Where{
				betterauth.Eq("teamId", team.ID),
				betterauth.Eq("userId", context.User.ID),
			},
			Select: []string{"id"},
		})
		if findErr != nil || row == nil {
			return nil, forbidden(findErr)
		}
	}
	var value any
	if teamID == "" {
		value = nil
	} else {
		value = team
	}
	response, err := betterauth.JSONResponse(http.StatusOK, value)
	if err != nil {
		return nil, err
	}
	organizationID := ""
	if teamID != "" {
		organizationID = team.OrganizationID
	}
	if err = instance.rotateActiveSession(
		context, response, organizationID, teamID, "organization.active_team.changed",
	); err != nil {
		return nil, err
	}
	return response, nil
}

func (instance *runtime) listUserTeams(
	context *betterauth.HookContext,
) (*betterauth.PluginResponse, error) {
	organizationID, err := instance.selectedOrganizationID(context)
	if err != nil {
		return nil, err
	}
	if _, err = instance.member(
		context, context.Database, organizationID, context.User.ID,
	); err != nil {
		return nil, forbidden(err)
	}
	limit, offset, err := queryPage(context, instance.config.MaxTeamsPerOrganization)
	if err != nil {
		return nil, err
	}
	teams, err := context.Database.FindMany(context.Context, betterauth.FindManyQuery{
		Model: ModelTeam,
		Where: []betterauth.Where{betterauth.Eq("organizationId", organizationID)},
		Limit: limit, Offset: offset,
	})
	if err != nil {
		return nil, internalError(err)
	}
	result := make([]Team, 0, len(teams))
	for _, row := range teams {
		team, parseErr := teamFromRecord(row)
		if parseErr != nil {
			return nil, internalError(parseErr)
		}
		membership, findErr := context.Database.FindOne(
			context.Context, betterauth.FindOneQuery{
				Model: ModelTeamMember,
				Where: []betterauth.Where{
					betterauth.Eq("teamId", team.ID),
					betterauth.Eq("userId", context.User.ID),
				},
				Select: []string{"id"},
			},
		)
		if findErr != nil && !errors.Is(findErr, betterauth.ErrNotFound) {
			return nil, internalError(findErr)
		}
		if membership != nil {
			result = append(result, team)
		}
	}
	return betterauth.JSONResponse(http.StatusOK, result)
}

func (instance *runtime) listTeamMembers(
	context *betterauth.HookContext,
) (*betterauth.PluginResponse, error) {
	teamID := strings.TrimSpace(context.Query.Get("teamId"))
	team, err := findTeamByID(context, context.Database, teamID)
	if err != nil {
		return nil, notFound(err)
	}
	if _, err = instance.authorize(
		context, context.Database, team.OrganizationID, "team", "read",
	); err != nil {
		return nil, err
	}
	limit, offset, err := queryPage(context, instance.config.MaxMembersPerOrganization)
	if err != nil {
		return nil, err
	}
	rows, err := context.Database.FindMany(context.Context, betterauth.FindManyQuery{
		Model: ModelTeamMember,
		Where: []betterauth.Where{betterauth.Eq("teamId", team.ID)},
		Limit: limit, Offset: offset,
	})
	if err != nil {
		return nil, internalError(err)
	}
	result := make([]TeamMember, len(rows))
	for index := range rows {
		result[index], err = teamMemberFromRecord(rows[index])
		if err != nil {
			return nil, internalError(err)
		}
	}
	return betterauth.JSONResponse(http.StatusOK, result)
}

func (instance *runtime) addTeamMember(
	context *betterauth.HookContext,
) (*betterauth.PluginResponse, error) {
	teamID := bodyString(context, "teamId")
	userID := bodyString(context, "userId")
	team, err := findTeamByID(context, context.Database, teamID)
	if err != nil {
		return nil, notFound(err)
	}
	if _, err = instance.authorize(
		context, context.Database, team.OrganizationID, "team", "update",
	); err != nil {
		return nil, err
	}
	if _, err = instance.member(
		context, context.Database, team.OrganizationID, userID,
	); err != nil {
		return nil, badRequest("The user is not an organization member.", err)
	}
	id, err := context.GenerateID()
	if err != nil {
		return nil, internalError(err)
	}
	now := context.Clock.Now().UTC()
	var membership TeamMember
	err = context.Database.Transaction(context.Context, func(tx betterauth.DatabaseAdapter) error {
		if _, authorizeErr := instance.authorize(
			context, tx, team.OrganizationID, "team", "update",
		); authorizeErr != nil {
			return authorizeErr
		}
		if _, memberErr := instance.member(
			context, tx, team.OrganizationID, userID,
		); memberErr != nil {
			return badRequest("The user is not an organization member.", memberErr)
		}
		event := MutationEvent{
			Action: "organization.team.member_added", OrganizationID: team.OrganizationID,
			SubjectID: userID, Data: map[string]any{"teamId": team.ID},
		}
		hookContext := contextWithDatabase(context, tx)
		if instance.config.Hooks.BeforeMutation != nil {
			if hookErr := instance.config.Hooks.BeforeMutation(hookContext, event); hookErr != nil {
				return hookErr
			}
		}
		if _, authorizeErr := instance.authorize(
			context, tx, team.OrganizationID, "team", "update",
		); authorizeErr != nil {
			return authorizeErr
		}
		if _, memberErr := instance.member(
			context, tx, team.OrganizationID, userID,
		); memberErr != nil {
			return badRequest("The user is not an organization member.", memberErr)
		}
		row, createErr := tx.Create(context.Context, betterauth.CreateQuery{
			Model: ModelTeamMember,
			Data: betterauth.Record{
				"id": id, "teamId": team.ID, "userId": userID, "createdAt": now,
			},
			ForceAllowID: true,
		})
		if createErr != nil {
			return createErr
		}
		membership, createErr = teamMemberFromRecord(row)
		if createErr != nil {
			return createErr
		}
		if createErr = instance.audit(
			context, tx, "organization.team.member_added", userID,
			team.OrganizationID, map[string]any{"teamId": team.ID},
		); createErr != nil {
			return createErr
		}
		if instance.config.Hooks.AfterMutation != nil {
			return instance.config.Hooks.AfterMutation(hookContext, event)
		}
		return nil
	})
	if err != nil {
		return nil, mapMutationError(err)
	}
	return betterauth.JSONResponse(http.StatusOK, membership)
}

func (instance *runtime) removeTeamMember(
	context *betterauth.HookContext,
) (*betterauth.PluginResponse, error) {
	teamID := bodyString(context, "teamId")
	userID := bodyString(context, "userId")
	team, err := findTeamByID(context, context.Database, teamID)
	if err != nil {
		return nil, notFound(err)
	}
	if _, err = instance.authorize(
		context, context.Database, team.OrganizationID, "team", "update",
	); err != nil {
		return nil, err
	}
	err = context.Database.Transaction(context.Context, func(tx betterauth.DatabaseAdapter) error {
		if _, authorizeErr := instance.authorize(
			context, tx, team.OrganizationID, "team", "update",
		); authorizeErr != nil {
			return authorizeErr
		}
		event := MutationEvent{
			Action: "organization.team.member_removed", OrganizationID: team.OrganizationID,
			SubjectID: userID, Data: map[string]any{"teamId": team.ID},
		}
		hookContext := contextWithDatabase(context, tx)
		if instance.config.Hooks.BeforeMutation != nil {
			if hookErr := instance.config.Hooks.BeforeMutation(hookContext, event); hookErr != nil {
				return hookErr
			}
		}
		if _, authorizeErr := instance.authorize(
			context, tx, team.OrganizationID, "team", "update",
		); authorizeErr != nil {
			return authorizeErr
		}
		if deleteErr := tx.Delete(context.Context, betterauth.DeleteQuery{
			Model: ModelTeamMember,
			Where: []betterauth.Where{
				betterauth.Eq("teamId", team.ID), betterauth.Eq("userId", userID),
			},
		}); deleteErr != nil {
			return deleteErr
		}
		if _, updateErr := tx.UpdateMany(context.Context, betterauth.UpdateQuery{
			Model: betterauth.ModelSession,
			Where: []betterauth.Where{
				betterauth.Eq("userId", userID),
				betterauth.Eq("activeTeamId", team.ID),
			},
			Update: betterauth.Record{
				"activeTeamId": nil, "updatedAt": context.Clock.Now().UTC(),
			},
		}); updateErr != nil {
			return updateErr
		}
		if auditErr := instance.audit(
			context, tx, "organization.team.member_removed", userID,
			team.OrganizationID, map[string]any{"teamId": team.ID},
		); auditErr != nil {
			return auditErr
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

func findTeam(
	context *betterauth.HookContext,
	database betterauth.DatabaseAdapter,
	organizationID, teamID string,
) (Team, error) {
	row, err := database.FindOne(context.Context, betterauth.FindOneQuery{
		Model: ModelTeam,
		Where: []betterauth.Where{
			betterauth.Eq("id", teamID),
			betterauth.Eq("organizationId", organizationID),
		},
	})
	if err != nil || row == nil {
		if err == nil {
			err = betterauth.ErrNotFound
		}
		return Team{}, err
	}
	return teamFromRecord(row)
}

func findTeamByID(
	context *betterauth.HookContext,
	database betterauth.DatabaseAdapter,
	teamID string,
) (Team, error) {
	row, err := database.FindOne(context.Context, betterauth.FindOneQuery{
		Model: ModelTeam,
		Where: []betterauth.Where{betterauth.Eq("id", teamID)},
	})
	if err != nil || row == nil {
		if err == nil {
			err = betterauth.ErrNotFound
		}
		return Team{}, err
	}
	return teamFromRecord(row)
}
