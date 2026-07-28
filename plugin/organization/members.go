package organization

import (
	"errors"
	"net/http"
	"strings"

	betterauth "github.com/eadwinCode/better-auth-go"
)

func (instance *runtime) removeMember(
	context *betterauth.HookContext,
) (*betterauth.PluginResponse, error) {
	organizationID, err := instance.selectedOrganizationID(context)
	if err != nil {
		return nil, err
	}
	actor, err := instance.authorize(
		context, context.Database, organizationID, "member", "delete",
	)
	if err != nil {
		return nil, err
	}
	memberID := bodyString(context, "memberId")
	var removed Member
	err = context.Database.Transaction(context.Context, func(tx betterauth.DatabaseAdapter) error {
		currentActor, authorizeErr := instance.authorize(
			context, tx, organizationID, "member", "delete",
		)
		if authorizeErr != nil {
			return authorizeErr
		}
		actor = currentActor
		var findErr error
		removed, findErr = findMemberByID(context, tx, organizationID, memberID)
		if findErr != nil {
			return findErr
		}
		if roleIncludes(removed.Role, instance.config.CreatorRole) {
			if !roleIncludes(actor.Role, instance.config.CreatorRole) {
				return forbidden(nil)
			}
			count, countErr := ownerCount(
				context, tx, organizationID, instance.config.CreatorRole,
			)
			if countErr != nil {
				return countErr
			}
			if count <= 1 {
				return conflict("The final organization owner cannot be removed.", nil)
			}
		}
		event := MutationEvent{
			Action: "organization.member.removed", OrganizationID: organizationID,
			SubjectID: removed.UserID, Data: map[string]any{"memberId": removed.ID},
		}
		hookContext := contextWithDatabase(context, tx)
		if instance.config.Hooks.BeforeMutation != nil {
			if hookErr := instance.config.Hooks.BeforeMutation(hookContext, event); hookErr != nil {
				return hookErr
			}
		}
		if _, authorizeErr = instance.authorize(
			context, tx, organizationID, "member", "delete",
		); authorizeErr != nil {
			return authorizeErr
		}
		if deleteErr := tx.Delete(context.Context, betterauth.DeleteQuery{
			Model: ModelMember,
			Where: []betterauth.Where{
				betterauth.Eq("id", removed.ID),
				betterauth.Eq("organizationId", organizationID),
			},
		}); deleteErr != nil {
			return deleteErr
		}
		if cleanupErr := removeUserFromOrganizationTeams(
			context, tx, organizationID, removed.UserID,
		); cleanupErr != nil {
			return cleanupErr
		}
		if _, updateErr := tx.UpdateMany(context.Context, betterauth.UpdateQuery{
			Model: betterauth.ModelSession,
			Where: []betterauth.Where{
				betterauth.Eq("userId", removed.UserID),
				betterauth.Eq("activeOrganizationId", organizationID),
			},
			Update: betterauth.Record{
				"activeOrganizationId": nil, "activeTeamId": nil,
				"updatedAt": context.Clock.Now().UTC(),
			},
		}); updateErr != nil {
			return updateErr
		}
		if auditErr := instance.audit(
			context, tx, "organization.member.removed", removed.UserID,
			organizationID, map[string]any{"memberId": removed.ID},
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
	return betterauth.JSONResponse(http.StatusOK, removed)
}

func (instance *runtime) updateMemberRole(
	context *betterauth.HookContext,
) (*betterauth.PluginResponse, error) {
	organizationID, err := instance.selectedOrganizationID(context)
	if err != nil {
		return nil, err
	}
	actor, err := instance.authorize(
		context, context.Database, organizationID, "member", "update",
	)
	if err != nil {
		return nil, err
	}
	role, err := canonicalRoles([]string{bodyString(context, "role")})
	if err != nil {
		return nil, badRequest("The member role is invalid.", err)
	}
	if err = instance.requireDefinedRoles(context, context.Database, organizationID, role); err != nil {
		return nil, err
	}
	if !roleIncludes(actor.Role, instance.config.CreatorRole) &&
		roleIncludes(role, instance.config.CreatorRole) {
		return nil, forbidden(nil)
	}
	memberID := bodyString(context, "memberId")
	var updated Member
	err = context.Database.Transaction(context.Context, func(tx betterauth.DatabaseAdapter) error {
		currentActor, authorizeErr := instance.authorize(
			context, tx, organizationID, "member", "update",
		)
		if authorizeErr != nil {
			return authorizeErr
		}
		actor = currentActor
		current, findErr := findMemberByID(context, tx, organizationID, memberID)
		if findErr != nil {
			return findErr
		}
		if roleIncludes(current.Role, instance.config.CreatorRole) &&
			!roleIncludes(role, instance.config.CreatorRole) {
			if !roleIncludes(actor.Role, instance.config.CreatorRole) {
				return forbidden(nil)
			}
			count, countErr := ownerCount(
				context, tx, organizationID, instance.config.CreatorRole,
			)
			if countErr != nil {
				return countErr
			}
			if count <= 1 {
				return conflict("The final organization owner cannot be demoted.", nil)
			}
		}
		event := MutationEvent{
			Action: "organization.member.role_updated", OrganizationID: organizationID,
			SubjectID: current.UserID,
			Data:      map[string]any{"memberId": current.ID, "role": role},
		}
		hookContext := contextWithDatabase(context, tx)
		if instance.config.Hooks.BeforeMutation != nil {
			if hookErr := instance.config.Hooks.BeforeMutation(hookContext, event); hookErr != nil {
				return hookErr
			}
		}
		if _, authorizeErr = instance.authorize(
			context, tx, organizationID, "member", "update",
		); authorizeErr != nil {
			return authorizeErr
		}
		row, updateErr := tx.Update(context.Context, betterauth.UpdateQuery{
			Model: ModelMember,
			Where: []betterauth.Where{
				betterauth.Eq("id", memberID),
				betterauth.Eq("organizationId", organizationID),
				betterauth.Eq("role", current.Role),
			},
			Update: betterauth.Record{
				"role": role, "updatedAt": context.Clock.Now().UTC(),
			},
		})
		if updateErr != nil || row == nil {
			if updateErr == nil {
				updateErr = betterauth.ErrNotFound
			}
			return updateErr
		}
		updated, updateErr = memberFromRecord(row)
		if updateErr != nil {
			return updateErr
		}
		if auditErr := instance.audit(
			context, tx, "organization.member.role_updated", updated.UserID,
			organizationID, map[string]any{
				"memberId": updated.ID, "previousRole": current.Role, "role": role,
			},
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
	return betterauth.JSONResponse(http.StatusOK, updated)
}

func (instance *runtime) getActiveMember(
	context *betterauth.HookContext,
) (*betterauth.PluginResponse, error) {
	organizationID, err := instance.selectedOrganizationID(context)
	if err != nil {
		return nil, err
	}
	member, err := instance.member(
		context, context.Database, organizationID, context.User.ID,
	)
	if err != nil {
		return nil, forbidden(err)
	}
	return betterauth.JSONResponse(http.StatusOK, member)
}

func (instance *runtime) leaveOrganization(
	context *betterauth.HookContext,
) (*betterauth.PluginResponse, error) {
	organizationID := bodyString(context, "organizationId")
	member, err := instance.member(
		context, context.Database, organizationID, context.User.ID,
	)
	if err != nil {
		return nil, forbidden(err)
	}
	err = context.Database.Transaction(context.Context, func(tx betterauth.DatabaseAdapter) error {
		event := MutationEvent{
			Action: "organization.member.left", OrganizationID: organizationID,
			SubjectID: context.User.ID, Data: map[string]any{"memberId": member.ID},
		}
		hookContext := contextWithDatabase(context, tx)
		current, findErr := findMemberByID(
			context, tx, organizationID, member.ID,
		)
		if findErr != nil {
			return findErr
		}
		if roleIncludes(current.Role, instance.config.CreatorRole) {
			count, countErr := ownerCount(
				context, tx, organizationID, instance.config.CreatorRole,
			)
			if countErr != nil {
				return countErr
			}
			if count <= 1 {
				return conflict("The final organization owner cannot leave.", nil)
			}
		}
		if instance.config.Hooks.BeforeMutation != nil {
			if hookErr := instance.config.Hooks.BeforeMutation(hookContext, event); hookErr != nil {
				return hookErr
			}
		}
		if deleteErr := tx.Delete(context.Context, betterauth.DeleteQuery{
			Model: ModelMember,
			Where: []betterauth.Where{
				betterauth.Eq("id", member.ID),
				betterauth.Eq("organizationId", organizationID),
				betterauth.Eq("userId", context.User.ID),
			},
		}); deleteErr != nil {
			return deleteErr
		}
		if cleanupErr := removeUserFromOrganizationTeams(
			context, tx, organizationID, context.User.ID,
		); cleanupErr != nil {
			return cleanupErr
		}
		if _, updateErr := tx.UpdateMany(context.Context, betterauth.UpdateQuery{
			Model: betterauth.ModelSession,
			Where: []betterauth.Where{
				betterauth.Eq("userId", context.User.ID),
				betterauth.Eq("activeOrganizationId", organizationID),
			},
			Update: betterauth.Record{
				"activeOrganizationId": nil, "activeTeamId": nil,
				"updatedAt": context.Clock.Now().UTC(),
			},
		}); updateErr != nil {
			return updateErr
		}
		if auditErr := instance.audit(
			context, tx, "organization.member.left", context.User.ID,
			organizationID, map[string]any{"memberId": member.ID},
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
	return betterauth.JSONResponse(http.StatusOK, member)
}

func (instance *runtime) listMembers(
	context *betterauth.HookContext,
) (*betterauth.PluginResponse, error) {
	organizationID, err := instance.selectedOrganizationID(context)
	if err != nil {
		return nil, err
	}
	if _, err = instance.authorize(
		context, context.Database, organizationID, "member", "read",
	); err != nil {
		return nil, err
	}
	limit, offset, err := queryPage(context, instance.config.MaxMembersPerOrganization)
	if err != nil {
		return nil, err
	}
	rows, err := context.Database.FindMany(context.Context, betterauth.FindManyQuery{
		Model: ModelMember,
		Where: []betterauth.Where{betterauth.Eq("organizationId", organizationID)},
		Limit: limit, Offset: offset,
		Sort: &betterauth.Sort{Field: "createdAt", Direction: "asc"},
	})
	if err != nil {
		return nil, internalError(err)
	}
	members, err := rowsToMembers(rows)
	if err != nil {
		return nil, internalError(err)
	}
	total, err := context.Database.Count(context.Context, betterauth.CountQuery{
		Model: ModelMember,
		Where: []betterauth.Where{betterauth.Eq("organizationId", organizationID)},
	})
	if err != nil {
		return nil, internalError(err)
	}
	return betterauth.JSONResponse(http.StatusOK, map[string]any{
		"members": members, "total": total,
	})
}

func (instance *runtime) getActiveMemberRole(
	context *betterauth.HookContext,
) (*betterauth.PluginResponse, error) {
	organizationID, err := instance.selectedOrganizationID(context)
	if err != nil {
		return nil, err
	}
	member, err := instance.member(
		context, context.Database, organizationID, context.User.ID,
	)
	if err != nil {
		return nil, forbidden(err)
	}
	return betterauth.JSONResponse(http.StatusOK, map[string]string{"role": member.Role})
}

func findMemberByID(
	context *betterauth.HookContext,
	database betterauth.DatabaseAdapter,
	organizationID, memberID string,
) (Member, error) {
	row, err := database.FindOne(context.Context, betterauth.FindOneQuery{
		Model: ModelMember,
		Where: []betterauth.Where{
			betterauth.Eq("id", memberID),
			betterauth.Eq("organizationId", organizationID),
		},
	})
	if err != nil || row == nil {
		if err == nil {
			err = betterauth.ErrNotFound
		}
		return Member{}, err
	}
	return memberFromRecord(row)
}

func ownerCount(
	context *betterauth.HookContext,
	database betterauth.DatabaseAdapter,
	organizationID, ownerRole string,
) (int, error) {
	rows, err := findManyBounded(
		context, database, ModelMember,
		[]betterauth.Where{betterauth.Eq("organizationId", organizationID)},
		100_000,
	)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, row := range rows {
		role, parseErr := requiredString(row, "role")
		if parseErr != nil {
			return 0, parseErr
		}
		if roleIncludes(role, ownerRole) {
			count++
		}
	}
	return count, nil
}

func roleIncludes(roles, expected string) bool {
	for _, role := range strings.Split(roles, ",") {
		if role == expected {
			return true
		}
	}
	return false
}

func (instance *runtime) requireDefinedRoles(
	context *betterauth.HookContext,
	database betterauth.DatabaseAdapter,
	organizationID, roles string,
) error {
	for _, name := range strings.Split(roles, ",") {
		if _, exists := instance.roles[name]; exists {
			continue
		}
		row, err := database.FindOne(context.Context, betterauth.FindOneQuery{
			Model: ModelOrganizationRole,
			Where: []betterauth.Where{
				betterauth.Eq("organizationId", organizationID),
				betterauth.Eq("role", name),
			},
			Select: []string{"id"},
		})
		if err != nil && !errors.Is(err, betterauth.ErrNotFound) {
			return internalError(err)
		}
		if row == nil {
			return badRequest("The member role is not defined.", nil)
		}
	}
	return nil
}

func removeUserFromOrganizationTeams(
	context *betterauth.HookContext,
	database betterauth.DatabaseAdapter,
	organizationID, userID string,
) error {
	teams, err := findManyBounded(
		context, database, ModelTeam,
		[]betterauth.Where{betterauth.Eq("organizationId", organizationID)},
		100_000,
	)
	if err != nil {
		return err
	}
	for _, row := range teams {
		teamID, parseErr := requiredString(row, "id")
		if parseErr != nil {
			return parseErr
		}
		if _, err = database.DeleteMany(context.Context, betterauth.DeleteQuery{
			Model: ModelTeamMember,
			Where: []betterauth.Where{
				betterauth.Eq("teamId", teamID), betterauth.Eq("userId", userID),
			},
		}); err != nil {
			return err
		}
	}
	return nil
}
