package organization

import (
	"errors"
	"net/http"
	"strings"

	betterauth "github.com/eadwinCode/better-auth-go"
)

func (instance *runtime) hasPermission(
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
	requested, err := permissionFromInput(body(context)["permission"])
	if err != nil {
		return nil, badRequest("The permission request is invalid.", err)
	}
	for resource, actions := range requested {
		for _, action := range actions {
			allowed, permissionErr := instance.permission(
				context, context.Database, organizationID, member.Role, resource, action,
			)
			if permissionErr != nil {
				return nil, internalError(permissionErr)
			}
			if !allowed {
				return betterauth.JSONResponse(http.StatusOK, map[string]bool{"success": false})
			}
		}
	}
	return betterauth.JSONResponse(http.StatusOK, map[string]bool{"success": true})
}

func (instance *runtime) createRole(
	context *betterauth.HookContext,
) (*betterauth.PluginResponse, error) {
	organizationID, err := instance.selectedOrganizationID(context)
	if err != nil {
		return nil, err
	}
	actor, err := instance.authorize(
		context, context.Database, organizationID, "ac", "create",
	)
	if err != nil {
		return nil, err
	}
	name := strings.ToLower(bodyString(context, "role"))
	if !validRoleName(name) {
		return nil, badRequest("The role name is invalid.", nil)
	}
	if _, reserved := instance.roles[name]; reserved {
		return nil, conflict("The role name is reserved.", nil)
	}
	permission, err := permissionFromInput(body(context)["permission"])
	if err != nil {
		return nil, badRequest("The role permission is invalid.", err)
	}
	permission, err = normalizePermission(permission, instance.config.Statements)
	if err != nil {
		return nil, badRequest("The role permission is invalid.", err)
	}
	if err = instance.requireGrantablePermission(
		context, context.Database, organizationID, actor.Role, permission,
	); err != nil {
		return nil, err
	}
	id, err := context.GenerateID()
	if err != nil {
		return nil, internalError(err)
	}
	now := context.Clock.Now().UTC()
	role := OrganizationRole{
		ID: id, OrganizationID: organizationID, Role: name, Permission: permission,
		CreatedAt: now, UpdatedAt: now,
	}
	var created OrganizationRole
	err = context.Database.Transaction(context.Context, func(tx betterauth.DatabaseAdapter) error {
		currentActor, authorizeErr := instance.authorize(
			context, tx, organizationID, "ac", "create",
		)
		if authorizeErr != nil {
			return authorizeErr
		}
		if grantErr := instance.requireGrantablePermission(
			context, tx, organizationID, currentActor.Role, permission,
		); grantErr != nil {
			return grantErr
		}
		event := MutationEvent{
			Action: "organization.role.created", OrganizationID: organizationID,
			SubjectID: id, Data: map[string]any{"role": name},
		}
		hookContext := contextWithDatabase(context, tx)
		count, countErr := tx.Count(context.Context, betterauth.CountQuery{
			Model: ModelOrganizationRole,
			Where: []betterauth.Where{betterauth.Eq("organizationId", organizationID)},
		})
		if countErr != nil {
			return countErr
		}
		if count >= int64(instance.config.MaxRolesPerOrganization) {
			return conflict("The organization role limit has been reached.", nil)
		}
		if instance.config.Hooks.BeforeMutation != nil {
			if hookErr := instance.config.Hooks.BeforeMutation(hookContext, event); hookErr != nil {
				return hookErr
			}
		}
		currentActor, authorizeErr = instance.authorize(
			context, tx, organizationID, "ac", "create",
		)
		if authorizeErr != nil {
			return authorizeErr
		}
		if grantErr := instance.requireGrantablePermission(
			context, tx, organizationID, currentActor.Role, permission,
		); grantErr != nil {
			return grantErr
		}
		row, createErr := tx.Create(context.Context, betterauth.CreateQuery{
			Model: ModelOrganizationRole, Data: roleRecord(role), ForceAllowID: true,
		})
		if createErr != nil {
			return createErr
		}
		created, createErr = roleFromRecord(row)
		if createErr != nil {
			return createErr
		}
		if auditErr := instance.audit(
			context, tx, "organization.role.created", created.ID,
			organizationID, map[string]any{"role": created.Role},
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
	return betterauth.JSONResponse(http.StatusOK, created)
}

func (instance *runtime) deleteRole(
	context *betterauth.HookContext,
) (*betterauth.PluginResponse, error) {
	organizationID, err := instance.selectedOrganizationID(context)
	if err != nil {
		return nil, err
	}
	if _, err = instance.authorize(
		context, context.Database, organizationID, "ac", "delete",
	); err != nil {
		return nil, err
	}
	name := strings.ToLower(bodyString(context, "role"))
	if _, reserved := instance.roles[name]; reserved {
		return nil, conflict("Built-in roles cannot be deleted.", nil)
	}
	var deleted OrganizationRole
	err = context.Database.Transaction(context.Context, func(tx betterauth.DatabaseAdapter) error {
		if _, authorizeErr := instance.authorize(
			context, tx, organizationID, "ac", "delete",
		); authorizeErr != nil {
			return authorizeErr
		}
		event := MutationEvent{
			Action: "organization.role.deleted", OrganizationID: organizationID,
			Data: map[string]any{"role": name},
		}
		hookContext := contextWithDatabase(context, tx)
		row, findErr := tx.FindOne(context.Context, betterauth.FindOneQuery{
			Model: ModelOrganizationRole,
			Where: []betterauth.Where{
				betterauth.Eq("organizationId", organizationID),
				betterauth.Eq("role", name),
			},
		})
		if findErr != nil || row == nil {
			if findErr == nil {
				findErr = betterauth.ErrNotFound
			}
			return findErr
		}
		deleted, findErr = roleFromRecord(row)
		if findErr != nil {
			return findErr
		}
		event.SubjectID = deleted.ID
		members, findErr := findManyBounded(
			context, tx, ModelMember,
			[]betterauth.Where{betterauth.Eq("organizationId", organizationID)},
			instance.config.MaxMembersPerOrganization,
		)
		if findErr != nil {
			return findErr
		}
		for _, memberRow := range members {
			roleNames, parseErr := requiredString(memberRow, "role")
			if parseErr != nil {
				return parseErr
			}
			if roleIncludes(roleNames, name) {
				return conflict("The role is assigned to an organization member.", nil)
			}
		}
		invitations, findErr := findManyBounded(
			context, tx, ModelInvitation,
			[]betterauth.Where{
				betterauth.Eq("organizationId", organizationID),
				betterauth.Eq("status", "pending"),
			},
			instance.config.MaxInvitationsPerOrganization,
		)
		if findErr != nil {
			return findErr
		}
		for _, invitationRow := range invitations {
			roleNames, parseErr := requiredString(invitationRow, "role")
			if parseErr != nil {
				return parseErr
			}
			if roleIncludes(roleNames, name) {
				return conflict("The role is assigned to a pending invitation.", nil)
			}
		}
		if instance.config.Hooks.BeforeMutation != nil {
			if hookErr := instance.config.Hooks.BeforeMutation(hookContext, event); hookErr != nil {
				return hookErr
			}
		}
		if _, authorizeErr := instance.authorize(
			context, tx, organizationID, "ac", "delete",
		); authorizeErr != nil {
			return authorizeErr
		}
		if findErr = tx.Delete(context.Context, betterauth.DeleteQuery{
			Model: ModelOrganizationRole,
			Where: []betterauth.Where{
				betterauth.Eq("id", deleted.ID),
				betterauth.Eq("organizationId", organizationID),
			},
		}); findErr != nil {
			return findErr
		}
		if auditErr := instance.audit(
			context, tx, "organization.role.deleted", deleted.ID,
			organizationID, map[string]any{"role": name},
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
	return betterauth.JSONResponse(http.StatusOK, deleted)
}

func (instance *runtime) listRoles(
	context *betterauth.HookContext,
) (*betterauth.PluginResponse, error) {
	organizationID, err := instance.selectedOrganizationID(context)
	if err != nil {
		return nil, err
	}
	if _, err = instance.authorize(
		context, context.Database, organizationID, "ac", "read",
	); err != nil {
		return nil, err
	}
	limit, offset, err := queryPage(context, instance.config.MaxRolesPerOrganization)
	if err != nil {
		return nil, err
	}
	rows, err := context.Database.FindMany(context.Context, betterauth.FindManyQuery{
		Model: ModelOrganizationRole,
		Where: []betterauth.Where{betterauth.Eq("organizationId", organizationID)},
		Limit: limit, Offset: offset,
	})
	if err != nil {
		return nil, internalError(err)
	}
	result := make([]OrganizationRole, len(rows))
	for index := range rows {
		result[index], err = roleFromRecord(rows[index])
		if err != nil {
			return nil, internalError(err)
		}
	}
	return betterauth.JSONResponse(http.StatusOK, result)
}

func (instance *runtime) getRole(
	context *betterauth.HookContext,
) (*betterauth.PluginResponse, error) {
	organizationID, err := instance.selectedOrganizationID(context)
	if err != nil {
		return nil, err
	}
	if _, err = instance.authorize(
		context, context.Database, organizationID, "ac", "read",
	); err != nil {
		return nil, err
	}
	name := strings.ToLower(strings.TrimSpace(context.Query.Get("role")))
	if static, exists := instance.roles[name]; exists {
		return betterauth.JSONResponse(http.StatusOK, map[string]any{
			"organizationId": organizationID, "role": name,
			"permission": clonePermission(static.Permission), "builtIn": true,
		})
	}
	row, err := context.Database.FindOne(context.Context, betterauth.FindOneQuery{
		Model: ModelOrganizationRole,
		Where: []betterauth.Where{
			betterauth.Eq("organizationId", organizationID),
			betterauth.Eq("role", name),
		},
	})
	if err != nil || row == nil {
		return nil, notFound(err)
	}
	role, err := roleFromRecord(row)
	if err != nil {
		return nil, internalError(err)
	}
	return betterauth.JSONResponse(http.StatusOK, role)
}

func (instance *runtime) updateRole(
	context *betterauth.HookContext,
) (*betterauth.PluginResponse, error) {
	organizationID, err := instance.selectedOrganizationID(context)
	if err != nil {
		return nil, err
	}
	actor, err := instance.authorize(
		context, context.Database, organizationID, "ac", "update",
	)
	if err != nil {
		return nil, err
	}
	name := strings.ToLower(bodyString(context, "role"))
	if _, reserved := instance.roles[name]; reserved {
		return nil, conflict("Built-in roles cannot be updated.", nil)
	}
	permission, err := permissionFromInput(body(context)["permission"])
	if err != nil {
		return nil, badRequest("The role permission is invalid.", err)
	}
	permission, err = normalizePermission(permission, instance.config.Statements)
	if err != nil {
		return nil, badRequest("The role permission is invalid.", err)
	}
	if err = instance.requireGrantablePermission(
		context, context.Database, organizationID, actor.Role, permission,
	); err != nil {
		return nil, err
	}
	var role OrganizationRole
	err = context.Database.Transaction(context.Context, func(tx betterauth.DatabaseAdapter) error {
		currentActor, authorizeErr := instance.authorize(
			context, tx, organizationID, "ac", "update",
		)
		if authorizeErr != nil {
			return authorizeErr
		}
		if grantErr := instance.requireGrantablePermission(
			context, tx, organizationID, currentActor.Role, permission,
		); grantErr != nil {
			return grantErr
		}
		event := MutationEvent{
			Action: "organization.role.updated", OrganizationID: organizationID,
			Data: map[string]any{"role": name},
		}
		hookContext := contextWithDatabase(context, tx)
		if instance.config.Hooks.BeforeMutation != nil {
			if hookErr := instance.config.Hooks.BeforeMutation(hookContext, event); hookErr != nil {
				return hookErr
			}
		}
		currentActor, authorizeErr = instance.authorize(
			context, tx, organizationID, "ac", "update",
		)
		if authorizeErr != nil {
			return authorizeErr
		}
		if grantErr := instance.requireGrantablePermission(
			context, tx, organizationID, currentActor.Role, permission,
		); grantErr != nil {
			return grantErr
		}
		row, updateErr := tx.Update(context.Context, betterauth.UpdateQuery{
			Model: ModelOrganizationRole,
			Where: []betterauth.Where{
				betterauth.Eq("organizationId", organizationID),
				betterauth.Eq("role", name),
			},
			Update: betterauth.Record{
				"permission": permission, "updatedAt": context.Clock.Now().UTC(),
			},
		})
		if updateErr != nil || row == nil {
			if updateErr == nil {
				updateErr = betterauth.ErrNotFound
			}
			return updateErr
		}
		role, updateErr = roleFromRecord(row)
		if updateErr != nil {
			return updateErr
		}
		event.SubjectID = role.ID
		if updateErr = instance.audit(
			context, tx, "organization.role.updated", role.ID,
			organizationID, map[string]any{"role": role.Role},
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
	return betterauth.JSONResponse(http.StatusOK, role)
}

func permissionFromInput(value any) (Permission, error) {
	object, ok := value.(map[string]any)
	if !ok || len(object) == 0 {
		return nil, errors.New("organization: permission must be a non-empty object")
	}
	result := make(Permission, len(object))
	for resource, raw := range object {
		values, ok := raw.([]any)
		if !ok {
			if stringsValue, stringsOK := raw.([]string); stringsOK {
				result[resource] = stringsValue
				continue
			}
			return nil, errors.New("organization: permission actions must be an array")
		}
		actions := make([]string, len(values))
		for index, item := range values {
			action, ok := item.(string)
			if !ok {
				return nil, errors.New("organization: permission action must be a string")
			}
			actions[index] = action
		}
		result[resource] = actions
	}
	return result, nil
}

func roleRecord(value OrganizationRole) betterauth.Record {
	return betterauth.Record{
		"id": value.ID, "organizationId": value.OrganizationID,
		"role": value.Role, "permission": value.Permission,
		"createdAt": value.CreatedAt, "updatedAt": value.UpdatedAt,
	}
}

func (instance *runtime) requireGrantablePermission(
	context *betterauth.HookContext,
	database betterauth.DatabaseAdapter,
	organizationID, actorRoles string,
	permission Permission,
) error {
	for resource, actions := range permission {
		for _, action := range actions {
			allowed, err := instance.permission(
				context, database, organizationID, actorRoles, resource, action,
			)
			if err != nil {
				return internalError(err)
			}
			if !allowed {
				return forbidden(nil)
			}
		}
	}
	return nil
}
