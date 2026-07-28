package organization

import (
	"errors"
	"net/http"
	"strings"

	betterauth "github.com/eadwinCode/better-auth-go"
)

func (instance *runtime) inviteMember(
	context *betterauth.HookContext,
) (*betterauth.PluginResponse, error) {
	organizationID, err := instance.selectedOrganizationID(context)
	if err != nil {
		return nil, err
	}
	actor, err := instance.authorize(
		context, context.Database, organizationID, "invitation", "create",
	)
	if err != nil {
		return nil, err
	}
	role, err := canonicalRoles([]string{bodyString(context, "role")})
	if err != nil {
		return nil, badRequest("The invitation role is invalid.", err)
	}
	if err = instance.requireDefinedRoles(
		context, context.Database, organizationID, role,
	); err != nil {
		return nil, err
	}
	if roleIncludes(role, instance.config.CreatorRole) &&
		!roleIncludes(actor.Role, instance.config.CreatorRole) {
		return nil, forbidden(nil)
	}
	email := strings.ToLower(bodyString(context, "email"))
	teamID := bodyString(context, "teamId")
	if teamID != "" {
		if _, err = findTeam(context, context.Database, organizationID, teamID); err != nil {
			return nil, notFound(err)
		}
	}
	id, err := context.GenerateID()
	if err != nil {
		return nil, internalError(err)
	}
	now := context.Clock.Now().UTC()
	invitation := Invitation{
		ID: id, OrganizationID: organizationID, Email: email, Role: role,
		TeamID: teamID, Status: "pending", InviterID: context.User.ID,
		ExpiresAt: now.Add(instance.config.InvitationTTL),
		CreatedAt: now, UpdatedAt: now,
	}
	resend, _ := body(context)["resend"].(bool)
	var organization Organization
	err = context.Database.Transaction(context.Context, func(tx betterauth.DatabaseAdapter) error {
		currentActor, authorizeErr := instance.authorize(
			context, tx, organizationID, "invitation", "create",
		)
		if authorizeErr != nil {
			return authorizeErr
		}
		actor = currentActor
		if roleIncludes(role, instance.config.CreatorRole) &&
			!roleIncludes(actor.Role, instance.config.CreatorRole) {
			return forbidden(nil)
		}
		memberCount, countErr := tx.Count(context.Context, betterauth.CountQuery{
			Model: ModelMember,
			Where: []betterauth.Where{betterauth.Eq("organizationId", organizationID)},
		})
		if countErr != nil {
			return countErr
		}
		if memberCount >= int64(instance.config.MaxMembersPerOrganization) {
			return conflict("The organization member limit has been reached.", nil)
		}
		invitationCount, countErr := tx.Count(context.Context, betterauth.CountQuery{
			Model: ModelInvitation,
			Where: []betterauth.Where{
				betterauth.Eq("organizationId", organizationID),
				betterauth.Eq("status", "pending"),
			},
		})
		if countErr != nil {
			return countErr
		}
		if invitationCount >= int64(instance.config.MaxInvitationsPerOrganization) {
			return conflict("The organization invitation limit has been reached.", nil)
		}
		if existing, memberErr := instance.memberByEmail(
			context, tx, organizationID, email,
		); memberErr != nil {
			return memberErr
		} else if existing {
			return conflict("A member already uses this email address.", nil)
		}
		organizationRow, findErr := tx.FindOne(context.Context, betterauth.FindOneQuery{
			Model: ModelOrganization,
			Where: []betterauth.Where{betterauth.Eq("id", organizationID)},
		})
		if findErr != nil || organizationRow == nil {
			if findErr == nil {
				findErr = betterauth.ErrNotFound
			}
			return findErr
		}
		organization, findErr = organizationFromRecord(organizationRow)
		if findErr != nil {
			return findErr
		}
		hookContext := contextWithDatabase(context, tx)
		event := MutationEvent{
			Action: "organization.invitation.created", OrganizationID: organizationID,
			SubjectID: invitation.ID,
			Data:      map[string]any{"email": email, "role": role, "teamId": teamID},
		}
		if instance.config.Hooks.BeforeMutation != nil {
			if hookErr := instance.config.Hooks.BeforeMutation(hookContext, event); hookErr != nil {
				return hookErr
			}
		}
		if instance.config.Hooks.BeforeInvitationCreate != nil {
			if hookErr := instance.config.Hooks.BeforeInvitationCreate(
				hookContext, &invitation,
			); hookErr != nil {
				return hookErr
			}
			invitation.ID = id
			invitation.OrganizationID = organizationID
			invitation.Email = email
			invitation.Role = role
			invitation.TeamID = teamID
			invitation.Status = "pending"
			invitation.InviterID = context.User.ID
			invitation.ExpiresAt = now.Add(instance.config.InvitationTTL)
			invitation.CreatedAt = now
			invitation.UpdatedAt = now
		}
		currentActor, authorizeErr = instance.authorize(
			context, tx, organizationID, "invitation", "create",
		)
		if authorizeErr != nil {
			return authorizeErr
		}
		if roleIncludes(role, instance.config.CreatorRole) &&
			!roleIncludes(currentActor.Role, instance.config.CreatorRole) {
			return forbidden(nil)
		}
		existing, findErr := tx.FindOne(context.Context, betterauth.FindOneQuery{
			Model: ModelInvitation,
			Where: []betterauth.Where{
				betterauth.Eq("organizationId", organizationID),
				betterauth.Eq("email", email),
			},
		})
		if findErr != nil && !errors.Is(findErr, betterauth.ErrNotFound) {
			return findErr
		}
		var row betterauth.Record
		if existing != nil {
			current, parseErr := invitationFromRecord(existing)
			if parseErr != nil {
				return parseErr
			}
			if current.Status == "pending" && current.ExpiresAt.After(now) && !resend {
				return conflict("An active invitation already exists.", nil)
			}
			invitation.ID = current.ID
			invitation.CreatedAt = current.CreatedAt
			row, findErr = tx.Update(context.Context, betterauth.UpdateQuery{
				Model: ModelInvitation,
				Where: []betterauth.Where{
					betterauth.Eq("id", current.ID),
					betterauth.Eq("organizationId", organizationID),
				},
				Update: invitationUpdateRecord(invitation),
			})
		} else {
			row, findErr = tx.Create(context.Context, betterauth.CreateQuery{
				Model: ModelInvitation, Data: invitationRecord(invitation),
				ForceAllowID: true,
			})
		}
		if findErr != nil {
			return findErr
		}
		invitation, findErr = invitationFromRecord(row)
		if findErr != nil {
			return findErr
		}
		if findErr = instance.audit(
			context, tx, "organization.invitation.created", invitation.ID,
			organizationID, map[string]any{"email": email, "role": role},
		); findErr != nil {
			return findErr
		}
		if instance.config.Hooks.AfterInvitationCreate != nil {
			if hookErr := instance.config.Hooks.AfterInvitationCreate(
				hookContext, invitation,
			); hookErr != nil {
				return hookErr
			}
		}
		if instance.config.Hooks.AfterMutation != nil {
			return instance.config.Hooks.AfterMutation(hookContext, event)
		}
		return nil
	})
	if err != nil {
		return nil, mapMutationError(err)
	}
	if instance.config.DeliverInvitation != nil {
		if err = instance.config.DeliverInvitation(
			context, invitation, organization, *context.User,
		); err != nil {
			return nil, internalError(err)
		}
	}
	return betterauth.JSONResponse(http.StatusOK, invitation)
}

func (instance *runtime) acceptInvitation(
	context *betterauth.HookContext,
) (*betterauth.PluginResponse, error) {
	if !context.User.EmailVerified {
		return nil, forbidden(errors.New("organization: verified email required"))
	}
	invitationID := bodyString(context, "invitationId")
	now := context.Clock.Now().UTC()
	memberID, err := context.GenerateID()
	if err != nil {
		return nil, internalError(err)
	}
	teamMemberID, err := context.GenerateID()
	if err != nil {
		return nil, internalError(err)
	}
	var invitation Invitation
	var member Member
	err = context.Database.Transaction(context.Context, func(tx betterauth.DatabaseAdapter) error {
		row, findErr := tx.FindOne(context.Context, betterauth.FindOneQuery{
			Model: ModelInvitation,
			Where: []betterauth.Where{
				betterauth.Eq("id", invitationID),
				betterauth.Eq("status", "pending"),
				betterauth.Eq("email", strings.ToLower(context.User.Email)),
			},
		})
		if findErr != nil || row == nil {
			if findErr == nil {
				findErr = betterauth.ErrNotFound
			}
			return findErr
		}
		invitation, findErr = invitationFromRecord(row)
		if findErr != nil {
			return findErr
		}
		if !invitation.ExpiresAt.After(now) {
			return badRequest("The invitation is invalid or expired.", nil)
		}
		if roleErr := instance.requireDefinedRoles(
			context, tx, invitation.OrganizationID, invitation.Role,
		); roleErr != nil {
			return roleErr
		}
		count, countErr := tx.Count(context.Context, betterauth.CountQuery{
			Model: ModelMember,
			Where: []betterauth.Where{
				betterauth.Eq("organizationId", invitation.OrganizationID),
			},
		})
		if countErr != nil {
			return countErr
		}
		if count >= int64(instance.config.MaxMembersPerOrganization) {
			return conflict("The organization member limit has been reached.", nil)
		}
		updated, updateErr := tx.Update(context.Context, betterauth.UpdateQuery{
			Model: ModelInvitation,
			Where: []betterauth.Where{
				betterauth.Eq("id", invitation.ID),
				betterauth.Eq("status", "pending"),
				betterauth.Where{
					Field: "expiresAt", Operator: betterauth.WhereGT, Value: now,
				},
			},
			Update: betterauth.Record{"status": "accepted", "updatedAt": now},
		})
		if updateErr != nil || updated == nil {
			if updateErr == nil {
				updateErr = betterauth.ErrReplay
			}
			return updateErr
		}
		member = Member{
			ID: memberID, OrganizationID: invitation.OrganizationID,
			UserID: context.User.ID, Role: invitation.Role,
			CreatedAt: now, UpdatedAt: now,
		}
		hookContext := contextWithDatabase(context, tx)
		event := MutationEvent{
			Action:         "organization.invitation.accepted",
			OrganizationID: invitation.OrganizationID, SubjectID: context.User.ID,
			Data: map[string]any{"invitationId": invitation.ID},
		}
		if instance.config.Hooks.BeforeMutation != nil {
			if hookErr := instance.config.Hooks.BeforeMutation(hookContext, event); hookErr != nil {
				return hookErr
			}
		}
		if instance.config.Hooks.BeforeMemberCreate != nil {
			if hookErr := instance.config.Hooks.BeforeMemberCreate(hookContext, &member); hookErr != nil {
				return hookErr
			}
			member.ID = memberID
			member.OrganizationID = invitation.OrganizationID
			member.UserID = context.User.ID
			member.Role = invitation.Role
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
		if invitation.TeamID != "" {
			team, teamErr := findTeam(
				context, tx, invitation.OrganizationID, invitation.TeamID,
			)
			if teamErr != nil {
				return teamErr
			}
			if _, createErr = tx.Create(context.Context, betterauth.CreateQuery{
				Model: ModelTeamMember,
				Data: betterauth.Record{
					"id": teamMemberID, "teamId": team.ID,
					"userId": context.User.ID, "createdAt": now,
				},
				ForceAllowID: true,
			}); createErr != nil {
				return createErr
			}
		}
		if createErr = instance.audit(
			context, tx, "organization.invitation.accepted", context.User.ID,
			invitation.OrganizationID, map[string]any{"invitationId": invitation.ID},
		); createErr != nil {
			return createErr
		}
		if instance.config.Hooks.AfterMemberCreate != nil {
			if hookErr := instance.config.Hooks.AfterMemberCreate(hookContext, member); hookErr != nil {
				return hookErr
			}
		}
		if instance.config.Hooks.AfterMutation != nil {
			return instance.config.Hooks.AfterMutation(hookContext, event)
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, betterauth.ErrReplay) || errors.Is(err, betterauth.ErrNotFound) {
			return nil, badRequest("The invitation is invalid or expired.", err)
		}
		return nil, mapMutationError(err)
	}
	return betterauth.JSONResponse(http.StatusOK, invitation)
}

func (instance *runtime) rejectInvitation(
	context *betterauth.HookContext,
) (*betterauth.PluginResponse, error) {
	return instance.transitionInvitation(context, "rejected", false)
}

func (instance *runtime) cancelInvitation(
	context *betterauth.HookContext,
) (*betterauth.PluginResponse, error) {
	return instance.transitionInvitation(context, "canceled", true)
}

func (instance *runtime) transitionInvitation(
	context *betterauth.HookContext,
	status string,
	requireManagement bool,
) (*betterauth.PluginResponse, error) {
	invitationID := bodyString(context, "invitationId")
	row, err := context.Database.FindOne(context.Context, betterauth.FindOneQuery{
		Model: ModelInvitation,
		Where: []betterauth.Where{
			betterauth.Eq("id", invitationID), betterauth.Eq("status", "pending"),
		},
	})
	if err != nil || row == nil {
		return nil, badRequest("The invitation is invalid or expired.", err)
	}
	invitation, err := invitationFromRecord(row)
	if err != nil {
		return nil, internalError(err)
	}
	if requireManagement {
		if _, err = instance.authorize(
			context, context.Database, invitation.OrganizationID,
			"invitation", "cancel",
		); err != nil {
			return nil, err
		}
	} else {
		if !context.User.EmailVerified ||
			!strings.EqualFold(invitation.Email, context.User.Email) {
			return nil, forbidden(nil)
		}
	}
	err = context.Database.Transaction(context.Context, func(tx betterauth.DatabaseAdapter) error {
		if requireManagement {
			if _, authorizeErr := instance.authorize(
				context, tx, invitation.OrganizationID, "invitation", "cancel",
			); authorizeErr != nil {
				return authorizeErr
			}
		}
		event := MutationEvent{
			Action:         "organization.invitation." + status,
			OrganizationID: invitation.OrganizationID, SubjectID: invitation.ID,
		}
		hookContext := contextWithDatabase(context, tx)
		if instance.config.Hooks.BeforeMutation != nil {
			if hookErr := instance.config.Hooks.BeforeMutation(hookContext, event); hookErr != nil {
				return hookErr
			}
		}
		if requireManagement {
			if _, authorizeErr := instance.authorize(
				context, tx, invitation.OrganizationID, "invitation", "cancel",
			); authorizeErr != nil {
				return authorizeErr
			}
		}
		updated, updateErr := tx.Update(context.Context, betterauth.UpdateQuery{
			Model: ModelInvitation,
			Where: []betterauth.Where{
				betterauth.Eq("id", invitation.ID),
				betterauth.Eq("status", "pending"),
			},
			Update: betterauth.Record{
				"status": status, "updatedAt": context.Clock.Now().UTC(),
			},
		})
		if updateErr != nil || updated == nil {
			if updateErr == nil {
				updateErr = betterauth.ErrReplay
			}
			return updateErr
		}
		invitation, updateErr = invitationFromRecord(updated)
		if updateErr != nil {
			return updateErr
		}
		if updateErr = instance.audit(
			context, tx, event.Action, invitation.ID, invitation.OrganizationID, nil,
		); updateErr != nil {
			return updateErr
		}
		if instance.config.Hooks.AfterMutation != nil {
			return instance.config.Hooks.AfterMutation(hookContext, event)
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, betterauth.ErrReplay) {
			return nil, badRequest("The invitation is invalid or expired.", err)
		}
		return nil, mapMutationError(err)
	}
	return betterauth.JSONResponse(http.StatusOK, invitation)
}

func (instance *runtime) getInvitation(
	context *betterauth.HookContext,
) (*betterauth.PluginResponse, error) {
	invitationID := strings.TrimSpace(context.Query.Get("invitationId"))
	row, err := context.Database.FindOne(context.Context, betterauth.FindOneQuery{
		Model: ModelInvitation,
		Where: []betterauth.Where{betterauth.Eq("id", invitationID)},
	})
	if err != nil || row == nil {
		return nil, notFound(err)
	}
	invitation, err := invitationFromRecord(row)
	if err != nil {
		return nil, internalError(err)
	}
	if strings.EqualFold(invitation.Email, context.User.Email) {
		if !context.User.EmailVerified {
			return nil, forbidden(nil)
		}
	} else {
		if _, err = instance.authorize(
			context, context.Database, invitation.OrganizationID,
			"invitation", "read",
		); err != nil {
			return nil, err
		}
	}
	return betterauth.JSONResponse(http.StatusOK, invitation)
}

func (instance *runtime) listInvitations(
	context *betterauth.HookContext,
) (*betterauth.PluginResponse, error) {
	organizationID, err := instance.selectedOrganizationID(context)
	if err != nil {
		return nil, err
	}
	if _, err = instance.authorize(
		context, context.Database, organizationID, "invitation", "read",
	); err != nil {
		return nil, err
	}
	limit, offset, err := queryPage(context, instance.config.MaxInvitationsPerOrganization)
	if err != nil {
		return nil, err
	}
	rows, err := context.Database.FindMany(context.Context, betterauth.FindManyQuery{
		Model: ModelInvitation,
		Where: []betterauth.Where{betterauth.Eq("organizationId", organizationID)},
		Limit: limit, Offset: offset,
		Sort: &betterauth.Sort{Field: "createdAt", Direction: "desc"},
	})
	if err != nil {
		return nil, internalError(err)
	}
	invitations, err := rowsToInvitations(rows)
	if err != nil {
		return nil, internalError(err)
	}
	return betterauth.JSONResponse(http.StatusOK, invitations)
}

func (instance *runtime) listUserInvitations(
	context *betterauth.HookContext,
) (*betterauth.PluginResponse, error) {
	if !context.User.EmailVerified {
		return nil, forbidden(nil)
	}
	limit, offset, err := queryPage(context, instance.config.MaxInvitationsPerOrganization)
	if err != nil {
		return nil, err
	}
	rows, err := context.Database.FindMany(context.Context, betterauth.FindManyQuery{
		Model: ModelInvitation,
		Where: []betterauth.Where{
			betterauth.Eq("email", strings.ToLower(context.User.Email)),
			betterauth.Eq("status", "pending"),
		},
		Limit: limit, Offset: offset,
		Sort: &betterauth.Sort{Field: "createdAt", Direction: "desc"},
	})
	if err != nil {
		return nil, internalError(err)
	}
	invitations, err := rowsToInvitations(rows)
	if err != nil {
		return nil, internalError(err)
	}
	return betterauth.JSONResponse(http.StatusOK, invitations)
}

func (instance *runtime) memberByEmail(
	context *betterauth.HookContext,
	database betterauth.DatabaseAdapter,
	organizationID, email string,
) (bool, error) {
	user, err := database.FindOne(context.Context, betterauth.FindOneQuery{
		Model: betterauth.ModelUser,
		Where: []betterauth.Where{{
			Field: "email", Operator: betterauth.WhereEQ,
			Value: email, Mode: betterauth.StringInsensitive,
		}},
		Select: []string{"id"},
	})
	if err != nil && !errors.Is(err, betterauth.ErrNotFound) {
		return false, err
	}
	if user == nil {
		return false, nil
	}
	userID, err := requiredString(user, "id")
	if err != nil {
		return false, err
	}
	row, err := database.FindOne(context.Context, betterauth.FindOneQuery{
		Model: ModelMember,
		Where: []betterauth.Where{
			betterauth.Eq("organizationId", organizationID),
			betterauth.Eq("userId", userID),
		},
		Select: []string{"id"},
	})
	if err != nil && !errors.Is(err, betterauth.ErrNotFound) {
		return false, err
	}
	return row != nil, nil
}

func invitationRecord(value Invitation) betterauth.Record {
	record := invitationUpdateRecord(value)
	record["id"] = value.ID
	record["organizationId"] = value.OrganizationID
	record["createdAt"] = value.CreatedAt
	return record
}

func invitationUpdateRecord(value Invitation) betterauth.Record {
	return betterauth.Record{
		"email": value.Email, "role": value.Role, "teamId": value.TeamID,
		"status": value.Status, "inviterId": value.InviterID,
		"expiresAt": value.ExpiresAt, "updatedAt": value.UpdatedAt,
	}
}
