package scim

import (
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	betterauth "github.com/eadwinCode/better-auth-go"
)

type managedUser struct {
	User    betterauth.User
	Account userBinding
}

func (instance *runtime) createUser(
	context *betterauth.HookContext,
) (*betterauth.PluginResponse, error) {
	connection, err := connectionFromContext(context)
	if err != nil {
		return scimInternal()
	}
	input, err := decodeUserInput(context.Body)
	if err == nil {
		input, err = normalizeUserInput(input)
	}
	if err != nil {
		return scimError(http.StatusBadRequest, "invalidValue", "Invalid User resource.")
	}
	email := primaryEmail(input)
	accountID := externalAccountID(input)
	existingAccount, accountErr := context.Database.FindOne(context.Context, betterauth.FindOneQuery{
		Model: ModelSCIMUser,
		Where: []betterauth.Where{
			betterauth.Eq("connectionId", connection.ProviderID),
			betterauth.Eq("externalId", accountID),
		},
	})
	if existingAccount != nil {
		return scimError(http.StatusConflict, "uniqueness", "User already exists.")
	}
	if accountErr != nil && !errors.Is(accountErr, betterauth.ErrNotFound) {
		return scimInternal()
	}

	now := context.Clock.Now().UTC()
	row, findErr := context.Database.FindOne(context.Context, betterauth.FindOneQuery{
		Model: betterauth.ModelUser, Where: []betterauth.Where{betterauth.Eq("email", email)},
	})
	existing := findErr == nil && row != nil
	if findErr != nil && !errors.Is(findErr, betterauth.ErrNotFound) {
		return scimInternal()
	}
	var user betterauth.User
	if existing {
		user, err = userFromSCIMRecord(row)
		if err != nil || !instance.canLinkExisting(context, connection, user, email) {
			return scimError(http.StatusConflict, "uniqueness", "User already exists.")
		}
		if input.Active != nil && !*input.Active {
			return scimError(
				http.StatusConflict, "uniqueness",
				"An existing user cannot be linked while inactive.",
			)
		}
	} else {
		userID, generateErr := context.GenerateID()
		if generateErr != nil {
			return scimInternal()
		}
		user = betterauth.User{
			ID: userID, Email: email, Name: fullName(input, email),
			EmailVerified: false, CreatedAt: now, UpdatedAt: now,
		}
		if input.Active != nil && !*input.Active {
			user.DisabledAt = &now
		}
	}
	accountIDValue, err := context.GenerateID()
	if err != nil {
		return scimInternal()
	}
	account := userBinding{
		ID: accountIDValue, UserID: user.ID, Provider: connection.ProviderID,
		ProviderAccountID: accountID, OwnsUser: !existing, CreatedAt: now, UpdatedAt: now,
	}
	if instance.config.Hooks.BeforeUserCreate != nil {
		if err = instance.config.Hooks.BeforeUserCreate(context, user, connection); err != nil {
			return nil, err
		}
	}
	err = context.Database.Transaction(context.Context, func(tx betterauth.DatabaseAdapter) error {
		if !existing {
			if _, createErr := tx.Create(context.Context, betterauth.CreateQuery{
				Model: betterauth.ModelUser, ForceAllowID: true, Data: scimUserRecord(user),
			}); createErr != nil {
				return createErr
			}
		}
		if _, createErr := tx.Create(context.Context, betterauth.CreateQuery{
			Model: ModelSCIMUser, ForceAllowID: true, Data: scimAccountRecord(account),
		}); createErr != nil {
			return createErr
		}
		if connection.OrganizationID != "" {
			transactionContext := *context
			transactionContext.Database = tx
			if err := instance.config.OrganizationAuthorizer.AddSCIMMember(
				&transactionContext, connection.OrganizationID, user.ID,
			); err != nil {
				return err
			}
		}
		if user.DisabledAt != nil {
			if _, revokeErr := tx.UpdateMany(context.Context, betterauth.UpdateQuery{
				Model: betterauth.ModelSession,
				Where: []betterauth.Where{
					betterauth.Eq("userId", user.ID), betterauth.Eq("revokedAt", nil),
				},
				Update: betterauth.Record{"revokedAt": now, "updatedAt": now},
			}); revokeErr != nil {
				return revokeErr
			}
		}
		return writeAudit(context, tx, "scim.user.created", protocolActor(connection), user.ID,
			map[string]string{
				"connectionId": connection.ProviderID, "organizationId": connection.OrganizationID,
				"linkedExisting": strconv.FormatBool(existing),
			})
	})
	if err != nil {
		if errors.Is(err, betterauth.ErrConflict) {
			return scimError(http.StatusConflict, "uniqueness", "User already exists.")
		}
		return scimInternal()
	}
	if instance.config.Hooks.AfterUserCreate != nil {
		if err = instance.config.Hooks.AfterUserCreate(context, user, connection); err != nil {
			return nil, err
		}
	}
	resource := resourceFromManaged(context.BaseURL, managedUser{User: user, Account: account})
	response, err := scimJSON(http.StatusCreated, resource)
	if err == nil {
		response.Headers.Set("Location", resource.Meta.Location)
	}
	return response, err
}

func (instance *runtime) listUsers(
	context *betterauth.HookContext,
) (*betterauth.PluginResponse, error) {
	connection, err := connectionFromContext(context)
	if err != nil {
		return scimInternal()
	}
	filters, err := parseFilter(
		context.Query.Get("filter"), instance.config.MaxFilterBytes, instance.config.MaxFilterClauses,
	)
	if err != nil {
		return scimError(http.StatusBadRequest, "invalidFilter", "Invalid filter.")
	}
	start := queryInteger(context.Query, "startIndex", 1)
	if start < 1 {
		return scimError(http.StatusBadRequest, "invalidValue", "Invalid startIndex.")
	}
	count := queryInteger(context.Query, "count", instance.config.MaxPageSize)
	if count < 0 || count > instance.config.MaxPageSize {
		return scimError(http.StatusBadRequest, "invalidValue", "Invalid count.")
	}
	resources := make([]UserResource, 0, count)
	total := 0
	if len(filters) > 0 {
		managed, found, findErr := instance.findFilteredUser(context, connection, filters)
		if findErr != nil {
			return scimInternal()
		}
		if found {
			total = 1
			if start == 1 && count > 0 {
				resources = append(resources, resourceFromManaged(context.BaseURL, managed))
			}
		}
	} else {
		totalCount, countErr := context.Database.Count(context.Context, betterauth.CountQuery{
			Model: ModelSCIMUser,
			Where: []betterauth.Where{betterauth.Eq("connectionId", connection.ProviderID)},
		})
		if countErr != nil {
			return scimInternal()
		}
		total = int(totalCount)
		if count > 0 && start <= total {
			accounts, findErr := context.Database.FindMany(context.Context, betterauth.FindManyQuery{
				Model: ModelSCIMUser,
				Where: []betterauth.Where{betterauth.Eq("connectionId", connection.ProviderID)},
				Limit: count, Offset: start - 1,
				Sort: &betterauth.Sort{Field: "createdAt", Direction: "asc"},
			})
			if findErr != nil {
				return scimInternal()
			}
			for _, accountRow := range accounts {
				account, parseErr := accountFromSCIMRecord(accountRow)
				if parseErr != nil {
					return scimInternal()
				}
				userRow, userErr := context.Database.FindOne(
					context.Context,
					betterauth.FindOneQuery{
						Model: betterauth.ModelUser,
						Where: []betterauth.Where{betterauth.Eq("id", account.UserID)},
					},
				)
				if userErr != nil || userRow == nil {
					continue
				}
				user, parseErr := userFromSCIMRecord(userRow)
				if parseErr != nil {
					return scimInternal()
				}
				if instance.connectionOwnsUser(context, connection, user.ID) {
					resources = append(
						resources,
						resourceFromManaged(context.BaseURL, managedUser{User: user, Account: account}),
					)
				}
			}
		}
	}
	return scimJSON(http.StatusOK, map[string]any{
		"schemas": []string{SchemaListResponse}, "totalResults": total,
		"startIndex": start, "itemsPerPage": len(resources), "Resources": resources,
	})
}

func (instance *runtime) findFilteredUser(
	context *betterauth.HookContext,
	connection ProviderConnection,
	filters []Filter,
) (managedUser, bool, error) {
	var userWhere []betterauth.Where
	accountWhere := []betterauth.Where{betterauth.Eq("connectionId", connection.ProviderID)}
	for _, filter := range filters {
		switch filter.Field {
		case "id", "email":
			userWhere = append(userWhere, betterauth.Eq(filter.Field, filter.Value))
		case "accountId":
			accountWhere = append(accountWhere, betterauth.Eq("externalId", filter.Value))
		default:
			return managedUser{}, false, errors.New("scim: unsafe filter field")
		}
	}
	var userRow, accountRow betterauth.Record
	var err error
	if len(userWhere) > 0 {
		userRow, err = context.Database.FindOne(context.Context, betterauth.FindOneQuery{
			Model: betterauth.ModelUser, Where: userWhere,
		})
		if err != nil || userRow == nil {
			return managedUser{}, false, normalizeFindError(err)
		}
		userID, _ := userRow["id"].(string)
		accountWhere = append(accountWhere, betterauth.Eq("userId", userID))
		accountRow, err = context.Database.FindOne(context.Context, betterauth.FindOneQuery{
			Model: ModelSCIMUser, Where: accountWhere,
		})
		if err != nil || accountRow == nil {
			return managedUser{}, false, normalizeFindError(err)
		}
	} else {
		accountRow, err = context.Database.FindOne(context.Context, betterauth.FindOneQuery{
			Model: ModelSCIMUser, Where: accountWhere,
		})
		if err != nil || accountRow == nil {
			return managedUser{}, false, normalizeFindError(err)
		}
		accountUserID, _ := accountRow["userId"].(string)
		userRow, err = context.Database.FindOne(context.Context, betterauth.FindOneQuery{
			Model: betterauth.ModelUser,
			Where: []betterauth.Where{betterauth.Eq("id", accountUserID)},
		})
		if err != nil || userRow == nil {
			return managedUser{}, false, normalizeFindError(err)
		}
	}
	user, err := userFromSCIMRecord(userRow)
	if err != nil {
		return managedUser{}, false, err
	}
	account, err := accountFromSCIMRecord(accountRow)
	if err != nil {
		return managedUser{}, false, err
	}
	managed := managedUser{User: user, Account: account}
	if !instance.connectionOwnsUser(context, connection, user.ID) ||
		!filtersMatch(managed, filters) {
		return managedUser{}, false, nil
	}
	return managed, true, nil
}

func normalizeFindError(err error) error {
	if err == nil || errors.Is(err, betterauth.ErrNotFound) {
		return nil
	}
	return err
}

func (instance *runtime) getUser(
	context *betterauth.HookContext,
) (*betterauth.PluginResponse, error) {
	connection, err := connectionFromContext(context)
	if err != nil {
		return scimInternal()
	}
	managed, response := instance.findManagedUser(context, connection, context.Params["userId"])
	if response != nil {
		return response, nil
	}
	return scimJSON(http.StatusOK, resourceFromManaged(context.BaseURL, managed))
}

func (instance *runtime) replaceUser(
	context *betterauth.HookContext,
) (*betterauth.PluginResponse, error) {
	input, err := decodeUserInput(context.Body)
	if err == nil {
		input, err = normalizeUserInput(input)
	}
	if err != nil {
		return scimError(http.StatusBadRequest, "invalidValue", "Invalid User resource.")
	}
	return instance.updateUser(context, input, false)
}

func (instance *runtime) patchUser(
	context *betterauth.HookContext,
) (*betterauth.PluginResponse, error) {
	connection, err := connectionFromContext(context)
	if err != nil {
		return scimInternal()
	}
	managed, response := instance.findManagedUser(context, connection, context.Params["userId"])
	if response != nil {
		return response, nil
	}
	request, err := decodePatchRequest(context.Body)
	if err != nil || len(request.Operations) == 0 ||
		len(request.Operations) > instance.config.MaxPatchOperations ||
		!containsFold(request.Schemas, SchemaPatch) {
		return scimError(http.StatusBadRequest, "invalidSyntax", "Invalid PatchOp resource.")
	}
	active := managed.User.DisabledAt == nil
	input := UserInput{
		Schemas: []string{SchemaUser}, UserName: managed.User.Email,
		ExternalID: managed.Account.ProviderAccountID,
		Name:       &Name{Formatted: managed.User.Name},
		Emails:     []Email{{Value: managed.User.Email, Primary: true}}, Active: &active,
	}
	if err = applyPatchOperations(&input, request.Operations); err != nil {
		return scimError(http.StatusBadRequest, "invalidPath", "Invalid patch operation.")
	}
	input, err = normalizeUserInput(input)
	if err != nil {
		return scimError(http.StatusBadRequest, "invalidValue", "Invalid patch value.")
	}
	response, err = instance.updateUser(context, input, true)
	if err != nil || response == nil || response.Status >= 400 {
		return response, err
	}
	return noContentResponse(), nil
}

func (instance *runtime) updateUser(
	context *betterauth.HookContext,
	input UserInput,
	patch bool,
) (*betterauth.PluginResponse, error) {
	connection, err := connectionFromContext(context)
	if err != nil {
		return scimInternal()
	}
	managed, response := instance.findManagedUser(context, connection, context.Params["userId"])
	if response != nil {
		return response, nil
	}
	email := primaryEmail(input)
	accountID := externalAccountID(input)
	if email != managed.User.Email {
		row, findErr := context.Database.FindOne(context.Context, betterauth.FindOneQuery{
			Model: betterauth.ModelUser, Where: []betterauth.Where{betterauth.Eq("email", email)},
		})
		if findErr == nil && row != nil {
			return scimError(http.StatusConflict, "uniqueness", "Email is already in use.")
		}
		if findErr != nil && !errors.Is(findErr, betterauth.ErrNotFound) {
			return scimInternal()
		}
	}
	if accountID != managed.Account.ProviderAccountID {
		row, findErr := context.Database.FindOne(context.Context, betterauth.FindOneQuery{
			Model: ModelSCIMUser,
			Where: []betterauth.Where{
				betterauth.Eq("connectionId", connection.ProviderID),
				betterauth.Eq("externalId", accountID),
			},
		})
		if findErr == nil && row != nil {
			return scimError(http.StatusConflict, "uniqueness", "External identity is already in use.")
		}
		if findErr != nil && !errors.Is(findErr, betterauth.ErrNotFound) {
			return scimInternal()
		}
	}
	now := context.Clock.Now().UTC()
	updated := managed.User
	updated.Email = email
	updated.Name = fullName(input, email)
	updated.UpdatedAt = now
	if email != managed.User.Email {
		updated.EmailVerified = false
	}
	deactivating := false
	if input.Active != nil {
		if *input.Active {
			updated.DisabledAt = nil
		} else {
			if updated.DisabledAt == nil {
				deactivating = true
			}
			updated.DisabledAt = &now
		}
	}
	updatedAccount := managed.Account
	updatedAccount.ProviderAccountID = accountID
	updatedAccount.UpdatedAt = now
	if instance.config.Hooks.BeforeUserUpdate != nil {
		if err = instance.config.Hooks.BeforeUserUpdate(context, updated, connection); err != nil {
			return nil, err
		}
	}
	err = context.Database.Transaction(context.Context, func(tx betterauth.DatabaseAdapter) error {
		if _, updateErr := tx.Update(context.Context, betterauth.UpdateQuery{
			Model: betterauth.ModelUser,
			Where: []betterauth.Where{betterauth.Eq("id", updated.ID)},
			Update: betterauth.Record{
				"email": updated.Email, "name": updated.Name,
				"emailVerified": updated.EmailVerified, "disabledAt": nullableTime(updated.DisabledAt),
				"updatedAt": updated.UpdatedAt,
			},
		}); updateErr != nil {
			return updateErr
		}
		if _, updateErr := tx.Update(context.Context, betterauth.UpdateQuery{
			Model: ModelSCIMUser,
			Where: []betterauth.Where{
				betterauth.Eq("id", updatedAccount.ID),
				betterauth.Eq("connectionId", connection.ProviderID),
			},
			Update: betterauth.Record{
				"externalId": updatedAccount.ProviderAccountID,
				"connectionUserKey": scimConnectionUserKey(
					connection.ProviderID, updatedAccount.ProviderAccountID,
				),
				"updatedAt": updatedAccount.UpdatedAt,
			},
		}); updateErr != nil {
			return updateErr
		}
		if deactivating {
			if _, revokeErr := tx.UpdateMany(context.Context, betterauth.UpdateQuery{
				Model: betterauth.ModelSession,
				Where: []betterauth.Where{
					betterauth.Eq("userId", updated.ID), betterauth.Eq("revokedAt", nil),
				},
				Update: betterauth.Record{"revokedAt": now, "updatedAt": now},
			}); revokeErr != nil {
				return revokeErr
			}
		}
		action := "scim.user.updated"
		if patch {
			action = "scim.user.patched"
		}
		if deactivating {
			action = "scim.user.deactivated"
		}
		return writeAudit(context, tx, action, protocolActor(connection), updated.ID,
			map[string]string{"connectionId": connection.ProviderID})
	})
	if err != nil {
		if errors.Is(err, betterauth.ErrConflict) {
			return scimError(http.StatusConflict, "uniqueness", "User update conflicts.")
		}
		return scimInternal()
	}
	if instance.config.Hooks.AfterUserUpdate != nil {
		if err = instance.config.Hooks.AfterUserUpdate(context, updated, connection); err != nil {
			return nil, err
		}
	}
	return scimJSON(
		http.StatusOK,
		resourceFromManaged(context.BaseURL, managedUser{User: updated, Account: updatedAccount}),
	)
}

func (instance *runtime) deleteUser(
	context *betterauth.HookContext,
) (*betterauth.PluginResponse, error) {
	connection, err := connectionFromContext(context)
	if err != nil {
		return scimInternal()
	}
	managed, response := instance.findManagedUser(context, connection, context.Params["userId"])
	if response != nil {
		return response, nil
	}
	if instance.config.Hooks.BeforeUserDelete != nil {
		if err = instance.config.Hooks.BeforeUserDelete(context, managed.User, connection); err != nil {
			return nil, err
		}
	}
	err = context.Database.Transaction(context.Context, func(tx betterauth.DatabaseAdapter) error {
		if connection.OrganizationID != "" {
			transactionContext := *context
			transactionContext.Database = tx
			if err := instance.config.OrganizationAuthorizer.RemoveSCIMMember(
				&transactionContext, connection.OrganizationID, managed.User.ID,
			); err != nil {
				return err
			}
			if err := tx.Delete(context.Context, betterauth.DeleteQuery{
				Model: ModelSCIMUser,
				Where: []betterauth.Where{
					betterauth.Eq("id", managed.Account.ID),
					betterauth.Eq("connectionId", connection.ProviderID),
				},
			}); err != nil {
				return err
			}
		} else {
			bindingCount, countErr := tx.Count(context.Context, betterauth.CountQuery{
				Model: ModelSCIMUser,
				Where: []betterauth.Where{betterauth.Eq("userId", managed.User.ID)},
			})
			if countErr != nil {
				return countErr
			}
			deleteGlobalUser := false
			if managed.Account.OwnsUser && bindingCount == 1 {
				authAccountCount, accountErr := tx.Count(context.Context, betterauth.CountQuery{
					Model: betterauth.ModelAccount,
					Where: []betterauth.Where{betterauth.Eq("userId", managed.User.ID)},
				})
				if accountErr != nil {
					return accountErr
				}
				deleteGlobalUser = authAccountCount == 0
			}
			if !deleteGlobalUser {
				if err := tx.Delete(context.Context, betterauth.DeleteQuery{
					Model: ModelSCIMUser,
					Where: []betterauth.Where{betterauth.Eq("id", managed.Account.ID)},
				}); err != nil {
					return err
				}
			} else {
				if _, err := tx.DeleteMany(context.Context, betterauth.DeleteQuery{
					Model: betterauth.ModelSession,
					Where: []betterauth.Where{betterauth.Eq("userId", managed.User.ID)},
				}); err != nil {
					return err
				}
				if _, err := tx.DeleteMany(context.Context, betterauth.DeleteQuery{
					Model: ModelSCIMUser,
					Where: []betterauth.Where{betterauth.Eq("userId", managed.User.ID)},
				}); err != nil {
					return err
				}
				if err := tx.Delete(context.Context, betterauth.DeleteQuery{
					Model: betterauth.ModelUser,
					Where: []betterauth.Where{betterauth.Eq("id", managed.User.ID)},
				}); err != nil {
					return err
				}
			}
		}
		return writeAudit(context, tx, "scim.user.deprovisioned",
			protocolActor(connection), managed.User.ID,
			map[string]string{
				"connectionId": connection.ProviderID, "organizationId": connection.OrganizationID,
			})
	})
	if err != nil {
		return scimInternal()
	}
	if instance.config.Hooks.AfterUserDelete != nil {
		if err = instance.config.Hooks.AfterUserDelete(context, managed.User, connection); err != nil {
			return nil, err
		}
	}
	return noContentResponse(), nil
}

func (instance *runtime) findManagedUser(
	context *betterauth.HookContext,
	connection ProviderConnection,
	userID string,
) (managedUser, *betterauth.PluginResponse) {
	userID = strings.TrimSpace(userID)
	if userID == "" || len(userID) > 512 {
		response, _ := scimError(http.StatusNotFound, "", "User not found.")
		return managedUser{}, response
	}
	accountRow, err := context.Database.FindOne(context.Context, betterauth.FindOneQuery{
		Model: ModelSCIMUser,
		Where: []betterauth.Where{
			betterauth.Eq("userId", userID), betterauth.Eq("connectionId", connection.ProviderID),
		},
	})
	if err != nil || accountRow == nil {
		response, _ := scimError(http.StatusNotFound, "", "User not found.")
		return managedUser{}, response
	}
	if !instance.connectionOwnsUser(context, connection, userID) {
		response, _ := scimError(http.StatusNotFound, "", "User not found.")
		return managedUser{}, response
	}
	userRow, err := context.Database.FindOne(context.Context, betterauth.FindOneQuery{
		Model: betterauth.ModelUser, Where: []betterauth.Where{betterauth.Eq("id", userID)},
	})
	if err != nil || userRow == nil {
		response, _ := scimError(http.StatusNotFound, "", "User not found.")
		return managedUser{}, response
	}
	user, userErr := userFromSCIMRecord(userRow)
	account, accountErr := accountFromSCIMRecord(accountRow)
	if userErr != nil || accountErr != nil {
		response, _ := scimInternal()
		return managedUser{}, response
	}
	return managedUser{User: user, Account: account}, nil
}

func (instance *runtime) connectionOwnsUser(
	context *betterauth.HookContext,
	connection ProviderConnection,
	userID string,
) bool {
	if connection.OrganizationID == "" {
		return true
	}
	if instance.config.OrganizationAuthorizer == nil {
		return false
	}
	member, err := instance.config.OrganizationAuthorizer.IsSCIMMember(
		context, connection.OrganizationID, userID,
	)
	return err == nil && member
}

func (instance *runtime) canLinkExisting(
	context *betterauth.HookContext,
	connection ProviderConnection,
	user betterauth.User,
	email string,
) bool {
	policy := instance.config.LinkExistingUsers
	if !policy.Enabled {
		return false
	}
	if len(policy.TrustedDomains) > 0 {
		_, domain, found := strings.Cut(email, "@")
		if !found || !slices.Contains(policy.TrustedDomains, domain) {
			return false
		}
	}
	if policy.RequireExistingOrgMembership {
		if connection.OrganizationID == "" || instance.config.OrganizationAuthorizer == nil {
			return false
		}
		member, err := instance.config.OrganizationAuthorizer.IsSCIMMember(
			context, connection.OrganizationID, user.ID,
		)
		if err != nil || !member {
			return false
		}
	}
	if policy.Allow != nil {
		allowed, err := policy.Allow(context, user, email, connection)
		return err == nil && allowed
	}
	return true
}

func resourceFromManaged(baseURL string, managed managedUser) UserResource {
	name := (*Name)(nil)
	if managed.User.Name != "" {
		name = &Name{Formatted: managed.User.Name}
	}
	return UserResource{
		Schemas: []string{SchemaUser}, ID: managed.User.ID,
		ExternalID: managed.Account.ProviderAccountID, UserName: managed.User.Email,
		Name: name, DisplayName: managed.User.Name, Active: managed.User.DisabledAt == nil,
		Emails: []Email{{Value: managed.User.Email, Primary: true}},
		Meta: ResourceMeta{
			ResourceType: "User", Created: managed.User.CreatedAt,
			LastModified: managed.User.UpdatedAt,
			Location: strings.TrimRight(baseURL, "/") + "/scim/v2/Users/" +
				url.PathEscape(managed.User.ID),
		},
	}
}

func userFromSCIMRecord(row betterauth.Record) (betterauth.User, error) {
	id, idOK := row["id"].(string)
	email, emailOK := row["email"].(string)
	created, createdOK := row["createdAt"].(time.Time)
	updated, updatedOK := row["updatedAt"].(time.Time)
	if !idOK || id == "" || !emailOK || email == "" || !createdOK || !updatedOK {
		return betterauth.User{}, errors.New("scim: invalid user record")
	}
	return betterauth.User{
		ID: id, Email: email, Name: stringOrEmpty(row["name"]),
		ImageURL: stringOrEmpty(row["image"]), EmailVerified: boolOr(row["emailVerified"], false),
		CreatedAt: created.UTC(), UpdatedAt: updated.UTC(), DisabledAt: timePtr(row["disabledAt"]),
	}, nil
}

func accountFromSCIMRecord(row betterauth.Record) (userBinding, error) {
	id, idOK := row["id"].(string)
	userID, userOK := row["userId"].(string)
	providerID, providerOK := row["connectionId"].(string)
	accountID, accountOK := row["externalId"].(string)
	created, createdOK := row["createdAt"].(time.Time)
	updated, updatedOK := row["updatedAt"].(time.Time)
	if !idOK || !userOK || !providerOK || !accountOK || !createdOK || !updatedOK ||
		id == "" || userID == "" || providerID == "" || accountID == "" {
		return userBinding{}, errors.New("scim: invalid user binding record")
	}
	return userBinding{
		ID: id, UserID: userID, Provider: providerID, ProviderAccountID: accountID,
		OwnsUser:  boolOr(row["ownsUser"], false),
		CreatedAt: created.UTC(), UpdatedAt: updated.UTC(),
	}, nil
}

func scimUserRecord(user betterauth.User) betterauth.Record {
	return betterauth.Record{
		"id": user.ID, "email": user.Email, "name": user.Name, "image": user.ImageURL,
		"emailVerified": user.EmailVerified, "createdAt": user.CreatedAt,
		"updatedAt": user.UpdatedAt, "disabledAt": nullableTime(user.DisabledAt),
	}
}

func scimAccountRecord(account userBinding) betterauth.Record {
	return betterauth.Record{
		"id": account.ID, "userId": account.UserID, "connectionId": account.Provider,
		"externalId":        account.ProviderAccountID,
		"connectionUserKey": scimConnectionUserKey(account.Provider, account.ProviderAccountID),
		"ownsUser":          account.OwnsUser,
		"createdAt":         account.CreatedAt,
		"updatedAt":         account.UpdatedAt,
	}
}

func scimConnectionUserKey(connectionID, externalID string) string {
	return betterauth.HashToken(connectionID + "\x00" + externalID)
}

func primaryEmail(input UserInput) string {
	for _, email := range input.Emails {
		if email.Primary {
			return strings.ToLower(strings.TrimSpace(email.Value))
		}
	}
	if len(input.Emails) > 0 {
		return strings.ToLower(strings.TrimSpace(input.Emails[0].Value))
	}
	return strings.ToLower(strings.TrimSpace(input.UserName))
}

func externalAccountID(input UserInput) string {
	if value := strings.TrimSpace(input.ExternalID); value != "" {
		return value
	}
	return strings.ToLower(strings.TrimSpace(input.UserName))
}

func fullName(input UserInput, fallback string) string {
	if input.Name == nil {
		return fallback
	}
	if input.Name.Formatted != "" {
		return input.Name.Formatted
	}
	if name := strings.TrimSpace(input.Name.GivenName + " " + input.Name.FamilyName); name != "" {
		return name
	}
	return fallback
}

func filtersMatch(managed managedUser, filters []Filter) bool {
	for _, filter := range filters {
		var value string
		switch filter.Field {
		case "id":
			value = managed.User.ID
		case "email":
			value = managed.User.Email
		case "accountId":
			value = managed.Account.ProviderAccountID
		default:
			return false
		}
		if !strings.EqualFold(value, filter.Value) {
			return false
		}
	}
	return true
}

func queryInteger(query url.Values, name string, fallback int) int {
	raw := strings.TrimSpace(query.Get(name))
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return -1
	}
	return value
}

func scimInternal() (*betterauth.PluginResponse, error) {
	return scimError(http.StatusInternalServerError, "", "The request could not be completed.")
}

func noContentResponse() *betterauth.PluginResponse {
	return &betterauth.PluginResponse{
		Status:  http.StatusNoContent,
		Headers: http.Header{"Content-Type": []string{"application/scim+json; charset=utf-8"}},
	}
}
