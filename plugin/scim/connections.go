package scim

import (
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	betterauth "github.com/eadwinCode/better-auth-go"
)

type scimContextKey struct{}

func (instance *runtime) generateToken(
	context *betterauth.HookContext,
) (*betterauth.PluginResponse, error) {
	body, _ := context.Body.(map[string]any)
	providerID, _ := body["providerId"].(string)
	providerID = strings.ToLower(strings.TrimSpace(providerID))
	organizationID, _ := body["organizationId"].(string)
	organizationID = strings.TrimSpace(organizationID)
	if !validIdentifier(providerID, 128) ||
		slices.Contains(instance.config.ReservedProviderIDs, providerID) {
		return nil, betterauth.NewError(
			betterauth.CodeBadRequest, "Invalid SCIM provider identifier.",
			http.StatusBadRequest, nil,
		)
	}
	if organizationID != "" {
		if instance.config.OrganizationAuthorizer == nil {
			return nil, betterauth.NewError(
				betterauth.CodeBadRequest,
				"Organization-scoped SCIM is not configured.",
				http.StatusBadRequest, nil,
			)
		}
		if err := instance.authorizeOrganization(context, organizationID); err != nil {
			return nil, betterauth.NewError(
				betterauth.CodeForbidden, "You are not allowed to manage this SCIM connection.",
				http.StatusForbidden, err,
			)
		}
	}
	if instance.config.CanGenerateToken != nil {
		allowed, err := instance.config.CanGenerateToken(context, providerID, organizationID)
		if err != nil || !allowed {
			return nil, betterauth.NewError(
				betterauth.CodeForbidden, "You are not allowed to generate a SCIM token.",
				http.StatusForbidden, err,
			)
		}
	}

	existing, err := context.Database.FindOne(context.Context, betterauth.FindOneQuery{
		Model: ModelSCIMProvider, Where: []betterauth.Where{betterauth.Eq("providerId", providerID)},
	})
	if err != nil && !errors.Is(err, betterauth.ErrNotFound) {
		return nil, internalManagementError(err)
	}
	if existing != nil {
		connection, parseErr := providerFromRecord(existing)
		if parseErr != nil {
			return nil, internalManagementError(parseErr)
		}
		if authErr := instance.authorizeConnection(context, connection); authErr != nil {
			return nil, authErr
		}
		if connection.OrganizationID != organizationID {
			return nil, betterauth.NewError(
				betterauth.CodeConflict, "SCIM provider identifier is already in use.",
				http.StatusConflict, nil,
			)
		}
	}
	if _, hasSSO := context.Schema["ssoProvider"]; hasSSO {
		ssoProvider, findErr := context.Database.FindOne(
			context.Context,
			betterauth.FindOneQuery{
				Model: "ssoProvider",
				Where: []betterauth.Where{betterauth.Eq("providerId", providerID)},
			},
		)
		if findErr != nil && !errors.Is(findErr, betterauth.ErrNotFound) {
			return nil, internalManagementError(findErr)
		}
		if ssoProvider != nil {
			return nil, betterauth.NewError(
				betterauth.CodeConflict,
				"SCIM provider identifier collides with an SSO provider.",
				http.StatusConflict, nil,
			)
		}
	}
	count, err := context.Database.Count(context.Context, betterauth.CountQuery{
		Model: ModelSCIMProvider,
	})
	if err != nil {
		return nil, internalManagementError(err)
	}
	if existing == nil && count >= int64(instance.config.ProviderLimit) {
		return nil, betterauth.NewError(
			betterauth.CodeConflict, "SCIM provider limit reached.", http.StatusConflict, nil,
		)
	}
	secret, err := context.GenerateToken(32)
	if err != nil {
		return nil, internalManagementError(err)
	}
	raw, err := encodeBearerToken(secret, providerID, organizationID)
	if err != nil {
		return nil, internalManagementError(err)
	}
	now := context.Clock.Now().UTC()
	connection := ProviderConnection{
		ProviderID: providerID, OrganizationID: organizationID,
		UserID: context.User.ID, CreatedAt: now, UpdatedAt: now,
	}
	if instance.config.TokenTTL > 0 {
		expires := now.Add(instance.config.TokenTTL)
		connection.ExpiresAt = &expires
	}
	if existing != nil {
		connection.ID, _ = existing["id"].(string)
		connection.CreatedAt = recordTimeOr(existing["createdAt"], now)
	} else {
		connection.ID, err = context.GenerateID()
		if err != nil {
			return nil, internalManagementError(err)
		}
	}
	if instance.config.Hooks.BeforeTokenGenerated != nil {
		if err = instance.config.Hooks.BeforeTokenGenerated(
			context, *context.User, connection,
		); err != nil {
			return nil, err
		}
	}
	err = context.Database.Transaction(context.Context, func(tx betterauth.DatabaseAdapter) error {
		if existing == nil {
			_, err = tx.Create(context.Context, betterauth.CreateQuery{
				Model: ModelSCIMProvider, ForceAllowID: true,
				Data: providerRecord(connection, betterauth.HashToken(secret)),
			})
		} else {
			_, err = tx.Update(context.Context, betterauth.UpdateQuery{
				Model: ModelSCIMProvider,
				Where: []betterauth.Where{betterauth.Eq("id", connection.ID)},
				Update: betterauth.Record{
					"tokenHash": betterauth.HashToken(secret), "organizationId": nullableString(organizationID),
					"userId": context.User.ID, "updatedAt": now, "expiresAt": nullableTime(connection.ExpiresAt),
					"lastUsedAt": nil,
				},
			})
		}
		if err != nil {
			return err
		}
		return writeAudit(context, tx, "scim.connection.rotated", context.User.ID, context.User.ID,
			map[string]string{"providerId": providerID, "organizationId": organizationID})
	})
	if err != nil {
		return nil, internalManagementError(err)
	}
	if instance.config.Hooks.AfterTokenGenerated != nil {
		if err = instance.config.Hooks.AfterTokenGenerated(
			context, *context.User, connection,
		); err != nil {
			return nil, err
		}
	}
	response, err := betterauth.JSONResponse(http.StatusCreated, map[string]string{"scimToken": raw})
	return response, err
}

func (instance *runtime) listConnections(
	context *betterauth.HookContext,
) (*betterauth.PluginResponse, error) {
	rows, err := context.Database.FindMany(context.Context, betterauth.FindManyQuery{
		Model: ModelSCIMProvider, Limit: min(instance.config.ProviderLimit, 1000),
		Sort: &betterauth.Sort{Field: "createdAt", Direction: "desc"},
	})
	if err != nil {
		return nil, internalManagementError(err)
	}
	providers := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		connection, parseErr := providerFromRecord(row)
		if parseErr != nil {
			return nil, internalManagementError(parseErr)
		}
		if instance.authorizeConnection(context, connection) == nil {
			providers = append(providers, publicConnection(connection))
		}
	}
	return betterauth.JSONResponse(http.StatusOK, map[string]any{"providers": providers})
}

func (instance *runtime) getConnection(
	context *betterauth.HookContext,
) (*betterauth.PluginResponse, error) {
	connection, err := instance.connectionByProvider(context, context.Query.Get("providerId"))
	if err != nil {
		return nil, err
	}
	if err = instance.authorizeConnection(context, connection); err != nil {
		return nil, err
	}
	return betterauth.JSONResponse(http.StatusOK, publicConnection(connection))
}

func (instance *runtime) deleteConnection(
	context *betterauth.HookContext,
) (*betterauth.PluginResponse, error) {
	body, _ := context.Body.(map[string]any)
	providerID, _ := body["providerId"].(string)
	connection, err := instance.connectionByProvider(context, providerID)
	if err != nil {
		return nil, err
	}
	if err = instance.authorizeConnection(context, connection); err != nil {
		return nil, err
	}
	err = context.Database.Transaction(context.Context, func(tx betterauth.DatabaseAdapter) error {
		bindings, countErr := tx.Count(context.Context, betterauth.CountQuery{
			Model: ModelSCIMUser,
			Where: []betterauth.Where{betterauth.Eq("connectionId", connection.ProviderID)},
		})
		if countErr != nil {
			return countErr
		}
		if bindings != 0 {
			return betterauth.ErrConflict
		}
		if err := tx.Delete(context.Context, betterauth.DeleteQuery{
			Model: ModelSCIMProvider,
			Where: []betterauth.Where{betterauth.Eq("id", connection.ID)},
		}); err != nil {
			return err
		}
		return writeAudit(context, tx, "scim.connection.deleted", context.User.ID, context.User.ID,
			map[string]string{"providerId": connection.ProviderID})
	})
	if err != nil {
		if errors.Is(err, betterauth.ErrConflict) {
			return nil, betterauth.NewError(
				betterauth.CodeConflict,
				"Deprovision every SCIM user before deleting the connection.",
				http.StatusConflict, err,
			)
		}
		return nil, internalManagementError(err)
	}
	return betterauth.JSONResponse(http.StatusOK, map[string]bool{"success": true})
}

func (instance *runtime) connectionByProvider(
	context *betterauth.HookContext,
	providerID string,
) (ProviderConnection, error) {
	providerID = strings.ToLower(strings.TrimSpace(providerID))
	if !validIdentifier(providerID, 128) {
		return ProviderConnection{}, betterauth.NewError(
			betterauth.CodeNotFound, "SCIM connection not found.", http.StatusNotFound, nil,
		)
	}
	row, err := context.Database.FindOne(context.Context, betterauth.FindOneQuery{
		Model: ModelSCIMProvider,
		Where: []betterauth.Where{betterauth.Eq("providerId", providerID)},
	})
	if err != nil {
		if errors.Is(err, betterauth.ErrNotFound) {
			return ProviderConnection{}, betterauth.NewError(
				betterauth.CodeNotFound, "SCIM connection not found.", http.StatusNotFound, nil,
			)
		}
		return ProviderConnection{}, internalManagementError(err)
	}
	if row == nil {
		return ProviderConnection{}, betterauth.NewError(
			betterauth.CodeNotFound, "SCIM connection not found.", http.StatusNotFound, nil,
		)
	}
	return providerFromRecord(row)
}

func (instance *runtime) authorizeConnection(
	context *betterauth.HookContext,
	connection ProviderConnection,
) error {
	if context.User == nil {
		return betterauth.NewError(
			betterauth.CodeUnauthorized, "Authentication required.", http.StatusUnauthorized, nil,
		)
	}
	if connection.OrganizationID != "" {
		if instance.config.OrganizationAuthorizer == nil {
			return betterauth.NewError(
				betterauth.CodeForbidden, "You are not allowed to manage this SCIM connection.",
				http.StatusForbidden, nil,
			)
		}
		if err := instance.authorizeOrganization(context, connection.OrganizationID); err != nil {
			return betterauth.NewError(
				betterauth.CodeForbidden, "You are not allowed to manage this SCIM connection.",
				http.StatusForbidden, err,
			)
		}
		return nil
	}
	if connection.UserID != "" && connection.UserID == context.User.ID {
		return nil
	}
	return betterauth.NewError(
		betterauth.CodeNotFound, "SCIM connection not found.", http.StatusNotFound, nil,
	)
}

func (instance *runtime) authorizeOrganization(
	context *betterauth.HookContext,
	organizationID string,
) error {
	if roleAware, ok := instance.config.OrganizationAuthorizer.(OrganizationRoleAuthorizer); ok {
		return roleAware.AuthorizeSCIMConnectionRoles(
			context, organizationID, slices.Clone(instance.config.RequiredRoles),
		)
	}
	return instance.config.OrganizationAuthorizer.AuthorizeSCIMConnection(
		context, organizationID,
	)
}

func providerRecord(connection ProviderConnection, hash string) betterauth.Record {
	return betterauth.Record{
		"id": connection.ID, "providerId": connection.ProviderID, "tokenHash": hash,
		"organizationId": nullableString(connection.OrganizationID),
		"userId":         nullableString(connection.UserID),
		"createdAt":      connection.CreatedAt, "updatedAt": connection.UpdatedAt,
		"lastUsedAt": nullableTime(connection.LastUsedAt), "expiresAt": nullableTime(connection.ExpiresAt),
	}
}

func publicConnection(connection ProviderConnection) map[string]any {
	var organizationID any
	if connection.OrganizationID != "" {
		organizationID = connection.OrganizationID
	}
	return map[string]any{
		"id": connection.ID, "providerId": connection.ProviderID,
		"organizationId": organizationID,
	}
}

func providerFromRecord(row betterauth.Record) (ProviderConnection, error) {
	id, idOK := row["id"].(string)
	providerID, providerOK := row["providerId"].(string)
	createdAt, createdOK := row["createdAt"].(time.Time)
	updatedAt, updatedOK := row["updatedAt"].(time.Time)
	if !idOK || id == "" || !providerOK || providerID == "" ||
		!createdOK || createdAt.IsZero() || !updatedOK || updatedAt.IsZero() {
		return ProviderConnection{}, errors.New("scim: adapter returned invalid provider")
	}
	return ProviderConnection{
		ID: id, ProviderID: providerID, OrganizationID: stringOrEmpty(row["organizationId"]),
		UserID: stringOrEmpty(row["userId"]), CreatedAt: createdAt.UTC(), UpdatedAt: updatedAt.UTC(),
		LastUsedAt: timePtr(row["lastUsedAt"]), ExpiresAt: timePtr(row["expiresAt"]),
	}, nil
}

func internalManagementError(err error) error {
	return betterauth.NewError(
		betterauth.CodeInternal, "The request could not be completed.",
		http.StatusInternalServerError, err,
	)
}
