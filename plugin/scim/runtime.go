package scim

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	betterauth "github.com/eadwinCode/better-auth-go"
)

type authenticatedConnection struct {
	Connection ProviderConnection
	TokenHash  string
}

func (instance *runtime) authenticateBearer(
	hook *betterauth.HookContext,
) (*betterauth.PluginResponse, error) {
	if unsafeSCIMMethod(hook.Request.Method) {
		contentType := strings.ToLower(strings.TrimSpace(
			strings.Split(hook.Headers.Get("Content-Type"), ";")[0],
		))
		if contentType != "application/json" && contentType != "application/scim+json" {
			return scimError(http.StatusUnsupportedMediaType, "", "Unsupported media type.")
		}
	}
	authorization := strings.TrimSpace(hook.Headers.Get("Authorization"))
	scheme, raw, ok := strings.Cut(authorization, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return scimError(http.StatusUnauthorized, "", "Authentication failed.")
	}
	claims, err := parseBearerToken(raw, instance.config.MaxBearerBytes)
	if err != nil {
		return scimError(http.StatusUnauthorized, "", "Authentication failed.")
	}
	row, err := hook.Database.FindOne(hook.Context, betterauth.FindOneQuery{
		Model: ModelSCIMProvider,
		Where: []betterauth.Where{
			betterauth.Eq("providerId", claims.ProviderID),
			betterauth.Eq("organizationId", nullableString(claims.OrganizationID)),
		},
	})
	var connection ProviderConnection
	var storedHash string
	if err == nil && row != nil {
		connection, err = providerFromRecord(row)
		storedHash, _ = row["tokenHash"].(string)
	} else if row == nil && (err == nil || errors.Is(err, betterauth.ErrNotFound)) {
		connection, storedHash, err = instance.defaultConnection(claims)
	}
	now := hook.Clock.Now().UTC()
	comparisonHash := storedHash
	if comparisonHash == "" {
		comparisonHash = betterauth.HashToken("scim-invalid-bearer-comparison")
	}
	hashValid := tokenHashMatches(comparisonHash, claims.TokenHash)
	if err != nil || storedHash == "" || !hashValid ||
		(connection.ExpiresAt != nil && !connection.ExpiresAt.After(now)) {
		return scimError(http.StatusUnauthorized, "", "Authentication failed.")
	}
	if row != nil {
		if _, err = hook.Database.Update(hook.Context, betterauth.UpdateQuery{
			Model: ModelSCIMProvider,
			Where: []betterauth.Where{
				betterauth.Eq("id", connection.ID), betterauth.Eq("tokenHash", storedHash),
			},
			Update: betterauth.Record{"lastUsedAt": now, "updatedAt": now},
		}); err != nil {
			return scimError(http.StatusInternalServerError, "", "The request could not be completed.")
		}
		connection.LastUsedAt = &now
		connection.UpdatedAt = now
	}
	hook.Context = context.WithValue(
		hook.Context, scimContextKey{},
		authenticatedConnection{Connection: connection, TokenHash: storedHash},
	)
	return nil, nil
}

func (instance *runtime) defaultConnection(
	claims bearerClaims,
) (ProviderConnection, string, error) {
	for _, configured := range instance.config.DefaultConnections {
		if configured.ProviderID != claims.ProviderID ||
			configured.OrganizationID != claims.OrganizationID {
			continue
		}
		return ProviderConnection{
			ID:         "default:" + configured.ProviderID,
			ProviderID: configured.ProviderID, OrganizationID: configured.OrganizationID,
			UserID: configured.UserID, CreatedAt: time.Unix(0, 0).UTC(),
			UpdatedAt: time.Unix(0, 0).UTC(), ExpiresAt: configured.ExpiresAt,
		}, configured.TokenHash, nil
	}
	return ProviderConnection{}, "", betterauth.ErrNotFound
}

func connectionFromContext(hook *betterauth.HookContext) (ProviderConnection, error) {
	value, ok := hook.Context.Value(scimContextKey{}).(authenticatedConnection)
	if !ok {
		return ProviderConnection{}, errors.New("scim: authenticated connection is missing")
	}
	return value.Connection, nil
}

func (instance *runtime) scimResponseHook(
	hook *betterauth.HookContext,
	response *betterauth.PluginResponse,
) error {
	if !strings.HasPrefix(hook.Path, "/scim/v2/") || response == nil {
		return nil
	}
	response.Headers.Set("Content-Type", "application/scim+json; charset=utf-8")
	response.Headers.Set("Cache-Control", "no-store")
	if response.Status < 400 {
		return nil
	}
	var existing SCIMError
	if json.Unmarshal(response.Body, &existing) == nil &&
		containsFold(existing.Schemas, SchemaError) {
		return nil
	}
	detail := "The request could not be completed."
	scimType := ""
	switch response.Status {
	case http.StatusBadRequest:
		detail = "Invalid request."
	case http.StatusUnauthorized:
		detail = "Authentication failed."
	case http.StatusForbidden:
		detail = "Forbidden."
	case http.StatusNotFound:
		detail = "Resource not found."
	case http.StatusConflict:
		detail, scimType = "Resource already exists.", "uniqueness"
	case http.StatusRequestEntityTooLarge:
		detail = "Request body is too large."
	case http.StatusUnsupportedMediaType:
		detail = "Unsupported media type."
	}
	encoded, err := scimError(response.Status, scimType, detail)
	if err != nil {
		return err
	}
	response.Body = encoded.Body
	response.Headers = encoded.Headers
	return nil
}

func writeAudit(
	hook *betterauth.HookContext,
	db betterauth.DatabaseAdapter,
	action, actorUserID, subjectUserID string,
	details map[string]string,
) error {
	id, err := hook.GenerateID()
	if err != nil {
		return err
	}
	sessionID := ""
	if hook.Session != nil {
		sessionID = hook.Session.ID
	}
	_, err = db.Create(hook.Context, betterauth.CreateQuery{
		Model: betterauth.ModelAuditEvent, ForceAllowID: true,
		Data: betterauth.Record{
			"id": id, "schemaVersion": 1, "action": action,
			"actorUserId": actorUserID, "subjectUserId": subjectUserID,
			"sessionId": sessionID, "occurredAt": hook.Clock.Now().UTC(),
			"request": map[string]string{
				"requestId": hook.Headers.Get("X-Request-ID"),
				"userAgent": truncate(hook.Headers.Get("User-Agent"), 512),
			},
			"details": cloneStrings(details),
		},
	})
	return err
}

func decodeUserInput(value any) (UserInput, error) {
	var result UserInput
	if err := remarshal(value, &result); err != nil {
		return result, errors.New("invalid SCIM User")
	}
	return result, nil
}

func decodePatchRequest(value any) (PatchRequest, error) {
	var result PatchRequest
	if err := remarshal(value, &result); err != nil {
		return result, errors.New("invalid SCIM PatchOp")
	}
	return result, nil
}

func remarshal(value, destination any) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(strings.NewReader(string(encoded)))
	decoder.DisallowUnknownFields()
	return decoder.Decode(destination)
}

func unsafeSCIMMethod(method string) bool {
	return method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch
}

func stringOrEmpty(value any) string {
	result, _ := value.(string)
	return result
}

func boolOr(value any, fallback bool) bool {
	result, ok := value.(bool)
	if !ok {
		return fallback
	}
	return result
}

func recordTimeOr(value any, fallback time.Time) time.Time {
	result, ok := value.(time.Time)
	if !ok || result.IsZero() {
		return fallback
	}
	return result.UTC()
}

func timePtr(value any) *time.Time {
	result, ok := value.(time.Time)
	if !ok || result.IsZero() {
		return nil
	}
	result = result.UTC()
	return &result
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func nullableTime(value *time.Time) any {
	if value == nil {
		return nil
	}
	return value.UTC()
}

func cloneStrings(value map[string]string) map[string]string {
	result := make(map[string]string, len(value))
	for key, item := range value {
		result[key] = item
	}
	return result
}

func truncate(value string, maximum int) string {
	if len(value) <= maximum {
		return value
	}
	return value[:maximum]
}

func protocolActor(connection ProviderConnection) string {
	if connection.UserID != "" {
		return connection.UserID
	}
	return fmt.Sprintf("scim:%s", connection.ProviderID)
}
