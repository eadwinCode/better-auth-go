package organization

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	betterauth "github.com/eadwinCode/better-auth-go"
)

func organizationFromRecord(row betterauth.Record) (Organization, error) {
	var value Organization
	var err error
	if value.ID, err = requiredString(row, "id"); err != nil {
		return value, err
	}
	if value.Name, err = requiredString(row, "name"); err != nil {
		return value, err
	}
	if value.Slug, err = requiredString(row, "slug"); err != nil {
		return value, err
	}
	value.Logo, _ = row["logo"].(string)
	if row["metadata"] != nil {
		value.Metadata, err = permissionlessObject(row["metadata"])
		if err != nil {
			return value, fmt.Errorf("organization: invalid metadata: %w", err)
		}
	}
	if value.CreatedAt, err = recordTime(row["createdAt"]); err != nil {
		return value, err
	}
	if value.UpdatedAt, err = recordTime(row["updatedAt"]); err != nil {
		return value, err
	}
	return value, nil
}

func memberFromRecord(row betterauth.Record) (Member, error) {
	var value Member
	var err error
	if value.ID, err = requiredString(row, "id"); err != nil {
		return value, err
	}
	if value.OrganizationID, err = requiredString(row, "organizationId"); err != nil {
		return value, err
	}
	if value.UserID, err = requiredString(row, "userId"); err != nil {
		return value, err
	}
	if value.Role, err = requiredString(row, "role"); err != nil {
		return value, err
	}
	if value.CreatedAt, err = recordTime(row["createdAt"]); err != nil {
		return value, err
	}
	if value.UpdatedAt, err = recordTime(row["updatedAt"]); err != nil {
		return value, err
	}
	return value, nil
}

func invitationFromRecord(row betterauth.Record) (Invitation, error) {
	var value Invitation
	var err error
	if value.ID, err = requiredString(row, "id"); err != nil {
		return value, err
	}
	if value.OrganizationID, err = requiredString(row, "organizationId"); err != nil {
		return value, err
	}
	if value.Email, err = requiredString(row, "email"); err != nil {
		return value, err
	}
	if value.Role, err = requiredString(row, "role"); err != nil {
		return value, err
	}
	value.TeamID, _ = row["teamId"].(string)
	if value.Status, err = requiredString(row, "status"); err != nil {
		return value, err
	}
	if value.InviterID, err = requiredString(row, "inviterId"); err != nil {
		return value, err
	}
	if value.ExpiresAt, err = recordTime(row["expiresAt"]); err != nil {
		return value, err
	}
	if value.CreatedAt, err = recordTime(row["createdAt"]); err != nil {
		return value, err
	}
	if value.UpdatedAt, err = recordTime(row["updatedAt"]); err != nil {
		return value, err
	}
	return value, nil
}

func teamFromRecord(row betterauth.Record) (Team, error) {
	var value Team
	var err error
	if value.ID, err = requiredString(row, "id"); err != nil {
		return value, err
	}
	if value.OrganizationID, err = requiredString(row, "organizationId"); err != nil {
		return value, err
	}
	if value.Name, err = requiredString(row, "name"); err != nil {
		return value, err
	}
	if value.CreatedAt, err = recordTime(row["createdAt"]); err != nil {
		return value, err
	}
	if value.UpdatedAt, err = recordTime(row["updatedAt"]); err != nil {
		return value, err
	}
	return value, nil
}

func teamMemberFromRecord(row betterauth.Record) (TeamMember, error) {
	var value TeamMember
	var err error
	if value.ID, err = requiredString(row, "id"); err != nil {
		return value, err
	}
	if value.TeamID, err = requiredString(row, "teamId"); err != nil {
		return value, err
	}
	if value.UserID, err = requiredString(row, "userId"); err != nil {
		return value, err
	}
	if value.CreatedAt, err = recordTime(row["createdAt"]); err != nil {
		return value, err
	}
	return value, nil
}

func roleFromRecord(row betterauth.Record) (OrganizationRole, error) {
	var value OrganizationRole
	var err error
	if value.ID, err = requiredString(row, "id"); err != nil {
		return value, err
	}
	if value.OrganizationID, err = requiredString(row, "organizationId"); err != nil {
		return value, err
	}
	if value.Role, err = requiredString(row, "role"); err != nil {
		return value, err
	}
	if value.Permission, err = permissionFromValue(row["permission"]); err != nil {
		return value, err
	}
	if value.CreatedAt, err = recordTime(row["createdAt"]); err != nil {
		return value, err
	}
	if value.UpdatedAt, err = recordTime(row["updatedAt"]); err != nil {
		return value, err
	}
	return value, nil
}

func requiredString(row betterauth.Record, field string) (string, error) {
	value, ok := row[field].(string)
	value = strings.TrimSpace(value)
	if !ok || value == "" {
		return "", fmt.Errorf("organization: invalid %s record field", field)
	}
	return value, nil
}

func recordTime(value any) (time.Time, error) {
	switch typed := value.(type) {
	case time.Time:
		return typed.UTC(), nil
	case string:
		parsed, err := time.Parse(time.RFC3339Nano, typed)
		return parsed.UTC(), err
	default:
		return time.Time{}, errors.New("organization: invalid timestamp")
	}
}

func permissionlessObject(value any) (map[string]any, error) {
	switch typed := value.(type) {
	case map[string]any:
		result := make(map[string]any, len(typed))
		for key, item := range typed {
			result[key] = item
		}
		return result, nil
	case string:
		var result map[string]any
		if err := json.Unmarshal([]byte(typed), &result); err != nil {
			return nil, err
		}
		return result, nil
	default:
		encoded, err := json.Marshal(value)
		if err != nil {
			return nil, err
		}
		var result map[string]any
		err = json.Unmarshal(encoded, &result)
		return result, err
	}
}

func permissionFromValue(value any) (Permission, error) {
	encoded, err := json.Marshal(value)
	if text, ok := value.(string); ok {
		encoded = []byte(text)
	}
	if err != nil {
		return nil, err
	}
	var result Permission
	if err := json.Unmarshal(encoded, &result); err != nil {
		return nil, errors.New("organization: invalid permission record")
	}
	return result, nil
}

func rowsToMembers(rows []betterauth.Record) ([]Member, error) {
	result := make([]Member, len(rows))
	for index := range rows {
		value, err := memberFromRecord(rows[index])
		if err != nil {
			return nil, err
		}
		result[index] = value
	}
	return result, nil
}

func rowsToInvitations(rows []betterauth.Record) ([]Invitation, error) {
	result := make([]Invitation, len(rows))
	for index := range rows {
		value, err := invitationFromRecord(rows[index])
		if err != nil {
			return nil, err
		}
		result[index] = value
	}
	return result, nil
}

func rowsToTeams(rows []betterauth.Record) ([]Team, error) {
	result := make([]Team, len(rows))
	for index := range rows {
		value, err := teamFromRecord(rows[index])
		if err != nil {
			return nil, err
		}
		result[index] = value
	}
	return result, nil
}

func (instance *runtime) member(
	context *betterauth.HookContext,
	database betterauth.DatabaseAdapter,
	organizationID, userID string,
) (Member, error) {
	row, err := database.FindOne(context.Context, betterauth.FindOneQuery{
		Model: ModelMember,
		Where: []betterauth.Where{
			betterauth.Eq("organizationId", organizationID),
			betterauth.Eq("userId", userID),
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

func (instance *runtime) permission(
	context *betterauth.HookContext,
	database betterauth.DatabaseAdapter,
	organizationID, roles, resource, action string,
) (bool, error) {
	if instance.staticPermission(roles, resource, action) {
		return true, nil
	}
	for _, name := range strings.Split(roles, ",") {
		row, err := database.FindOne(context.Context, betterauth.FindOneQuery{
			Model: ModelOrganizationRole,
			Where: []betterauth.Where{
				betterauth.Eq("organizationId", organizationID),
				betterauth.Eq("role", name),
			},
		})
		if err != nil && !errors.Is(err, betterauth.ErrNotFound) {
			return false, err
		}
		if row == nil {
			continue
		}
		role, err := roleFromRecord(row)
		if err != nil {
			return false, err
		}
		if slices.Contains(role.Permission[resource], action) {
			return true, nil
		}
	}
	return false, nil
}

func (instance *runtime) authorize(
	context *betterauth.HookContext,
	database betterauth.DatabaseAdapter,
	organizationID, resource, action string,
) (Member, error) {
	member, err := instance.member(context, database, organizationID, context.User.ID)
	if err != nil {
		return Member{}, forbidden(err)
	}
	allowed, err := instance.permission(
		context, database, organizationID, member.Role, resource, action,
	)
	if err != nil {
		return Member{}, internalError(err)
	}
	if !allowed {
		return Member{}, forbidden(nil)
	}
	return member, nil
}

func (instance *runtime) activeOrganizationID(
	context *betterauth.HookContext,
) (string, error) {
	row, err := context.Database.FindOne(context.Context, betterauth.FindOneQuery{
		Model: betterauth.ModelSession,
		Where: []betterauth.Where{
			betterauth.Eq("id", context.Session.ID),
			betterauth.Eq("userId", context.User.ID),
		},
		Select: []string{"activeOrganizationId"},
	})
	if err != nil || row == nil {
		if err == nil {
			err = betterauth.ErrNotFound
		}
		return "", err
	}
	value, _ := row["activeOrganizationId"].(string)
	return strings.TrimSpace(value), nil
}

func (instance *runtime) selectedOrganizationID(
	context *betterauth.HookContext,
) (string, error) {
	value := bodyString(context, "organizationId")
	if value == "" {
		value = strings.TrimSpace(context.Query.Get("organizationId"))
	}
	if value == "" {
		var err error
		value, err = instance.activeOrganizationID(context)
		if err != nil {
			return "", internalError(err)
		}
	}
	if value == "" || len(value) > 512 {
		return "", badRequest("An organization must be selected.", nil)
	}
	return value, nil
}

func (instance *runtime) audit(
	context *betterauth.HookContext,
	database betterauth.DatabaseAdapter,
	action, subjectID, organizationID string,
	details map[string]any,
) error {
	id, err := context.GenerateID()
	if err != nil {
		return err
	}
	sessionID := ""
	if context.Session != nil {
		sessionID = context.Session.ID
	}
	if details == nil {
		details = map[string]any{}
	}
	details["organizationId"] = organizationID
	_, err = database.Create(context.Context, betterauth.CreateQuery{
		Model: betterauth.ModelAuditEvent,
		Data: betterauth.Record{
			"id": id, "schemaVersion": float64(1), "action": action,
			"actorUserId": context.User.ID, "subjectUserId": subjectID,
			"sessionId": sessionID, "occurredAt": context.Clock.Now().UTC(),
			"request": requestDetails(context.Request), "details": details,
		},
		ForceAllowID: true,
	})
	return err
}

func requestDetails(request *http.Request) map[string]any {
	if request == nil {
		return map[string]any{}
	}
	ip := request.RemoteAddr
	if host, _, err := net.SplitHostPort(request.RemoteAddr); err == nil {
		ip = host
	}
	return map[string]any{
		"ip":        trimBounded(ip, 128),
		"userAgent": trimBounded(request.UserAgent(), 512),
	}
}

func trimBounded(value string, maximum int) string {
	value = strings.TrimSpace(value)
	if len(value) > maximum {
		return value[:maximum]
	}
	return value
}

func body(context *betterauth.HookContext) map[string]any {
	value, _ := context.Body.(map[string]any)
	return value
}

func bodyString(context *betterauth.HookContext, key string) string {
	value, _ := body(context)[key].(string)
	return strings.TrimSpace(value)
}

func bodyObject(context *betterauth.HookContext, key string) map[string]any {
	value, _ := body(context)[key].(map[string]any)
	return value
}

func queryPage(
	context *betterauth.HookContext,
	maximum int,
) (limit, offset int, err error) {
	if maximum < 1 {
		return 0, 0, errors.New("organization: invalid pagination maximum")
	}
	limit = maximum
	if limit > 100 {
		limit = 100
	}
	if value := strings.TrimSpace(context.Query.Get("limit")); value != "" {
		limit, err = strconv.Atoi(value)
		if err != nil || limit < 1 || limit > maximum || limit > 1000 {
			return 0, 0, badRequest("The pagination limit is invalid.", err)
		}
	}
	if value := strings.TrimSpace(context.Query.Get("offset")); value != "" {
		offset, err = strconv.Atoi(value)
		if err != nil || offset < 0 || offset > 1_000_000 {
			return 0, 0, badRequest("The pagination offset is invalid.", err)
		}
	}
	return limit, offset, nil
}

func findManyBounded(
	context *betterauth.HookContext,
	database betterauth.DatabaseAdapter,
	model string,
	where []betterauth.Where,
	maximum int,
) ([]betterauth.Record, error) {
	if maximum < 1 {
		return nil, errors.New("organization: invalid storage bound")
	}
	result := make([]betterauth.Record, 0)
	for offset := 0; offset < maximum; {
		limit := maximum - offset
		if limit > 1000 {
			limit = 1000
		}
		rows, err := database.FindMany(context.Context, betterauth.FindManyQuery{
			Model: model, Where: where, Limit: limit, Offset: offset,
		})
		if err != nil {
			return nil, err
		}
		result = append(result, rows...)
		if len(rows) < limit {
			break
		}
		offset += len(rows)
	}
	return result, nil
}

func adapterPageLimit(maximum int) int {
	if maximum > 1000 {
		return 1000
	}
	return maximum
}

func internalError(cause error) error {
	if cause == nil {
		cause = errors.New("organization: unexpected empty result")
	}
	return betterauth.NewError(
		betterauth.CodeInternal, "The request could not be completed.",
		http.StatusInternalServerError, cause,
	)
}

func badRequest(message string, cause error) error {
	return betterauth.NewError(betterauth.CodeBadRequest, message, http.StatusBadRequest, cause)
}

func forbidden(cause error) error {
	return betterauth.NewError(
		betterauth.CodeForbidden, "You do not have permission to perform this action.",
		http.StatusForbidden, cause,
	)
}

func notFound(cause error) error {
	return betterauth.NewError(
		betterauth.CodeNotFound, "Organization resource not found.",
		http.StatusNotFound, cause,
	)
}

func conflict(message string, cause error) error {
	return betterauth.NewError(betterauth.CodeConflict, message, http.StatusConflict, cause)
}
