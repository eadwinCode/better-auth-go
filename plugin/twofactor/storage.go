package twofactor

import (
	"context"
	"crypto/subtle"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	betterauth "github.com/eadwinCode/better-auth-go"
)

const (
	verificationPending  = "two_factor_pending"
	verificationAttempts = "two_factor_attempts"
	verificationOTP      = "two_factor_otp"
	verificationTrusted  = "two_factor_trusted_device"
)

func (instance *runtime) findTwoFactor(
	context *betterauth.HookContext,
	userID string,
) (twoFactorRecord, error) {
	row, err := context.Database.FindOne(context.Context, betterauth.FindOneQuery{
		Model: ModelTwoFactor,
		Where: []betterauth.Where{betterauth.Eq("userId", userID)},
	})
	if err != nil || row == nil {
		if err == nil {
			err = betterauth.ErrNotFound
		}
		return twoFactorRecord{}, err
	}
	return twoFactorFromRecord(row)
}

func twoFactorFromRecord(row betterauth.Record) (twoFactorRecord, error) {
	var result twoFactorRecord
	var ok bool
	if result.ID, ok = row["id"].(string); !ok || result.ID == "" {
		return result, errors.New("twofactor: invalid record id")
	}
	if result.UserID, ok = row["userId"].(string); !ok || result.UserID == "" {
		return result, errors.New("twofactor: invalid record user")
	}
	if result.Secret, ok = row["secret"].(string); !ok || result.Secret == "" {
		return result, errors.New("twofactor: invalid encrypted secret")
	}
	if result.BackupCodes, ok = row["backupCodes"].(string); !ok || result.BackupCodes == "" {
		return result, errors.New("twofactor: invalid encrypted backup codes")
	}
	result.Verified, _ = row["verified"].(bool)
	count, err := integerValue(row["failedVerificationCount"])
	if err != nil {
		return result, err
	}
	result.FailedVerificationCount = count
	if value := row["lockedUntil"]; value != nil {
		locked, timeErr := timeValue(value)
		if timeErr != nil {
			return result, timeErr
		}
		result.LockedUntil = &locked
	}
	if result.CreatedAt, err = timeValue(row["createdAt"]); err != nil {
		return result, err
	}
	if result.UpdatedAt, err = timeValue(row["updatedAt"]); err != nil {
		return result, err
	}
	return result, nil
}

func integerValue(value any) (int, error) {
	switch typed := value.(type) {
	case int:
		if typed >= 0 {
			return typed, nil
		}
	case int64:
		if typed >= 0 && typed <= int64(^uint(0)>>1) {
			return int(typed), nil
		}
	case float64:
		if typed >= 0 && typed == float64(int(typed)) {
			return int(typed), nil
		}
	case json.Number:
		parsed, err := strconv.Atoi(string(typed))
		if err == nil && parsed >= 0 {
			return parsed, nil
		}
	}
	return 0, errors.New("twofactor: invalid non-negative integer")
}

func timeValue(value any) (time.Time, error) {
	switch typed := value.(type) {
	case time.Time:
		return typed.UTC(), nil
	case string:
		parsed, err := time.Parse(time.RFC3339Nano, typed)
		return parsed.UTC(), err
	default:
		return time.Time{}, errors.New("twofactor: invalid timestamp")
	}
}

func (instance *runtime) credentialPassword(
	context *betterauth.HookContext,
	userID string,
) (string, bool, error) {
	row, err := context.Database.FindOne(context.Context, betterauth.FindOneQuery{
		Model: betterauth.ModelAccount,
		Where: []betterauth.Where{
			betterauth.Eq("providerId", "credential"),
			betterauth.Eq("accountId", userID),
		},
		Select: []string{"password"},
	})
	if err != nil {
		return "", false, err
	}
	if row == nil {
		return "", false, nil
	}
	password, ok := row["password"].(string)
	if !ok || password == "" {
		return "", false, errors.New("twofactor: invalid credential record")
	}
	return password, true, nil
}

func (instance *runtime) requirePassword(
	context *betterauth.HookContext,
	userID string,
	password string,
) error {
	encoded, exists, err := instance.credentialPassword(context, userID)
	if err != nil {
		return internalError(err)
	}
	if !exists {
		if instance.config.AllowPasswordless {
			return nil
		}
		return invalidPassword(nil)
	}
	if password == "" {
		return invalidPassword(nil)
	}
	verified, err := context.Passwords.Verify(context.Context, encoded, password)
	if err != nil {
		return internalError(err)
	}
	if !verified.Valid {
		return invalidPassword(nil)
	}
	if verified.ReplacementHash != "" {
		_, err = context.Database.Update(context.Context, betterauth.UpdateQuery{
			Model: betterauth.ModelAccount,
			Where: []betterauth.Where{
				betterauth.Eq("providerId", "credential"),
				betterauth.Eq("accountId", userID),
				betterauth.Eq("password", encoded),
			},
			Update: betterauth.Record{
				"password":  verified.ReplacementHash,
				"updatedAt": context.Clock.Now().UTC(),
			},
		})
		if err != nil {
			return internalError(err)
		}
	}
	return nil
}

func (instance *runtime) generateBackupCodes(
	context *betterauth.HookContext,
) ([]string, string, error) {
	codes := make([]string, instance.config.BackupCodeCount)
	for index := range codes {
		raw, err := context.GenerateToken(32)
		if err != nil {
			return nil, "", err
		}
		encoded := base32.StdEncoding.WithPadding(base32.NoPadding).
			EncodeToString([]byte(betterauth.HashToken(raw)))
		encoded = strings.ToLower(encoded)
		if len(encoded) < instance.config.BackupCodeLength {
			return nil, "", errors.New("twofactor: generated backup code is too short")
		}
		value := encoded[:instance.config.BackupCodeLength]
		middle := len(value) / 2
		codes[index] = value[:middle] + "-" + value[middle:]
	}
	plaintext, err := json.Marshal(codes)
	if err != nil {
		return nil, "", err
	}
	sealed, err := instance.config.Cipher.Seal(context.Context, string(plaintext))
	return codes, sealed, err
}

func (instance *runtime) openBackupCodes(
	ctx context.Context,
	encoded string,
) ([]string, error) {
	plaintext, err := instance.config.Cipher.Open(ctx, encoded)
	if err != nil {
		return nil, err
	}
	var codes []string
	if err := json.Unmarshal([]byte(plaintext), &codes); err != nil ||
		len(codes) > 50 {
		return nil, errors.New("twofactor: invalid backup-code record")
	}
	return codes, nil
}

func normalizeBackupCode(value string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(value), "-", ""))
}

func backupCodeIndex(codes []string, candidate string) int {
	normalized := normalizeBackupCode(candidate)
	for index, code := range codes {
		if subtle.ConstantTimeCompare(
			[]byte(normalizeBackupCode(code)), []byte(normalized),
		) == 1 {
			return index
		}
	}
	return -1
}

func verificationValue(prefix, raw string) string {
	return betterauth.HashToken(prefix + ":" + raw)
}

func metadataValue(value verificationMetadata) (any, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var normalized any
	if err := json.Unmarshal(raw, &normalized); err != nil {
		return nil, err
	}
	return normalized, nil
}

func parseMetadata(row betterauth.Record) (verificationMetadata, error) {
	raw, err := json.Marshal(row["metadata"])
	if err != nil {
		return verificationMetadata{}, err
	}
	var result verificationMetadata
	if err := json.Unmarshal(raw, &result); err != nil {
		return result, err
	}
	return result, nil
}

func (instance *runtime) createVerification(
	context *betterauth.HookContext,
	database betterauth.DatabaseAdapter,
	identifier string,
	value string,
	expiresAt time.Time,
	metadata verificationMetadata,
) error {
	id, err := context.GenerateID()
	if err != nil {
		return err
	}
	normalized, err := metadataValue(metadata)
	if err != nil {
		return err
	}
	_, err = database.Create(context.Context, betterauth.CreateQuery{
		Model: betterauth.ModelVerification,
		Data: betterauth.Record{
			"id": id, "identifier": identifier, "value": value,
			"expiresAt": expiresAt.UTC(), "createdAt": context.Clock.Now().UTC(),
			"metadata": normalized,
		},
		ForceAllowID: true,
	})
	return err
}

func consumeVerification(
	context *betterauth.HookContext,
	identifier string,
	value string,
) (betterauth.Record, error) {
	row, err := context.Database.ConsumeOne(context.Context, betterauth.DeleteQuery{
		Model: betterauth.ModelVerification,
		Where: []betterauth.Where{
			betterauth.Eq("identifier", identifier),
			betterauth.Eq("value", value),
			{Field: "expiresAt", Operator: betterauth.WhereGT, Value: context.Clock.Now().UTC()},
		},
	})
	if err != nil || row == nil {
		if err == nil {
			err = betterauth.ErrNotFound
		}
		return nil, err
	}
	return row, nil
}

func findVerification(
	context *betterauth.HookContext,
	identifier string,
	value string,
) (betterauth.Record, error) {
	row, err := context.Database.FindOne(context.Context, betterauth.FindOneQuery{
		Model: betterauth.ModelVerification,
		Where: []betterauth.Where{
			betterauth.Eq("identifier", identifier),
			betterauth.Eq("value", value),
			{Field: "expiresAt", Operator: betterauth.WhereGT, Value: context.Clock.Now().UTC()},
		},
	})
	if err != nil || row == nil {
		if err == nil {
			err = betterauth.ErrNotFound
		}
		return nil, err
	}
	return row, nil
}

func (instance *runtime) beginAttempt(
	context *betterauth.HookContext,
	handle string,
) (verificationMetadata, time.Time, error) {
	value := verificationValue("attempt", handle)
	row, err := consumeVerification(context, verificationAttempts, value)
	if err != nil {
		return verificationMetadata{}, time.Time{}, err
	}
	metadata, err := parseMetadata(row)
	if err != nil || metadata.Attempts >= instance.config.ChallengeMaxAttempts {
		_, _ = context.Database.ConsumeOne(context.Context, betterauth.DeleteQuery{
			Model: betterauth.ModelVerification,
			Where: []betterauth.Where{
				betterauth.Eq("identifier", verificationPending),
				betterauth.Eq("value", verificationValue("pending", handle)),
			},
		})
		return metadata, time.Time{}, betterauth.ErrReplay
	}
	expires, err := timeValue(row["expiresAt"])
	return metadata, expires, err
}

func (instance *runtime) rearmAttempt(
	context *betterauth.HookContext,
	handle string,
	metadata verificationMetadata,
	expires time.Time,
) {
	_ = instance.createVerification(
		context, context.Database, verificationAttempts,
		verificationValue("attempt", handle), expires, metadata,
	)
}

func cookieValue(request *http.Request, name string) (string, error) {
	if request == nil || name == "" {
		return "", betterauth.ErrNotFound
	}
	cookie, err := request.Cookie(name)
	if err != nil || cookie.Value == "" || len(cookie.Value) > 1024 {
		return "", betterauth.ErrNotFound
	}
	return cookie.Value, nil
}

func removeResponseCookie(response *betterauth.PluginResponse, name string) (string, error) {
	if response == nil || response.Headers == nil {
		return "", betterauth.ErrNotFound
	}
	values := response.Headers.Values("Set-Cookie")
	response.Headers.Del("Set-Cookie")
	var found string
	for _, value := range values {
		cookie, err := http.ParseSetCookie(value)
		if err != nil {
			return "", err
		}
		if cookie.Name == name {
			found = cookie.Value
			continue
		}
		response.Headers.Add("Set-Cookie", value)
	}
	if found == "" {
		return "", betterauth.ErrNotFound
	}
	return found, nil
}

func (instance *runtime) setPluginCookie(
	context *betterauth.HookContext,
	response *betterauth.PluginResponse,
	name string,
	value string,
	expires time.Time,
) error {
	return response.SetCookie(&http.Cookie{
		Name: name, Value: value, Path: "/", Expires: expires.UTC(),
		MaxAge: int(expires.Sub(context.Clock.Now().UTC()).Seconds()),
		Secure: true, HttpOnly: true, SameSite: context.Cookies.SameSite,
	})
}

func (instance *runtime) clearPluginCookie(
	context *betterauth.HookContext,
	response *betterauth.PluginResponse,
	name string,
) error {
	return response.SetCookie(&http.Cookie{
		Name: name, Value: "", Path: "/", Expires: time.Unix(1, 0), MaxAge: -1,
		Secure: true, HttpOnly: true, SameSite: context.Cookies.SameSite,
	})
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
		"requestId": trimBounded(request.Header.Get("X-Request-ID"), 128),
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

func (instance *runtime) audit(
	context *betterauth.HookContext,
	database betterauth.DatabaseAdapter,
	action string,
	userID string,
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
	_, err = database.Create(context.Context, betterauth.CreateQuery{
		Model: betterauth.ModelAuditEvent,
		Data: betterauth.Record{
			"id": id, "schemaVersion": float64(1), "action": action,
			"actorUserId": userID, "subjectUserId": userID,
			"sessionId": sessionID, "occurredAt": context.Clock.Now().UTC(),
			"request": requestDetails(context.Request), "details": details,
		},
		ForceAllowID: true,
	})
	return err
}

func internalError(cause error) error {
	if cause == nil {
		cause = errors.New("twofactor: unexpected empty result")
	}
	return betterauth.NewError(
		betterauth.CodeInternal, "The request could not be completed.",
		http.StatusInternalServerError, cause,
	)
}

func invalidPassword(cause error) error {
	return betterauth.NewError(
		betterauth.CodeBadRequest, "Invalid password.", http.StatusBadRequest, cause,
	)
}

func invalidFactor(cause error) error {
	return betterauth.NewError(
		betterauth.CodeUnauthorized, "Invalid two-factor code.",
		http.StatusUnauthorized, cause,
	)
}

func invalidChallenge(cause error) error {
	return betterauth.NewError(
		betterauth.CodeUnauthorized, "Invalid two-factor challenge.",
		http.StatusUnauthorized, cause,
	)
}

func tooManyAttempts(cause error) error {
	return betterauth.NewError(
		betterauth.CodeRateLimited, "Too many verification attempts.",
		http.StatusTooManyRequests, cause,
	)
}

func recordString(value any) string {
	text, _ := value.(string)
	return text
}

func boolBody(context *betterauth.HookContext, field string) bool {
	body, _ := context.Body.(map[string]any)
	value, _ := body[field].(bool)
	return value
}

func stringBody(context *betterauth.HookContext, field string) string {
	body, _ := context.Body.(map[string]any)
	value, _ := body[field].(string)
	return strings.TrimSpace(value)
}

func conflictError(message string, cause error) error {
	return betterauth.NewError(
		betterauth.CodeConflict, message, http.StatusConflict, cause,
	)
}

func formatFactor(factor string) map[string]any {
	return map[string]any{"factor": fmt.Sprint(factor)}
}
