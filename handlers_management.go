package betterauth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"strings"
	"time"
)

type changePasswordRequest struct {
	CurrentPassword     string `json:"currentPassword"`
	NewPassword         string `json:"newPassword"`
	RevokeOtherSessions bool   `json:"revokeOtherSessions,omitempty"`
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) error {
	if err := s.requireCSRF(r); err != nil {
		return err
	}
	current, user, raw, err := s.sessionFromRequest(r.Context(), r)
	if err != nil {
		return err
	}
	if err := s.requireFreshSession(current); err != nil {
		return err
	}
	var input changePasswordRequest
	if err := s.decodeJSON(w, r, &input); err != nil {
		return err
	}
	if len(input.CurrentPassword) > s.cfg.MaxPasswordBytes {
		return invalidCredentials(nil)
	}
	if err := s.passwordPolicyError(input.NewPassword); err != nil {
		return err
	}
	if err := s.rateLimit(r.Context(), r, "change-password", HashToken(user.ID)); err != nil {
		return err
	}
	credential, err := s.store.PasswordCredential(r.Context(), user.ID)
	if err != nil {
		return invalidCredentials(err)
	}
	verification, err := s.cfg.Passwords.Verify(r.Context(), credential.PasswordHash, input.CurrentPassword)
	if err != nil {
		return publicError(CodeInternal, "Password could not be changed.", http.StatusInternalServerError, err)
	}
	if !verification.Valid {
		return invalidCredentials(nil)
	}
	replacementHash, err := s.cfg.Passwords.Hash(r.Context(), input.NewPassword)
	if err != nil {
		return publicError(CodeInternal, "Password could not be changed.", http.StatusInternalServerError, err)
	}
	replacement, replacementRaw, err := s.newSession(user.ID, s.cfg.SessionDuration)
	if err != nil {
		return err
	}
	replacement.ImpersonatorID = current.ImpersonatorID
	replacement.ImpersonationID = current.ImpersonationID
	replacement, err = s.store.ChangePasswordAndRotate(r.Context(), ChangePasswordParams{
		UserID: user.ID, PreviousHash: credential.PasswordHash, ReplacementHash: replacementHash,
		CurrentTokenHash: HashToken(raw), ReplacementSession: replacement,
		RevokeOtherSessions: input.RevokeOtherSessions,
	})
	if err != nil {
		if errors.Is(err, ErrReplay) {
			return publicError(CodeUnauthorized, "Authentication required.", http.StatusUnauthorized, err)
		}
		return publicError(CodeInternal, "Password could not be changed.", http.StatusInternalServerError, err)
	}
	s.setSessionCookie(w, replacementRaw, replacement.ExpiresAt)
	writeJSON(w, http.StatusOK, map[string]any{"token": nil, "session": replacement, "user": user})
	return nil
}

// SetPassword sets or replaces the credential password for a user. It is a
// trusted server API and is deliberately not exposed as an HTTP endpoint.
func (s *Server) SetPassword(ctx context.Context, userID, password string) error {
	if strings.TrimSpace(userID) == "" {
		return publicError(CodeBadRequest, "Invalid password.", http.StatusBadRequest, nil)
	}
	if err := s.passwordPolicyError(password); err != nil {
		return err
	}
	if _, err := s.store.FindUserByID(ctx, userID); err != nil {
		return err
	}
	hash, err := s.cfg.Passwords.Hash(ctx, password)
	if err != nil {
		return err
	}
	return s.store.SetPasswordHash(ctx, userID, hash, s.cfg.Clock.Now().UTC())
}

// VerifyPassword verifies a credential without creating a session.
func (s *Server) VerifyPassword(ctx context.Context, userID, password string) (bool, error) {
	if strings.TrimSpace(userID) == "" || len(password) > s.cfg.MaxPasswordBytes {
		return false, nil
	}
	credential, err := s.store.PasswordCredential(ctx, userID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return false, nil
		}
		return false, err
	}
	result, err := s.cfg.Passwords.Verify(ctx, credential.PasswordHash, password)
	return result.Valid, err
}

func (s *Server) handleUpdateUser(w http.ResponseWriter, r *http.Request) error {
	if err := s.requireCSRF(r); err != nil {
		return err
	}
	_, user, _, err := s.sessionFromRequest(r.Context(), r)
	if err != nil {
		return err
	}
	var input map[string]any
	if err := s.decodeJSON(w, r, &input); err != nil {
		return err
	}
	fields, err := s.validatedInputFields(ModelUser, input, map[string]bool{
		"email": true,
	})
	if err != nil || len(fields) == 0 {
		return publicError(CodeBadRequest, "Invalid user update.", http.StatusBadRequest, err)
	}
	if value, ok := fields["name"].(string); ok {
		value = strings.TrimSpace(value)
		if value == "" || len(value) > 256 {
			return publicError(CodeBadRequest, "Invalid user update.", http.StatusBadRequest, nil)
		}
		fields["name"] = value
	}
	if value, ok := fields["image"].(string); ok && len(value) > 2048 {
		return publicError(CodeBadRequest, "Invalid user update.", http.StatusBadRequest, nil)
	}
	_, err = s.store.UpdateUser(r.Context(), user.ID, fields, s.cfg.Clock.Now().UTC())
	if err != nil {
		return publicError(CodeInternal, "User could not be updated.", http.StatusInternalServerError, err)
	}
	writeJSON(w, http.StatusOK, map[string]bool{"status": true})
	return nil
}

type changeEmailRequest struct {
	NewEmail    string `json:"newEmail"`
	CallbackURL string `json:"callbackURL,omitempty"`
}

func (s *Server) handleChangeEmail(w http.ResponseWriter, r *http.Request) error {
	if !s.cfg.User.ChangeEmailEnabled {
		return publicError(CodeNotFound, "Endpoint not found.", http.StatusNotFound, nil)
	}
	if err := s.requireCSRF(r); err != nil {
		return err
	}
	session, user, _, err := s.sessionFromRequest(r.Context(), r)
	if err != nil {
		return err
	}
	if err := s.requireFreshSession(session); err != nil {
		return err
	}
	var input changeEmailRequest
	if err := s.decodeJSON(w, r, &input); err != nil {
		return err
	}
	email, err := normalizeEmail(input.NewEmail)
	if err != nil {
		return publicError(CodeBadRequest, "Email could not be changed.", http.StatusBadRequest, err)
	}
	returnTo, err := s.allowedRedirect(input.CallbackURL)
	if err != nil {
		return err
	}
	if email == user.Email {
		writeJSON(w, http.StatusOK, map[string]bool{"status": true})
		return nil
	}
	if err := s.rateLimit(r.Context(), r, "change-email", HashToken(user.ID)); err != nil {
		return err
	}
	if existing, findErr := s.store.FindUserByEmail(r.Context(), email); findErr == nil && existing.ID != user.ID {
		return publicError(CodeConflict, "Email could not be changed.", http.StatusConflict, nil)
	} else if findErr != nil && !errors.Is(findErr, ErrNotFound) {
		return publicError(CodeInternal, "Email could not be changed.", http.StatusInternalServerError, findErr)
	}
	raw, err := s.cfg.Tokens.Token(32)
	if err != nil {
		return err
	}
	id, err := s.newID()
	if err != nil {
		return err
	}
	now := s.cfg.Clock.Now().UTC()
	token := OneTimeToken{
		ID: id, UserID: user.ID, Hash: HashToken(raw), Purpose: PurposeEmailChange,
		ExpiresAt: now.Add(s.cfg.EmailVerificationTTL), CreatedAt: now,
		Metadata: map[string]string{"newEmail": email, "returnTo": returnTo},
	}
	if err := s.store.PutOneTimeToken(r.Context(), token); err != nil {
		return publicError(CodeInternal, "Email could not be changed.", http.StatusInternalServerError, err)
	}
	if err := s.cfg.Mailer.Send(r.Context(), Mail{
		Kind: "email-change", To: email, Token: raw,
		ActionURL: s.actionURL("/verify-email", raw), ExpiresAt: token.ExpiresAt,
	}); err != nil {
		return publicError(CodeInternal, "Email could not be changed.", http.StatusInternalServerError, err)
	}
	writeJSON(w, http.StatusOK, map[string]bool{"status": true})
	return nil
}

type deleteUserRequest struct {
	Password string `json:"password,omitempty"`
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) error {
	if !s.cfg.User.DeleteUserEnabled {
		return publicError(CodeNotFound, "Endpoint not found.", http.StatusNotFound, nil)
	}
	if err := s.requireCSRF(r); err != nil {
		return err
	}
	session, user, _, err := s.sessionFromRequest(r.Context(), r)
	if err != nil {
		return err
	}
	if session.ImpersonatorID != "" {
		return publicError(CodeForbidden, "An impersonated user cannot be deleted.", http.StatusForbidden, nil)
	}
	if err := s.requireFreshSession(session); err != nil {
		return err
	}
	var input deleteUserRequest
	if err := s.decodeOptionalJSON(w, r, &input); err != nil {
		return err
	}
	credential, credentialErr := s.store.PasswordCredential(r.Context(), user.ID)
	if credentialErr == nil {
		if len(input.Password) == 0 || len(input.Password) > s.cfg.MaxPasswordBytes {
			return invalidCredentials(nil)
		}
		verification, err := s.cfg.Passwords.Verify(r.Context(), credential.PasswordHash, input.Password)
		if err != nil {
			return publicError(CodeInternal, "User could not be deleted.", http.StatusInternalServerError, err)
		}
		if !verification.Valid {
			return invalidCredentials(nil)
		}
	} else if !errors.Is(credentialErr, ErrNotFound) {
		return publicError(CodeInternal, "User could not be deleted.", http.StatusInternalServerError, credentialErr)
	}
	if err := s.rateLimit(r.Context(), r, "delete-user", HashToken(user.ID)); err != nil {
		return err
	}
	if err := s.store.DeleteUser(r.Context(), user.ID); err != nil {
		return publicError(CodeInternal, "User could not be deleted.", http.StatusInternalServerError, err)
	}
	s.clearSessionCookie(w)
	writeJSON(w, http.StatusOK, map[string]bool{"success": true})
	return nil
}

func (s *Server) handleListAccounts(w http.ResponseWriter, r *http.Request) error {
	_, user, _, err := s.sessionFromRequest(r.Context(), r)
	if err != nil {
		return err
	}
	accounts, err := s.store.ListAccounts(r.Context(), user.ID)
	if err != nil {
		return publicError(CodeInternal, "Accounts could not be listed.", http.StatusInternalServerError, err)
	}
	writeJSON(w, http.StatusOK, accounts)
	return nil
}

type unlinkAccountRequest struct {
	ProviderID string `json:"providerId"`
	AccountID  string `json:"accountId,omitempty"`
}

func (s *Server) handleUnlinkAccount(w http.ResponseWriter, r *http.Request) error {
	if err := s.requireCSRF(r); err != nil {
		return err
	}
	session, user, _, err := s.sessionFromRequest(r.Context(), r)
	if err != nil {
		return err
	}
	if err := s.requireFreshSession(session); err != nil {
		return err
	}
	var input unlinkAccountRequest
	if err := s.decodeJSON(w, r, &input); err != nil {
		return err
	}
	input.ProviderID = strings.TrimSpace(input.ProviderID)
	input.AccountID = strings.TrimSpace(input.AccountID)
	if !validProviderID(input.ProviderID) || len(input.AccountID) > 512 {
		return publicError(CodeBadRequest, "Invalid account selection.", http.StatusBadRequest, nil)
	}
	err = s.store.UnlinkAccount(
		r.Context(), user.ID, input.ProviderID, input.AccountID, s.cfg.Account.AllowUnlinkingAll,
	)
	if errors.Is(err, ErrNotFound) {
		return publicError(CodeNotFound, "Account not found.", http.StatusNotFound, err)
	}
	if errors.Is(err, ErrConflict) {
		return publicError(CodeConflict, "The final sign-in method cannot be removed.", http.StatusConflict, err)
	}
	if err != nil {
		return publicError(CodeInternal, "Account could not be unlinked.", http.StatusInternalServerError, err)
	}
	writeJSON(w, http.StatusOK, map[string]bool{"success": true})
	return nil
}

type sessionSummary struct {
	ID              string    `json:"id"`
	UserID          string    `json:"userId"`
	ExpiresAt       time.Time `json:"expiresAt"`
	CreatedAt       time.Time `json:"createdAt"`
	UpdatedAt       time.Time `json:"updatedAt"`
	LastSeenAt      time.Time `json:"lastSeenAt"`
	ImpersonatorID  string    `json:"impersonatedBy,omitempty"`
	ImpersonationID string    `json:"impersonationId,omitempty"`
	Current         bool      `json:"current"`
}

func (s *Server) handleListSessions(w http.ResponseWriter, r *http.Request) error {
	current, user, _, err := s.sessionFromRequest(r.Context(), r)
	if err != nil {
		return err
	}
	if err := s.requireFreshSession(current); err != nil {
		return err
	}
	sessions, err := s.store.ListSessions(r.Context(), user.ID, s.cfg.Clock.Now().UTC())
	if err != nil {
		return publicError(CodeInternal, "Sessions could not be listed.", http.StatusInternalServerError, err)
	}
	result := make([]sessionSummary, 0, len(sessions))
	for _, session := range sessions {
		result = append(result, sessionSummary{
			ID: session.ID, UserID: session.UserID, ExpiresAt: session.ExpiresAt,
			CreatedAt: session.CreatedAt, UpdatedAt: session.UpdatedAt, LastSeenAt: session.LastSeenAt,
			ImpersonatorID: session.ImpersonatorID, ImpersonationID: session.ImpersonationID,
			Current: session.ID == current.ID,
		})
	}
	writeJSON(w, http.StatusOK, result)
	return nil
}

type revokeSessionRequest struct {
	SessionID string `json:"sessionId,omitempty"`
}

func (s *Server) handleRevokeSession(w http.ResponseWriter, r *http.Request) error {
	if err := s.requireCSRF(r); err != nil {
		return err
	}
	current, user, _, err := s.sessionFromRequest(r.Context(), r)
	if err != nil {
		return err
	}
	var input revokeSessionRequest
	if err := s.decodeOptionalJSON(w, r, &input); err != nil {
		return err
	}
	input.SessionID = strings.TrimSpace(input.SessionID)
	if len(input.SessionID) > 256 {
		return publicError(CodeBadRequest, "Invalid session selection.", http.StatusBadRequest, nil)
	}
	if input.SessionID == "" {
		input.SessionID = current.ID
	}
	_, err = s.store.RevokeSessionByID(
		r.Context(), user.ID, input.SessionID, s.cfg.Clock.Now().UTC(),
	)
	if err != nil {
		return publicError(CodeInternal, "Session could not be revoked.", http.StatusInternalServerError, err)
	}
	if input.SessionID == current.ID {
		s.clearSessionCookie(w)
	}
	writeJSON(w, http.StatusOK, map[string]bool{"status": true})
	return nil
}

func (s *Server) handleRevokeOtherSessions(w http.ResponseWriter, r *http.Request) error {
	if err := s.requireCSRF(r); err != nil {
		return err
	}
	current, user, _, err := s.sessionFromRequest(r.Context(), r)
	if err != nil {
		return err
	}
	if err := s.store.RevokeOtherSessions(
		r.Context(), user.ID, current.ID, s.cfg.Clock.Now().UTC(),
	); err != nil {
		return publicError(CodeInternal, "Sessions could not be revoked.", http.StatusInternalServerError, err)
	}
	writeJSON(w, http.StatusOK, map[string]bool{"status": true})
	return nil
}

func (s *Server) handleRevokeSessions(w http.ResponseWriter, r *http.Request) error {
	if err := s.requireCSRF(r); err != nil {
		return err
	}
	_, user, _, err := s.sessionFromRequest(r.Context(), r)
	if err != nil {
		return err
	}
	if err := s.store.RevokeUserSessions(r.Context(), user.ID, s.cfg.Clock.Now().UTC()); err != nil {
		return publicError(CodeInternal, "Sessions could not be revoked.", http.StatusInternalServerError, err)
	}
	s.clearSessionCookie(w)
	writeJSON(w, http.StatusOK, map[string]bool{"status": true})
	return nil
}

func (s *Server) handleUpdateSession(w http.ResponseWriter, r *http.Request) error {
	if err := s.requireCSRF(r); err != nil {
		return err
	}
	_, user, raw, err := s.sessionFromRequest(r.Context(), r)
	if err != nil {
		return err
	}
	var input map[string]any
	if err := s.decodeJSON(w, r, &input); err != nil {
		return err
	}
	fields, err := s.validatedInputFields(ModelSession, input, nil)
	if err != nil || len(fields) == 0 {
		return publicError(CodeBadRequest, "Invalid session update.", http.StatusBadRequest, err)
	}
	session, err := s.store.UpdateSession(
		r.Context(), user.ID, HashToken(raw), fields, s.cfg.Clock.Now().UTC(),
	)
	if err != nil {
		return publicError(CodeInternal, "Session could not be updated.", http.StatusInternalServerError, err)
	}
	encoded, err := json.Marshal(session)
	if err != nil {
		return publicError(CodeInternal, "Session could not be updated.", http.StatusInternalServerError, err)
	}
	var publicSession map[string]any
	if err := json.Unmarshal(encoded, &publicSession); err != nil {
		return publicError(CodeInternal, "Session could not be updated.", http.StatusInternalServerError, err)
	}
	definition := s.cfg.Schema[ModelSession]
	for field, value := range fields {
		if definition.Fields[field].Returned {
			publicSession[field] = value
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"session": publicSession})
	return nil
}

func (s *Server) requireFreshSession(session Session) error {
	if s.cfg.Clock.Now().UTC().Sub(session.CreatedAt) > s.cfg.SessionFreshAge {
		return publicError(CodeSessionNotFresh, "Session is not fresh", http.StatusForbidden, nil)
	}
	return nil
}

func (s *Server) decodeOptionalJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxRequestBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return publicError(CodeBadRequest, "Invalid JSON request.", http.StatusBadRequest, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return publicError(CodeBadRequest, "The request must contain one JSON object.", http.StatusBadRequest, err)
	}
	return nil
}

func (s *Server) validatedInputFields(
	model string,
	input map[string]any,
	excluded map[string]bool,
) (Record, error) {
	definition, ok := s.cfg.Schema[model]
	if !ok {
		return nil, errors.New("betterauth: schema model is missing")
	}
	result := make(Record, len(input))
	for field, value := range input {
		fieldDefinition, exists := definition.Fields[field]
		if !exists || !fieldDefinition.Input || excluded[field] {
			return nil, errors.New("betterauth: field is not client-writable")
		}
		normalized, valid := normalizeInputValue(fieldDefinition.Type, value)
		if !valid {
			return nil, errors.New("betterauth: field has the wrong type")
		}
		result[field] = normalized
	}
	return result, nil
}

func normalizeInputValue(fieldType FieldType, value any) (any, bool) {
	if value == nil {
		return nil, true
	}
	switch fieldType {
	case FieldString:
		text, ok := value.(string)
		return text, ok && len(text) <= 16<<10
	case FieldNumber:
		switch number := value.(type) {
		case json.Number:
			parsed, err := number.Float64()
			return parsed, err == nil && !math.IsInf(parsed, 0) && !math.IsNaN(parsed)
		case float64:
			return number, !math.IsInf(number, 0) && !math.IsNaN(number)
		default:
			return nil, false
		}
	case FieldBoolean:
		boolean, ok := value.(bool)
		return boolean, ok
	case FieldDate:
		text, ok := value.(string)
		if !ok {
			return nil, false
		}
		parsed, err := time.Parse(time.RFC3339Nano, text)
		return parsed.UTC(), err == nil
	case FieldJSON:
		return value, true
	case FieldStringArray:
		values, ok := value.([]any)
		if !ok || len(values) > 1024 {
			return nil, false
		}
		result := make([]string, 0, len(values))
		for _, value := range values {
			text, ok := value.(string)
			if !ok || len(text) > 4096 {
				return nil, false
			}
			result = append(result, text)
		}
		return result, true
	default:
		return nil, false
	}
}
