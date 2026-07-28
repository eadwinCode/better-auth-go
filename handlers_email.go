package betterauth

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"
)

type signUpRequest struct {
	Email       string `json:"email"`
	Password    string `json:"password"`
	Name        string `json:"name"`
	Image       string `json:"image,omitempty"`
	CallbackURL string `json:"callbackURL,omitempty"`
}

func (s *Server) handleSignUp(w http.ResponseWriter, r *http.Request) error {
	var input signUpRequest
	if err := s.decodeJSON(w, r, &input); err != nil {
		return err
	}
	email, err := normalizeEmail(input.Email)
	if err != nil || len(input.Password) < s.cfg.MinPasswordBytes || len(input.Password) > s.cfg.MaxPasswordBytes {
		return publicError(CodeBadRequest, "Invalid account details.", http.StatusBadRequest, err)
	}
	if len(strings.TrimSpace(input.Name)) == 0 || len(input.Name) > 256 || len(input.Image) > 2048 {
		return publicError(CodeBadRequest, "Invalid account details.", http.StatusBadRequest, nil)
	}
	if err := s.rateLimit(r.Context(), r, "sign-up/email", HashToken(email)); err != nil {
		return err
	}
	passwordHash, err := s.cfg.Passwords.Hash(r.Context(), input.Password)
	if err != nil {
		return publicError(CodeInternal, "The account could not be created.", http.StatusInternalServerError, err)
	}
	userID, err := s.newID()
	if err != nil {
		return err
	}
	session, rawSession, err := s.newSession(userID, s.cfg.SessionDuration)
	if err != nil {
		return err
	}
	eventID, err := s.newID()
	if err != nil {
		return err
	}
	now := s.cfg.Clock.Now().UTC()
	user := User{
		ID: userID, Email: email, Name: strings.TrimSpace(input.Name), ImageURL: strings.TrimSpace(input.Image),
		EmailVerified: false, CreatedAt: now, UpdatedAt: now,
	}
	created, err := s.store.CreateEmailUser(r.Context(), CreateEmailUserParams{
		User: user, PasswordHash: passwordHash, Session: session,
		Event: DomainEvent{
			ID: eventID, SchemaVersion: 1, Name: EventUserCreated, AggregateID: userID,
			OccurredAt: now, Payload: map[string]string{"userId": userID, "email": email},
		},
	})
	if err != nil {
		if errors.Is(err, ErrConflict) {
			return publicError(CodeConflict, "The account could not be created.", http.StatusConflict, err)
		}
		return publicError(CodeInternal, "The account could not be created.", http.StatusInternalServerError, err)
	}
	s.revokePreviousBrowserSession(r.Context(), r, rawSession)
	s.setSessionCookie(w, rawSession, session.ExpiresAt)
	if err := s.ensureCSRFCookie(w, r); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"token": nil, "user": created})
	return nil
}

type signInRequest struct {
	Email      string `json:"email"`
	Password   string `json:"password"`
	RememberMe *bool  `json:"rememberMe,omitempty"`
}

func (s *Server) handleSignIn(w http.ResponseWriter, r *http.Request) error {
	var input signInRequest
	if err := s.decodeJSON(w, r, &input); err != nil {
		return err
	}
	email, err := normalizeEmail(input.Email)
	if err != nil || len(input.Password) > s.cfg.MaxPasswordBytes {
		return invalidCredentials(err)
	}
	if err := s.rateLimit(r.Context(), r, "sign-in/email", HashToken(email)); err != nil {
		return err
	}
	user, err := s.store.FindUserByEmail(r.Context(), email)
	if err != nil || user.DisabledAt != nil {
		return invalidCredentials(err)
	}
	credential, err := s.store.PasswordCredential(r.Context(), user.ID)
	if err != nil {
		return invalidCredentials(err)
	}
	verification, err := s.cfg.Passwords.Verify(r.Context(), credential.PasswordHash, input.Password)
	if err != nil {
		return publicError(CodeInternal, "Sign in could not be completed.", http.StatusInternalServerError, err)
	}
	if !verification.Valid {
		return invalidCredentials(nil)
	}
	if verification.ReplacementHash != "" {
		if err := s.store.ReplacePasswordHash(
			r.Context(), user.ID, credential.PasswordHash, verification.ReplacementHash, s.cfg.Clock.Now(),
		); err != nil && !errors.Is(err, ErrNotFound) {
			return publicError(CodeInternal, "Sign in could not be completed.", http.StatusInternalServerError, err)
		}
	}
	duration := s.cfg.SessionDuration
	if input.RememberMe != nil && !*input.RememberMe {
		duration = 24 * time.Hour
	}
	session, raw, err := s.newSession(user.ID, duration)
	if err != nil {
		return err
	}
	session, err = s.rotateOrCreateBrowserSession(r.Context(), r, session)
	if err != nil {
		return publicError(CodeInternal, "Sign in could not be completed.", http.StatusInternalServerError, err)
	}
	s.setSessionCookie(w, raw, session.ExpiresAt)
	if err := s.ensureCSRFCookie(w, r); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"redirect": false, "token": nil, "user": user})
	return nil
}

func (s *Server) rotateOrCreateBrowserSession(ctx context.Context, r *http.Request, replacement Session) (Session, error) {
	_, _, currentRaw, err := s.sessionFromRequest(ctx, r)
	if err == nil {
		return s.store.RotateSession(ctx, HashToken(currentRaw), replacement)
	}
	return s.store.CreateSession(ctx, replacement)
}

func (s *Server) revokePreviousBrowserSession(ctx context.Context, r *http.Request, replacementRaw string) {
	_, _, currentRaw, err := s.sessionFromRequest(ctx, r)
	if err != nil || currentRaw == replacementRaw {
		return
	}
	_ = s.store.RevokeSession(ctx, HashToken(currentRaw), s.cfg.Clock.Now().UTC())
}

func invalidCredentials(cause error) error {
	return publicError(CodeInvalidCredentials, "Invalid email or password.", http.StatusUnauthorized, cause)
}
