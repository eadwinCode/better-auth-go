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
	RememberMe  *bool  `json:"rememberMe,omitempty"`
}

func (s *Server) handleSignUp(w http.ResponseWriter, r *http.Request) error {
	var input signUpRequest
	if err := s.decodeJSON(w, r, &input); err != nil {
		return err
	}
	if s.cfg.EmailPassword.DisableSignUp {
		return publicError(
			CodeSignUpDisabled,
			"Email and password sign up is not enabled",
			http.StatusBadRequest,
			nil,
		)
	}
	email, err := normalizeEmail(input.Email)
	if err != nil {
		return publicError(CodeValidation, "[body.email] Invalid email address", http.StatusBadRequest, err)
	}
	if input.Password == "" {
		return publicError(
			CodeValidation,
			"[body.password] Too small: expected string to have >=1 characters",
			http.StatusBadRequest,
			nil,
		)
	}
	if err := s.passwordPolicyError(input.Password); err != nil {
		return err
	}
	if len(strings.TrimSpace(input.Name)) == 0 || len(input.Name) > 256 || len(input.Image) > 2048 {
		return publicError(CodeBadRequest, "Invalid account details.", http.StatusBadRequest, nil)
	}
	if err := s.rateLimit(r.Context(), r, "sign-up/email", HashToken(email)); err != nil {
		return err
	}
	enumerationSafe := s.cfg.EmailPassword.RequireEmailVerification || !s.cfg.autoSignInAfterSignUp()
	if _, findErr := s.store.FindUserByEmail(r.Context(), email); findErr == nil {
		if !enumerationSafe {
			return duplicateSignUpError(nil)
		}
		if _, hashErr := s.cfg.Passwords.Hash(r.Context(), input.Password); hashErr != nil {
			return publicError(CodeInternal, "The account could not be created.", http.StatusInternalServerError, hashErr)
		}
		return s.writeSyntheticSignUp(w, input, email)
	} else if !errors.Is(findErr, ErrNotFound) {
		return publicError(CodeInternal, "The account could not be created.", http.StatusInternalServerError, findErr)
	}
	passwordHash, err := s.cfg.Passwords.Hash(r.Context(), input.Password)
	if err != nil {
		return publicError(CodeInternal, "The account could not be created.", http.StatusInternalServerError, err)
	}
	userID, err := s.newID()
	if err != nil {
		return err
	}
	createSession := s.cfg.autoSignInAfterSignUp() && !s.cfg.EmailPassword.RequireEmailVerification
	var session Session
	var rawSession string
	if createSession {
		duration := s.cfg.SessionDuration
		if input.RememberMe != nil && !*input.RememberMe {
			duration = 24 * time.Hour
		}
		session, rawSession, err = s.newSession(userID, duration)
		if err != nil {
			return err
		}
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
		User: user, PasswordHash: passwordHash, Session: session, CreateSession: createSession,
		Event: DomainEvent{
			ID: eventID, SchemaVersion: 1, Name: EventUserCreated, AggregateID: userID,
			OccurredAt: now, Payload: map[string]string{"userId": userID, "email": email},
		},
	})
	if err != nil {
		if errors.Is(err, ErrConflict) {
			if _, findErr := s.store.FindUserByEmail(r.Context(), email); findErr != nil {
				return publicError(
					CodeInternal,
					"The account could not be created.",
					http.StatusInternalServerError,
					err,
				)
			}
			if enumerationSafe {
				writeJSON(w, http.StatusOK, map[string]any{"token": nil, "user": user})
				return nil
			}
			return duplicateSignUpError(err)
		}
		return publicError(CodeInternal, "The account could not be created.", http.StatusInternalServerError, err)
	}
	if s.cfg.EmailPassword.RequireEmailVerification {
		_ = s.issueOneTimeMail(
			r,
			created,
			PurposeEmailVerify,
			"email-verification",
			s.cfg.EmailVerificationTTL,
			"/verify-email",
		)
	}
	if !createSession {
		writeJSON(w, http.StatusOK, map[string]any{"token": nil, "user": created})
		return nil
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
	if err != nil {
		return publicError(CodeInvalidEmail, "Invalid email", http.StatusBadRequest, err)
	}
	if len(input.Password) > s.cfg.MaxPasswordBytes {
		return invalidCredentials(nil)
	}
	if err := s.rateLimit(r.Context(), r, "sign-in/email", HashToken(email)); err != nil {
		return err
	}
	user, err := s.store.FindUserByEmail(r.Context(), email)
	if err != nil || user.DisabledAt != nil {
		if hashErr := s.burnPasswordHash(r.Context(), input.Password); hashErr != nil {
			return publicError(CodeInternal, "Sign in could not be completed.", http.StatusInternalServerError, hashErr)
		}
		return invalidCredentials(err)
	}
	credential, err := s.store.PasswordCredential(r.Context(), user.ID)
	if err != nil {
		if hashErr := s.burnPasswordHash(r.Context(), input.Password); hashErr != nil {
			return publicError(CodeInternal, "Sign in could not be completed.", http.StatusInternalServerError, hashErr)
		}
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
	if s.cfg.EmailPassword.RequireEmailVerification && !user.EmailVerified {
		return publicError(CodeEmailNotVerified, "Email not verified", http.StatusForbidden, nil)
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
	return publicError(CodeInvalidCredentials, "Invalid email or password", http.StatusUnauthorized, cause)
}

func (s *Server) passwordPolicyError(password string) error {
	if len(password) < s.cfg.MinPasswordBytes {
		return publicError(CodePasswordTooShort, "Password too short", http.StatusBadRequest, nil)
	}
	if len(password) > s.cfg.MaxPasswordBytes {
		return publicError(CodePasswordTooLong, "Password too long", http.StatusBadRequest, nil)
	}
	return nil
}

func (s *Server) burnPasswordHash(ctx context.Context, password string) error {
	_, err := s.cfg.Passwords.Hash(ctx, password)
	return err
}

func (s *Server) writeSyntheticSignUp(w http.ResponseWriter, input signUpRequest, email string) error {
	userID, err := s.newID()
	if err != nil {
		return err
	}
	now := s.cfg.Clock.Now().UTC()
	writeJSON(w, http.StatusOK, map[string]any{
		"token": nil,
		"user": User{
			ID: userID, Email: email, Name: strings.TrimSpace(input.Name),
			ImageURL: strings.TrimSpace(input.Image), EmailVerified: false,
			CreatedAt: now, UpdatedAt: now,
		},
	})
	return nil
}

func duplicateSignUpError(cause error) error {
	return publicError(
		CodeUserAlreadyExists,
		"User already exists. Use another email.",
		http.StatusUnprocessableEntity,
		cause,
	)
}
