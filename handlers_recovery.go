package betterauth

import (
	"errors"
	"net/http"
	"strings"
	"time"
)

type emailRequest struct {
	Email       string `json:"email"`
	CallbackURL string `json:"callbackURL,omitempty"`
}

func (s *Server) handleForgotPassword(w http.ResponseWriter, r *http.Request) error {
	var input emailRequest
	if err := s.decodeJSON(w, r, &input); err != nil {
		return err
	}
	email, err := normalizeEmail(input.Email)
	if err != nil {
		email = strings.ToLower(strings.TrimSpace(input.Email))
	}
	if err := s.rateLimit(r.Context(), r, "forget-password", HashToken(email)); err != nil {
		return err
	}
	user, findErr := s.store.FindUserByEmail(r.Context(), email)
	if findErr == nil && user.DisabledAt == nil {
		if err := s.issueOneTimeMail(r, user, PurposePasswordReset, "password-reset", s.cfg.PasswordResetTTL, "/reset-password"); err != nil {
			// The public response remains generic. Delivery failures should be
			// observed by the application's mailer, not disclosed to callers.
		}
	} else if findErr != nil && !errors.Is(findErr, ErrNotFound) {
		// Preserve the same response for storage failures to avoid account
		// enumeration at this boundary.
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  true,
		"message": "If an account matches that email, a reset message has been sent.",
	})
	return nil
}

type resetPasswordRequest struct {
	Token       string `json:"token,omitempty"`
	NewPassword string `json:"newPassword"`
}

func (s *Server) handleResetPassword(w http.ResponseWriter, r *http.Request) error {
	var input resetPasswordRequest
	if err := s.decodeJSON(w, r, &input); err != nil {
		return err
	}
	if input.Token == "" {
		input.Token = r.URL.Query().Get("token")
	}
	if len(input.Token) < 20 || len(input.Token) > 2048 ||
		len(input.NewPassword) < s.cfg.MinPasswordBytes || len(input.NewPassword) > s.cfg.MaxPasswordBytes {
		return publicError(CodeInvalidToken, "The token is invalid or expired.", http.StatusBadRequest, nil)
	}
	if err := s.rateLimit(r.Context(), r, "reset-password", HashToken(input.Token)); err != nil {
		return err
	}
	passwordHash, err := s.cfg.Passwords.Hash(r.Context(), input.NewPassword)
	if err != nil {
		return publicError(CodeInternal, "Password reset could not be completed.", http.StatusInternalServerError, err)
	}
	session, raw, err := s.newSession("", s.cfg.SessionDuration)
	if err != nil {
		return err
	}
	user, session, err := s.store.ConsumePasswordReset(r.Context(), HashToken(input.Token), passwordHash, session)
	if err != nil {
		return publicError(CodeInvalidToken, "The token is invalid or expired.", http.StatusBadRequest, err)
	}
	s.setSessionCookie(w, raw, session.ExpiresAt)
	if err := s.ensureCSRFCookie(w, r); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": true, "user": user})
	return nil
}

func (s *Server) handleSendVerification(w http.ResponseWriter, r *http.Request) error {
	var input emailRequest
	if err := s.decodeJSON(w, r, &input); err != nil {
		return err
	}
	email, err := normalizeEmail(input.Email)
	if err != nil {
		email = strings.ToLower(strings.TrimSpace(input.Email))
	}
	if err := s.rateLimit(r.Context(), r, "send-verification-email", HashToken(email)); err != nil {
		return err
	}
	user, findErr := s.store.FindUserByEmail(r.Context(), email)
	if findErr == nil && !user.EmailVerified && user.DisabledAt == nil {
		_ = s.issueOneTimeMail(r, user, PurposeEmailVerify, "email-verification", s.cfg.EmailVerificationTTL, "/verify-email")
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  true,
		"message": "If the address needs verification, a message has been sent.",
	})
	return nil
}

func (s *Server) handleConfirmVerification(w http.ResponseWriter, r *http.Request) error {
	token := r.URL.Query().Get("token")
	if len(token) < 20 || len(token) > 2048 {
		return publicError(CodeInvalidToken, "The token is invalid or expired.", http.StatusBadRequest, nil)
	}
	if err := s.rateLimit(r.Context(), r, "verify-email", HashToken(token)); err != nil {
		return err
	}
	user, err := s.store.ConsumeEmailVerification(r.Context(), HashToken(token), s.cfg.Clock.Now().UTC())
	if err != nil {
		if !errors.Is(err, ErrReplay) && !errors.Is(err, ErrNotFound) {
			return publicError(CodeInvalidToken, "The token is invalid or expired.", http.StatusBadRequest, err)
		}
		var returnTo string
		user, returnTo, err = s.store.ConsumeEmailChange(r.Context(), HashToken(token), s.cfg.Clock.Now().UTC())
		if err != nil {
			return publicError(CodeInvalidToken, "The token is invalid or expired.", http.StatusBadRequest, err)
		}
		if returnTo != "" {
			w.Header().Set("Location", returnTo)
			w.WriteHeader(http.StatusFound)
			return nil
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": true, "user": user})
	return nil
}

func (s *Server) issueOneTimeMail(
	r *http.Request,
	user User,
	purpose OneTimePurpose,
	kind string,
	ttl time.Duration,
	route string,
) error {
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
		ID: id, UserID: user.ID, Hash: HashToken(raw), Purpose: purpose,
		ExpiresAt: now.Add(ttl), CreatedAt: now,
	}
	if err := s.store.PutOneTimeToken(r.Context(), token); err != nil {
		return err
	}
	return s.cfg.Mailer.Send(r.Context(), Mail{
		Kind: kind, To: user.Email, Token: raw,
		ActionURL: s.actionURL(route, raw), ExpiresAt: token.ExpiresAt,
	})
}
