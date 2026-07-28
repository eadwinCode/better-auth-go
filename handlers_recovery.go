package betterauth

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type emailRequest struct {
	Email       string `json:"email"`
	CallbackURL string `json:"callbackURL,omitempty"`
	RedirectTo  string `json:"redirectTo,omitempty"`
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
	redirectTo := input.RedirectTo
	if redirectTo == "" {
		redirectTo = input.CallbackURL
	}
	redirectTo, err = s.allowedRedirect(redirectTo)
	if err != nil {
		return err
	}
	user, findErr := s.store.FindUserByEmail(r.Context(), email)
	if findErr == nil && user.DisabledAt == nil {
		if err := s.issueOneTimeMail(
			r,
			user,
			PurposePasswordReset,
			"password-reset",
			s.cfg.PasswordResetTTL,
			"/reset-password",
			redirectTo,
		); err != nil {
			// The public response remains generic. Delivery failures should be
			// observed by the application's mailer, not disclosed to callers.
		}
	} else if findErr != nil && !errors.Is(findErr, ErrNotFound) {
		// Preserve the same response for storage failures to avoid account
		// enumeration at this boundary.
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  true,
		"message": "If this email exists in our system, check your email for the reset link",
	})
	return nil
}

func (s *Server) handleResetPasswordCallback(token string) func(http.ResponseWriter, *http.Request) error {
	return func(w http.ResponseWriter, r *http.Request) error {
		callbackURL, err := s.allowedRedirect(r.URL.Query().Get("callbackURL"))
		if err != nil {
			return err
		}
		if callbackURL == "" {
			return publicError(CodeBadRequest, "Callback URL is not allowed.", http.StatusBadRequest, nil)
		}
		valid := len(token) >= 20 && len(token) <= 2048
		if valid {
			valid, err = s.store.HasOneTimeToken(
				r.Context(),
				PurposePasswordReset,
				HashToken(token),
				s.cfg.Clock.Now().UTC(),
			)
			if err != nil {
				return publicError(CodeInternal, "The request could not be completed.", http.StatusInternalServerError, err)
			}
		}
		target, parseErr := url.Parse(callbackURL)
		if parseErr != nil {
			return publicError(CodeBadRequest, "Callback URL is not allowed.", http.StatusBadRequest, parseErr)
		}
		query := target.Query()
		if valid {
			query.Set("token", token)
		} else {
			query.Set("error", "INVALID_TOKEN")
		}
		target.RawQuery = query.Encode()
		http.Redirect(w, r, target.String(), http.StatusFound)
		return nil
	}
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
	if len(input.Token) < 20 || len(input.Token) > 2048 {
		return publicError(CodeInvalidToken, "Invalid token", http.StatusBadRequest, nil)
	}
	if err := s.passwordPolicyError(input.NewPassword); err != nil {
		return err
	}
	if err := s.rateLimit(r.Context(), r, "reset-password", HashToken(input.Token)); err != nil {
		return err
	}
	passwordHash, err := s.cfg.Passwords.Hash(r.Context(), input.NewPassword)
	if err != nil {
		return publicError(CodeInternal, "Password reset could not be completed.", http.StatusInternalServerError, err)
	}
	_, err = s.store.ConsumePasswordReset(
		r.Context(),
		HashToken(input.Token),
		passwordHash,
		s.cfg.Clock.Now().UTC(),
		s.cfg.EmailPassword.RevokeSessionsOnPasswordReset,
	)
	if err != nil {
		return publicError(CodeInvalidToken, "Invalid token", http.StatusBadRequest, err)
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": true})
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
	callbackURL, err := s.allowedRedirect(input.CallbackURL)
	if err != nil {
		return err
	}
	var user User
	var findErr error
	if _, sessionUser, _, sessionErr := s.sessionFromRequest(r.Context(), r); sessionErr == nil {
		if sessionUser.Email != email {
			return publicError(CodeEmailMismatch, "Email mismatch", http.StatusBadRequest, nil)
		}
		if sessionUser.EmailVerified {
			return publicError(CodeEmailAlreadyVerified, "Email is already verified", http.StatusBadRequest, nil)
		}
		user = sessionUser
	} else {
		user, findErr = s.store.FindUserByEmail(r.Context(), email)
	}
	if findErr == nil && !user.EmailVerified && user.DisabledAt == nil {
		_ = s.issueOneTimeMail(
			r,
			user,
			PurposeEmailVerify,
			"email-verification",
			s.cfg.EmailVerificationTTL,
			"/verify-email",
			callbackURL,
		)
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": true})
	return nil
}

func (s *Server) handleConfirmVerification(w http.ResponseWriter, r *http.Request) error {
	callbackURL, err := s.allowedRedirect(r.URL.Query().Get("callbackURL"))
	if err != nil {
		return err
	}
	token := r.URL.Query().Get("token")
	if len(token) < 20 || len(token) > 2048 {
		if callbackURL != "" {
			return redirectWithParameter(w, r, callbackURL, "error", "INVALID_TOKEN")
		}
		return publicError(CodeInvalidToken, "The token is invalid or expired.", http.StatusBadRequest, nil)
	}
	if err := s.rateLimit(r.Context(), r, "verify-email", HashToken(token)); err != nil {
		return err
	}
	user, err := s.store.ConsumeEmailVerification(r.Context(), HashToken(token), s.cfg.Clock.Now().UTC())
	emailChange := false
	if err != nil {
		if !errors.Is(err, ErrReplay) && !errors.Is(err, ErrNotFound) {
			return publicError(CodeInvalidToken, "The token is invalid or expired.", http.StatusBadRequest, err)
		}
		var returnTo string
		user, returnTo, err = s.store.ConsumeEmailChange(r.Context(), HashToken(token), s.cfg.Clock.Now().UTC())
		if err != nil {
			if callbackURL != "" {
				return redirectWithParameter(w, r, callbackURL, "error", "INVALID_TOKEN")
			}
			return publicError(CodeInvalidToken, "The token is invalid or expired.", http.StatusBadRequest, err)
		}
		emailChange = true
		if returnTo != "" {
			w.Header().Set("Location", returnTo)
			w.WriteHeader(http.StatusFound)
			return nil
		}
	}
	if emailChange {
		writeJSON(w, http.StatusOK, map[string]any{"status": true, "user": user})
		return nil
	}
	if callbackURL != "" {
		http.Redirect(w, r, callbackURL, http.StatusFound)
		return nil
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": true, "user": nil})
	return nil
}

func redirectWithParameter(
	w http.ResponseWriter,
	r *http.Request,
	rawURL string,
	key string,
	value string,
) error {
	target, err := url.Parse(rawURL)
	if err != nil {
		return err
	}
	query := target.Query()
	query.Set(key, value)
	target.RawQuery = query.Encode()
	http.Redirect(w, r, target.String(), http.StatusFound)
	return nil
}

func (s *Server) issueOneTimeMail(
	r *http.Request,
	user User,
	purpose OneTimePurpose,
	kind string,
	ttl time.Duration,
	route string,
	callbackURL string,
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
	actionURL := s.actionURL(route, raw)
	if purpose == PurposePasswordReset {
		actionURL = s.cfg.PublicURL + s.cfg.BasePath + route + "/" + url.PathEscape(raw) + "?callbackURL=" + url.QueryEscape(callbackURL)
	} else if callbackURL != "" {
		actionURL += "&callbackURL=" + url.QueryEscape(callbackURL)
	}
	return s.cfg.Mailer.Send(r.Context(), Mail{
		Kind: kind, To: user.Email, Token: raw,
		ActionURL: actionURL, ExpiresAt: token.ExpiresAt,
	})
}
