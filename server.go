package betterauth

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/mail"
	"strings"
	"time"
)

type Server struct {
	cfg            Config
	store          authStore
	trustedOrigins map[string]struct{}
	allowedReturns map[string]struct{}
	plugins        pluginRuntime
	handler        http.Handler
}

func New(cfg Config) (*Server, error) {
	normalized, origins, returns, err := cfg.normalized()
	if err != nil {
		return nil, err
	}
	plugins, err := newPluginRuntime(normalized.Plugins, normalized.Hooks)
	if err != nil {
		return nil, err
	}
	server := &Server{
		cfg:            normalized,
		store:          newDatabaseStore(normalized.Database),
		trustedOrigins: origins,
		allowedReturns: returns,
		plugins:        plugins,
	}
	server.handler = http.HandlerFunc(server.serveHTTP)
	return server, nil
}

// Handler returns an immutable, concurrency-safe standard library handler.
func (s *Server) Handler() http.Handler { return s.handler }

// Schema returns an independent copy of the fully merged core, application,
// and plugin schema. Schema-aware adapters use it for explicit migrations.
func (s *Server) Schema() Schema { return cloneSchema(s.cfg.Schema) }

func (s *Server) serveCoreHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	requestID := sanitizeRequestID(r.Header.Get("X-Request-ID"))
	if requestID != "" {
		w.Header().Set("X-Request-ID", requestID)
	}
	relative, ok := strings.CutPrefix(r.URL.Path, s.cfg.BasePath)
	if !ok || relative == "" {
		writeError(w, requestID, publicError(CodeNotFound, "Endpoint not found.", http.StatusNotFound, nil))
		return
	}

	var handler func(http.ResponseWriter, *http.Request) error
	switch relative {
	case "/sign-up/email":
		handler = s.postOnly(s.handleSignUp)
	case "/sign-in/email":
		handler = s.postOnly(s.handleSignIn)
	case "/sign-out":
		handler = s.postOnly(s.handleSignOut)
	case "/get-session":
		handler = s.getOnly(s.handleSession)
	case "/list-sessions":
		handler = s.getOnly(s.handleListSessions)
	case "/refresh-session":
		handler = s.postOnly(s.handleRefreshSession)
	case "/revoke-session":
		handler = s.postOnly(s.handleRevokeSession)
	case "/revoke-other-sessions":
		handler = s.postOnly(s.handleRevokeOtherSessions)
	case "/revoke-sessions":
		handler = s.postOnly(s.handleRevokeSessions)
	case "/update-session":
		handler = s.postOnly(s.handleUpdateSession)
	case "/update-user":
		handler = s.postOnly(s.handleUpdateUser)
	case "/change-email":
		handler = s.postOnly(s.handleChangeEmail)
	case "/delete-user":
		handler = s.postOnly(s.handleDeleteUser)
	case "/delete-user/callback":
		handler = s.getOnly(s.handleDeleteUserCallback)
	case "/change-password":
		handler = s.postOnly(s.handleChangePassword)
	case "/list-accounts":
		handler = s.getOnly(s.handleListAccounts)
	case "/link-social":
		handler = s.postOnly(s.handleLinkSocial)
	case "/unlink-account":
		handler = s.postOnly(s.handleUnlinkAccount)
	case "/get-access-token":
		handler = s.postOnly(s.handleGetAccessToken)
	case "/refresh-token":
		handler = s.postOnly(s.handleRefreshProviderToken)
	case "/sign-in/social":
		handler = s.postOnly(s.handleSocialAuthorize)
	case "/request-password-reset":
		handler = s.postOnly(s.handleForgotPassword)
	case "/forget-password":
		handler = s.postOnly(s.handleForgotPassword)
	case "/reset-password":
		handler = s.postOnly(s.handleResetPassword)
	case "/send-verification-email":
		handler = s.postOnly(s.handleSendVerification)
	case "/verify-email":
		handler = s.getOnly(s.handleConfirmVerification)
	case "/admin/impersonate-user":
		handler = s.postOnly(s.handleImpersonate)
	case "/admin/stop-impersonating":
		handler = s.postOnly(s.handleStopImpersonating)
	default:
		if token, found := strings.CutPrefix(relative, "/reset-password/"); found && token != "" {
			handler = s.getOnly(s.handleResetPasswordCallback(token))
		} else if providerID, found := strings.CutPrefix(relative, "/callback/"); found && validProviderID(providerID) {
			handler = s.handleSocialCallback(providerID)
		} else {
			writeError(w, requestID, publicError(CodeNotFound, "Endpoint not found.", http.StatusNotFound, nil))
			return
		}
	}
	if err := handler(w, r); err != nil {
		writeError(w, requestID, err)
	}
}

func (s *Server) postOnly(next func(http.ResponseWriter, *http.Request) error) func(http.ResponseWriter, *http.Request) error {
	return func(w http.ResponseWriter, r *http.Request) error {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			return publicError(CodeMethodNotAllowed, "Method not allowed.", http.StatusMethodNotAllowed, nil)
		}
		if err := s.checkOrigin(r); err != nil {
			return err
		}
		return next(w, r)
	}
}

func (s *Server) getOnly(next func(http.ResponseWriter, *http.Request) error) func(http.ResponseWriter, *http.Request) error {
	return func(w http.ResponseWriter, r *http.Request) error {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			return publicError(CodeMethodNotAllowed, "Method not allowed.", http.StatusMethodNotAllowed, nil)
		}
		return next(w, r)
	}
}

func (s *Server) decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxRequestBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return publicError(CodeBadRequest, "Invalid JSON request.", http.StatusBadRequest, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return publicError(CodeBadRequest, "The request must contain one JSON object.", http.StatusBadRequest, err)
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func normalizeEmail(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if len(value) < 3 || len(value) > 254 || strings.ContainsAny(value, "\r\n") {
		return "", errors.New("email length is invalid")
	}
	address, err := mail.ParseAddress(value)
	if err != nil || address.Address != value {
		return "", errors.New("email is invalid")
	}
	return value, nil
}

func (s *Server) newID() (string, error) {
	return s.cfg.Tokens.Token(16)
}

func (s *Server) newSession(userID string, duration time.Duration) (Session, string, error) {
	raw, err := s.cfg.Tokens.Token(32)
	if err != nil {
		return Session{}, "", err
	}
	id, err := s.newID()
	if err != nil {
		return Session{}, "", err
	}
	now := s.cfg.Clock.Now().UTC()
	return Session{
		ID:         id,
		UserID:     userID,
		TokenHash:  HashToken(raw),
		ExpiresAt:  now.Add(duration),
		CreatedAt:  now,
		UpdatedAt:  now,
		LastSeenAt: now,
	}, raw, nil
}

func (s *Server) issuePluginSession(r *http.Request, userID string) (*IssuedSession, error) {
	if userID == "" {
		return nil, publicError(CodeUnauthorized, "Authentication required.", http.StatusUnauthorized, nil)
	}
	user, err := s.store.FindUserByID(r.Context(), userID)
	if err != nil || user.DisabledAt != nil {
		return nil, publicError(CodeUnauthorized, "Authentication required.", http.StatusUnauthorized, err)
	}
	replacement, raw, err := s.newSession(user.ID, s.cfg.SessionDuration)
	if err != nil {
		return nil, err
	}
	csrf, err := s.cfg.Tokens.Token(32)
	if err != nil {
		return nil, err
	}
	if _, _, currentRaw, currentErr := s.sessionFromRequest(r.Context(), r); currentErr == nil {
		replacement, err = s.store.RotateSession(r.Context(), HashToken(currentRaw), replacement)
	} else {
		replacement, err = s.store.CreateSession(r.Context(), replacement)
	}
	if err != nil {
		return nil, publicError(
			CodeUnauthorized, "Authentication required.", http.StatusUnauthorized, err,
		)
	}
	now := s.cfg.Clock.Now().UTC()
	return &IssuedSession{
		Session: replacement,
		User:    user,
		csrf:    csrf,
		cookies: []*http.Cookie{
			{
				Name: s.cfg.Cookie.Name, Value: raw, Path: "/",
				Expires: replacement.ExpiresAt,
				MaxAge:  int(replacement.ExpiresAt.Sub(now).Seconds()),
				Secure:  true, HttpOnly: true, SameSite: s.cfg.Cookie.SameSite,
			},
			{
				Name: s.cfg.Cookie.CSRFName, Value: csrf, Path: "/",
				Expires: replacement.ExpiresAt,
				MaxAge:  int(replacement.ExpiresAt.Sub(now).Seconds()),
				Secure:  true, HttpOnly: false, SameSite: s.cfg.Cookie.SameSite,
			},
		},
	}, nil
}

func (s *Server) authenticatePluginOAuth(
	r *http.Request,
	profile OAuthProfile,
	tokens ProviderTokens,
) (*IssuedSession, bool, error) {
	if profile.Provider == "" || profile.ProviderAccountID == "" ||
		len(profile.Provider) > 128 || len(profile.ProviderAccountID) > 512 ||
		!profile.EmailVerified {
		return nil, false, publicError(
			CodeProviderFailure, "The provider did not return a verified identity.",
			http.StatusBadGateway, nil,
		)
	}
	email, err := normalizeEmail(profile.Email)
	if err != nil {
		return nil, false, publicError(
			CodeProviderFailure, "The provider did not return a verified identity.",
			http.StatusBadGateway, err,
		)
	}
	profile.Email = email
	encryptedTokens, err := s.encryptProviderTokens(r.Context(), tokens)
	if err != nil {
		return nil, false, publicError(
			CodeInternal, "External sign in could not be completed.",
			http.StatusInternalServerError, err,
		)
	}
	userID, err := s.newID()
	if err != nil {
		return nil, false, err
	}
	session, raw, err := s.newSession(userID, s.cfg.SessionDuration)
	if err != nil {
		return nil, false, err
	}
	eventID, err := s.newID()
	if err != nil {
		return nil, false, err
	}
	event := DomainEvent{
		ID: eventID, SchemaVersion: 1, Name: EventUserCreated, AggregateID: userID,
		OccurredAt: session.CreatedAt, Payload: map[string]string{
			"userId": userID, "email": profile.Email, "provider": profile.Provider,
		},
	}
	user, created, isNew, err := s.store.UpsertOAuthUser(
		r.Context(), profile, encryptedTokens, session, event,
	)
	if err != nil {
		if errors.Is(err, ErrConflict) {
			return nil, false, publicError(
				CodeConflict, "The external account could not be linked.",
				http.StatusConflict, err,
			)
		}
		return nil, false, publicError(
			CodeInternal, "External sign in could not be completed.",
			http.StatusInternalServerError, err,
		)
	}
	csrf, err := s.cfg.Tokens.Token(32)
	if err != nil {
		return nil, false, err
	}
	s.revokePreviousBrowserSession(r.Context(), r, raw)
	now := s.cfg.Clock.Now().UTC()
	return &IssuedSession{
		Session: created,
		User:    user,
		csrf:    csrf,
		cookies: []*http.Cookie{
			{
				Name: s.cfg.Cookie.Name, Value: raw, Path: "/",
				Expires: created.ExpiresAt,
				MaxAge:  int(created.ExpiresAt.Sub(now).Seconds()),
				Secure:  true, HttpOnly: true, SameSite: s.cfg.Cookie.SameSite,
			},
			{
				Name: s.cfg.Cookie.CSRFName, Value: csrf, Path: "/",
				Expires: created.ExpiresAt,
				MaxAge:  int(created.ExpiresAt.Sub(now).Seconds()),
				Secure:  true, HttpOnly: false, SameSite: s.cfg.Cookie.SameSite,
			},
		},
	}, isNew, nil
}

func (s *Server) sessionFromRequest(ctx context.Context, r *http.Request) (Session, User, string, error) {
	cookie, err := r.Cookie(s.cfg.Cookie.Name)
	if err != nil || cookie.Value == "" || len(cookie.Value) > 2048 {
		return Session{}, User{}, "", publicError(CodeUnauthorized, "Authentication required.", http.StatusUnauthorized, nil)
	}
	hash := HashToken(cookie.Value)
	session, user, err := s.store.SessionByTokenHash(ctx, hash)
	if err != nil {
		return Session{}, User{}, "", publicError(CodeUnauthorized, "Authentication required.", http.StatusUnauthorized, err)
	}
	now := s.cfg.Clock.Now().UTC()
	if session.RevokedAt != nil || !session.ExpiresAt.After(now) || user.DisabledAt != nil {
		return Session{}, User{}, "", publicError(CodeUnauthorized, "Authentication required.", http.StatusUnauthorized, nil)
	}
	return session, user, cookie.Value, nil
}

func (s *Server) setSessionCookie(w http.ResponseWriter, raw string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.cfg.Cookie.Name,
		Value:    raw,
		Path:     "/",
		Expires:  expires,
		MaxAge:   int(expires.Sub(s.cfg.Clock.Now()).Seconds()),
		Secure:   true,
		HttpOnly: true,
		SameSite: s.cfg.Cookie.SameSite,
	})
}

func (s *Server) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.cfg.Cookie.Name,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Expires:  time.Unix(1, 0),
		Secure:   true,
		HttpOnly: true,
		SameSite: s.cfg.Cookie.SameSite,
	})
}

func (s *Server) requireCSRF(r *http.Request) error {
	cookie, err := r.Cookie(s.cfg.Cookie.CSRFName)
	header := r.Header.Get("X-CSRF-Token")
	if err != nil || cookie.Value == "" || header == "" || len(cookie.Value) > 512 || len(header) > 512 {
		return publicError(CodeInvalidCSRF, "CSRF validation failed.", http.StatusForbidden, err)
	}
	if subtle.ConstantTimeCompare([]byte(HashToken(cookie.Value)), []byte(HashToken(header))) != 1 {
		return publicError(CodeInvalidCSRF, "CSRF validation failed.", http.StatusForbidden, nil)
	}
	return nil
}

func (s *Server) ensureCSRFCookie(w http.ResponseWriter, r *http.Request) error {
	if cookie, err := r.Cookie(s.cfg.Cookie.CSRFName); err == nil && cookie.Value != "" && len(cookie.Value) <= 512 {
		w.Header().Set("X-CSRF-Token", cookie.Value)
		return nil
	}
	raw, err := s.cfg.Tokens.Token(32)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     s.cfg.Cookie.CSRFName,
		Value:    raw,
		Path:     "/",
		Secure:   true,
		HttpOnly: false,
		SameSite: s.cfg.Cookie.SameSite,
	})
	w.Header().Set("X-CSRF-Token", raw)
	return nil
}

func (s *Server) checkOrigin(r *http.Request) error {
	raw := r.Header.Get("Origin")
	if raw == "" {
		return publicError(CodeInvalidOrigin, "Invalid origin", http.StatusForbidden, nil)
	}
	origin, err := normalizeOrigin(raw)
	if err != nil {
		return publicError(CodeInvalidOrigin, "Invalid origin", http.StatusForbidden, err)
	}
	if _, ok := s.trustedOrigins[origin]; !ok {
		return publicError(CodeInvalidOrigin, "Invalid origin", http.StatusForbidden, nil)
	}
	return nil
}

func (s *Server) rateLimit(ctx context.Context, r *http.Request, action, accountKey string) error {
	decision, err := s.cfg.RateLimiter.Allow(ctx, RateLimitRequest{
		Action:     action,
		IP:         s.remoteIP(r),
		AccountKey: accountKey,
	})
	if err != nil {
		return publicError(CodeInternal, "The request could not be completed.", http.StatusInternalServerError, err)
	}
	if !decision.Allowed {
		result := publicError(CodeRateLimited, "Too many requests.", http.StatusTooManyRequests, nil)
		result.RetryAfter = decision.RetryAfter
		return result
	}
	return nil
}

func (s *Server) remoteIP(r *http.Request) string {
	if s.cfg.TrustProxyHeaders {
		if forwarded := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-For"), ",")[0]); net.ParseIP(forwarded) != nil {
			return forwarded
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && net.ParseIP(host) != nil {
		return host
	}
	if net.ParseIP(r.RemoteAddr) != nil {
		return r.RemoteAddr
	}
	return ""
}

func (s *Server) requestMetadata(r *http.Request) RequestMetadata {
	return RequestMetadata{
		RequestID: sanitizeRequestID(r.Header.Get("X-Request-ID")),
		IP:        s.remoteIP(r),
		UserAgent: truncate(strings.TrimSpace(r.UserAgent()), 512),
	}
}

func sanitizeRequestID(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 128 || strings.ContainsAny(value, "\r\n") {
		return ""
	}
	return value
}

func truncate(value string, max int) string {
	if len(value) <= max {
		return value
	}
	return value[:max]
}

func (s *Server) actionURL(route, token string) string {
	return fmt.Sprintf("%s%s%s?token=%s", s.cfg.PublicURL, s.cfg.BasePath, route, token)
}
