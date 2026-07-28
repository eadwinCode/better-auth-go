package betterauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

type socialSignInRequest struct {
	Provider           string `json:"provider"`
	CallbackURL        string `json:"callbackURL,omitempty"`
	ErrorCallbackURL   string `json:"errorCallbackURL,omitempty"`
	NewUserCallbackURL string `json:"newUserCallbackURL,omitempty"`
	DisableRedirect    bool   `json:"disableRedirect,omitempty"`
	RequestSignUp      bool   `json:"requestSignUp,omitempty"`
}

func (s *Server) handleSocialAuthorize(w http.ResponseWriter, r *http.Request) error {
	var input socialSignInRequest
	if err := s.decodeJSON(w, r, &input); err != nil {
		return err
	}
	return s.beginSocialAuthorize(w, r, input, "")
}

func (s *Server) handleLinkSocial(w http.ResponseWriter, r *http.Request) error {
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
	var input socialSignInRequest
	if err := s.decodeJSON(w, r, &input); err != nil {
		return err
	}
	return s.beginSocialAuthorize(w, r, input, user.ID)
}

func (s *Server) beginSocialAuthorize(
	w http.ResponseWriter,
	r *http.Request,
	input socialSignInRequest,
	linkUserID string,
) error {
	providerID := strings.ToLower(strings.TrimSpace(input.Provider))
	provider, ok := s.cfg.SocialProviders[providerID]
	if !ok {
		return publicError(CodeBadRequest, "Social provider is not configured.", http.StatusBadRequest, nil)
	}
	returnTo, err := s.allowedRedirect(input.CallbackURL)
	if err != nil {
		return err
	}
	action := "sign-in/social:" + providerID
	accountKey := ""
	if linkUserID != "" {
		action = "link-social:" + providerID
		accountKey = HashToken(linkUserID)
	}
	if err := s.rateLimit(r.Context(), r, action, accountKey); err != nil {
		return err
	}
	stateRaw, err := s.cfg.Tokens.Token(32)
	if err != nil {
		return err
	}
	verifier, err := s.cfg.Tokens.Token(48)
	if err != nil {
		return err
	}
	nonce, err := s.cfg.Tokens.Token(32)
	if err != nil {
		return err
	}
	stateID, err := s.newID()
	if err != nil {
		return err
	}
	now := s.cfg.Clock.Now().UTC()
	redirectURI := s.providerCallbackURL(providerID)
	state := OAuthState{
		ID: stateID, Hash: HashToken(stateRaw), PKCEVerifier: verifier, Nonce: nonce,
		RedirectURI: redirectURI, ReturnTo: returnTo,
		LinkUserID: linkUserID, ExpiresAt: now.Add(s.cfg.OAuthStateTTL), CreatedAt: now,
	}
	if err := s.store.PutOAuthState(r.Context(), state); err != nil {
		return publicError(CodeInternal, "Social sign in could not be started.", http.StatusInternalServerError, err)
	}
	destination, err := provider.AuthorizationURL(stateRaw, pkceChallenge(verifier), nonce, redirectURI)
	if err != nil {
		return publicError(CodeProviderFailure, "Social sign in could not be started.", http.StatusBadGateway, err)
	}
	parsed, err := url.Parse(destination)
	if err != nil || parsed == nil || !parsed.IsAbs() || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
		return publicError(CodeProviderFailure, "Social sign in could not be started.", http.StatusBadGateway, err)
	}
	if input.DisableRedirect {
		writeJSON(w, http.StatusOK, map[string]any{"url": parsed.String(), "redirect": true})
		return nil
	}
	w.Header().Set("Location", parsed.String())
	w.WriteHeader(http.StatusFound)
	return nil
}

func (s *Server) handleSocialCallback(providerID string) func(http.ResponseWriter, *http.Request) error {
	return func(w http.ResponseWriter, r *http.Request) error {
		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodGet+", "+http.MethodPost)
			return publicError(CodeMethodNotAllowed, "Method not allowed.", http.StatusMethodNotAllowed, nil)
		}
		provider, ok := s.cfg.SocialProviders[providerID]
		if !ok {
			return publicError(CodeNotFound, "Social provider is not configured.", http.StatusNotFound, nil)
		}
		if r.Method == http.MethodPost {
			r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxRequestBytes)
			if err := r.ParseForm(); err != nil {
				return publicError(CodeBadRequest, "Invalid provider callback.", http.StatusBadRequest, err)
			}
		}
		if providerError := callbackValue(r, "error"); providerError != "" {
			return publicError(CodeProviderFailure, "The identity provider rejected the request.", http.StatusBadGateway, nil)
		}
		stateRaw := callbackValue(r, "state")
		code := callbackValue(r, "code")
		if len(stateRaw) < 20 || len(stateRaw) > 2048 || len(code) == 0 || len(code) > 4096 {
			return publicError(CodeInvalidToken, "The authorization response is invalid or expired.", http.StatusBadRequest, nil)
		}
		state, err := s.store.ConsumeOAuthState(r.Context(), HashToken(stateRaw), s.cfg.Clock.Now().UTC())
		if err != nil {
			return publicError(CodeInvalidToken, "The authorization response is invalid or expired.", http.StatusBadRequest, err)
		}
		ctx, cancel := context.WithTimeout(r.Context(), s.cfg.ProviderTimeout)
		defer cancel()
		result, err := provider.Exchange(ctx, code, state.PKCEVerifier, state.Nonce, state.RedirectURI)
		if err != nil {
			return publicError(CodeProviderFailure, "Social sign in could not be completed.", http.StatusBadGateway, err)
		}
		profile := result.Profile
		profile.Provider = providerID
		profile.Email, err = normalizeEmail(profile.Email)
		if err != nil || profile.ProviderAccountID == "" || len(profile.ProviderAccountID) > 512 || !profile.EmailVerified {
			return publicError(CodeProviderFailure, "The provider did not return a verified identity.", http.StatusBadGateway, err)
		}
		encryptedTokens, err := s.encryptProviderTokens(r.Context(), result.Tokens)
		if err != nil {
			return publicError(CodeInternal, "Social sign in could not be completed.", http.StatusInternalServerError, err)
		}
		if state.LinkUserID != "" {
			_, linkingUser, _, sessionErr := s.sessionFromRequest(r.Context(), r)
			if sessionErr != nil || linkingUser.ID != state.LinkUserID {
				return publicError(CodeUnauthorized, "Authentication required.", http.StatusUnauthorized, sessionErr)
			}
			if !s.cfg.Account.AllowLinkingDifferentEmails && profile.Email != linkingUser.Email {
				return publicError(CodeConflict, "The social account could not be linked.", http.StatusConflict, nil)
			}
			accountID, err := s.newID()
			if err != nil {
				return err
			}
			if err := s.store.LinkOAuthAccount(
				r.Context(), accountID, linkingUser.ID, profile, encryptedTokens, s.cfg.Clock.Now().UTC(),
			); err != nil {
				if errors.Is(err, ErrConflict) {
					return publicError(CodeConflict, "The social account could not be linked.", http.StatusConflict, err)
				}
				return publicError(CodeInternal, "The social account could not be linked.", http.StatusInternalServerError, err)
			}
			if state.ReturnTo != "" {
				w.Header().Set("Location", state.ReturnTo)
				w.WriteHeader(http.StatusFound)
				return nil
			}
			writeJSON(w, http.StatusOK, map[string]any{"redirect": false, "user": linkingUser})
			return nil
		}
		userID, err := s.newID()
		if err != nil {
			return err
		}
		session, raw, err := s.newSession(userID, s.cfg.SessionDuration)
		if err != nil {
			return err
		}
		eventID, err := s.newID()
		if err != nil {
			return err
		}
		event := DomainEvent{
			ID: eventID, SchemaVersion: 1, Name: EventUserCreated, AggregateID: userID,
			OccurredAt: session.CreatedAt, Payload: map[string]string{
				"userId": userID, "email": profile.Email, "provider": providerID,
			},
		}
		user, createdSession, isNew, err := s.store.UpsertOAuthUser(r.Context(), profile, encryptedTokens, session, event)
		if err != nil {
			if errors.Is(err, ErrConflict) {
				return publicError(CodeConflict, "The social account could not be linked.", http.StatusConflict, err)
			}
			return publicError(CodeInternal, "Social sign in could not be completed.", http.StatusInternalServerError, err)
		}
		s.revokePreviousBrowserSession(r.Context(), r, raw)
		s.setSessionCookie(w, raw, createdSession.ExpiresAt)
		if err := s.ensureCSRFCookie(w, r); err != nil {
			return err
		}
		if state.ReturnTo != "" {
			w.Header().Set("Location", state.ReturnTo)
			w.WriteHeader(http.StatusFound)
			return nil
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"redirect": false, "token": nil, "user": user, "isNewUser": isNew,
		})
		return nil
	}
}

func (s *Server) encryptProviderTokens(ctx context.Context, tokens ProviderTokens) (ProviderTokens, error) {
	var err error
	tokens.AccessToken, err = sealOptional(ctx, s.cfg.ProviderTokenCipher, tokens.AccessToken)
	if err != nil {
		return ProviderTokens{}, err
	}
	tokens.RefreshToken, err = sealOptional(ctx, s.cfg.ProviderTokenCipher, tokens.RefreshToken)
	if err != nil {
		return ProviderTokens{}, err
	}
	tokens.IDToken, err = sealOptional(ctx, s.cfg.ProviderTokenCipher, tokens.IDToken)
	if err != nil {
		return ProviderTokens{}, err
	}
	return tokens, nil
}

func sealOptional(ctx context.Context, cipher TokenCipher, value string) (string, error) {
	if value == "" {
		return "", nil
	}
	if cipher == nil {
		return "", errors.New("betterauth: provider token cipher is not configured")
	}
	return cipher.Seal(ctx, value)
}

func callbackValue(r *http.Request, key string) string {
	if r.Method == http.MethodPost {
		return r.PostForm.Get(key)
	}
	return r.URL.Query().Get(key)
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func (s *Server) providerCallbackURL(providerID string) string {
	return s.cfg.PublicURL + s.cfg.BasePath + "/callback/" + url.PathEscape(providerID)
}

func (s *Server) allowedRedirect(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", publicError(CodeBadRequest, "Callback URL is not allowed.", http.StatusBadRequest, err)
	}
	if !parsed.IsAbs() {
		base, parseErr := url.Parse(s.cfg.PublicURL)
		if parseErr != nil {
			return "", parseErr
		}
		parsed = base.ResolveReference(parsed)
	}
	checked, err := validateHTTPSURL(parsed.String(), true)
	if err != nil {
		return "", publicError(CodeBadRequest, "Callback URL is not allowed.", http.StatusBadRequest, err)
	}
	canonical := checked.String()
	if _, ok := s.allowedReturns[canonical]; !ok {
		return "", publicError(CodeBadRequest, "Callback URL is not allowed.", http.StatusBadRequest, nil)
	}
	return canonical, nil
}
