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
	if linkUserID != "" && !s.cfg.accountLinkingEnabled() {
		return publicError(CodeLinkingNotAllowed, "Account linking is not allowed.", http.StatusUnauthorized, nil)
	}
	returnTo, err := s.allowedRedirect(input.CallbackURL)
	if err != nil {
		return err
	}
	errorReturnTo, err := s.allowedRedirect(input.ErrorCallbackURL)
	if err != nil {
		return err
	}
	newUserReturnTo, err := s.allowedRedirect(input.NewUserCallbackURL)
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
		RedirectURI: redirectURI, ReturnTo: returnTo, ErrorReturnTo: errorReturnTo,
		NewUserReturnTo: newUserReturnTo, LinkUserID: linkUserID, RequestSignUp: input.RequestSignUp,
		ExpiresAt: now.Add(s.cfg.OAuthStateTTL), CreatedAt: now,
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
		writeJSON(w, http.StatusOK, map[string]any{"url": parsed.String(), "redirect": false})
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
		if r.Method == http.MethodPost {
			r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxRequestBytes)
			if err := r.ParseForm(); err != nil {
				return publicError(CodeBadRequest, "Invalid provider callback.", http.StatusBadRequest, err)
			}
		}
		stateRaw := callbackValue(r, "state")
		if len(stateRaw) < 20 || len(stateRaw) > 2048 {
			return publicError(CodeInvalidToken, "The authorization response is invalid or expired.", http.StatusBadRequest, nil)
		}
		state, err := s.store.ConsumeOAuthState(r.Context(), HashToken(stateRaw), s.cfg.Clock.Now().UTC())
		if err != nil {
			return publicError(CodeInvalidToken, "The authorization response is invalid or expired.", http.StatusBadRequest, err)
		}
		if state.RedirectURI != s.providerCallbackURL(providerID) {
			return publicError(CodeInvalidToken, "The authorization response is invalid or expired.", http.StatusBadRequest, nil)
		}
		provider, ok := s.cfg.SocialProviders[providerID]
		if !ok {
			return publicError(CodeNotFound, "Social provider is not configured.", http.StatusNotFound, nil)
		}
		if providerError := callbackValue(r, "error"); providerError != "" {
			return s.oauthCallbackError(
				w, state, safeProviderError(providerError), CodeProviderFailure,
				"The identity provider rejected the request.", http.StatusBadGateway, nil,
			)
		}
		code := callbackValue(r, "code")
		if len(code) == 0 || len(code) > 4096 {
			return s.oauthCallbackError(
				w, state, "no_code", CodeProviderFailure,
				"The identity provider did not return an authorization code.", http.StatusBadGateway, nil,
			)
		}
		ctx, cancel := context.WithTimeout(r.Context(), s.cfg.ProviderTimeout)
		defer cancel()
		result, err := provider.Exchange(ctx, code, state.PKCEVerifier, state.Nonce, state.RedirectURI)
		if err != nil {
			return s.oauthCallbackError(
				w, state, "invalid_code", CodeProviderFailure,
				"Social sign in could not be completed.", http.StatusBadGateway, err,
			)
		}
		profile := result.Profile
		profile.Provider = providerID
		profile.Email, err = normalizeEmail(profile.Email)
		trustedProvider, trustErr := s.trustedOAuthProvider(r, providerID)
		if trustErr != nil {
			return s.oauthCallbackError(
				w, state, "unable_to_get_user_info", CodeProviderFailure,
				"The provider did not return a verified identity.", http.StatusBadGateway, trustErr,
			)
		}
		if err != nil || profile.ProviderAccountID == "" || len(profile.ProviderAccountID) > 512 ||
			(!profile.EmailVerified && !trustedProvider) {
			return s.oauthCallbackError(
				w, state, "unable_to_get_user_info", CodeProviderFailure,
				"The provider did not return a verified identity.", http.StatusBadGateway, err,
			)
		}
		if trustedProvider {
			// Membership in TrustedProviders is an application-owned assertion
			// that this configured provider supplies verified email identity.
			profile.EmailVerified = true
		}
		encryptedTokens, err := s.encryptProviderTokens(r.Context(), result.Tokens)
		if err != nil {
			return publicError(CodeInternal, "Social sign in could not be completed.", http.StatusInternalServerError, err)
		}
		if state.LinkUserID != "" {
			_, linkingUser, _, sessionErr := s.sessionFromRequest(r.Context(), r)
			if sessionErr != nil || linkingUser.ID != state.LinkUserID {
				return s.oauthCallbackError(
					w, state, "session_expired", CodeUnauthorized,
					"Authentication required.", http.StatusUnauthorized, sessionErr,
				)
			}
			if !s.cfg.accountLinkingEnabled() {
				return s.oauthCallbackError(
					w, state, "unable_to_link_account", CodeLinkingNotAllowed,
					"Account linking is not allowed.", http.StatusUnauthorized, nil,
				)
			}
			if !s.cfg.Account.AllowLinkingDifferentEmails && profile.Email != linkingUser.Email {
				return s.oauthCallbackError(
					w, state, "email_doesn't_match", CodeLinkingDifferentEmails,
					"Account linking with a different email is not allowed.", http.StatusUnauthorized, nil,
				)
			}
			accountID, err := s.newID()
			if err != nil {
				return err
			}
			if err := s.store.LinkOAuthAccount(
				r.Context(), accountID, linkingUser.ID, profile, encryptedTokens, s.cfg.Clock.Now().UTC(),
			); err != nil {
				if errors.Is(err, ErrConflict) {
					return s.oauthCallbackError(
						w, state, "account_already_linked_to_different_user", CodeAccountLinkedElsewhere,
						"The social account is already linked to another user.", http.StatusConflict, err,
					)
				}
				return s.oauthCallbackError(
					w, state, "unable_to_link_account", CodeInternal,
					"The social account could not be linked.", http.StatusInternalServerError, err,
				)
			}
			if s.cfg.Account.UpdateUserInfoOnLink {
				fields := Record{}
				if profile.Name != "" {
					fields["name"] = profile.Name
				}
				if profile.ImageURL != "" {
					fields["image"] = profile.ImageURL
				}
				if len(fields) > 0 {
					if updated, updateErr := s.store.UpdateUser(
						r.Context(), linkingUser.ID, fields, s.cfg.Clock.Now().UTC(),
					); updateErr == nil {
						linkingUser = updated
					}
				}
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
		allowSignUp := true
		if policy, supportsPolicy := provider.(OAuthProviderSignUpPolicy); supportsPolicy {
			allowSignUp = !policy.DisableSignUp() && (!policy.DisableImplicitSignUp() || state.RequestSignUp)
		}
		user, createdSession, isNew, err := s.store.UpsertOAuthUser(
			r.Context(), profile, encryptedTokens, session, event, OAuthUpsertPolicy{
				AllowImplicitLink:        s.cfg.accountLinkingEnabled() && !s.cfg.Account.DisableImplicitLinking,
				RequireLocalVerification: s.cfg.requireLocalEmailVerifiedForLinking(),
				UpdateUserInfoOnLink:     s.cfg.Account.UpdateUserInfoOnLink,
				UpdateAccountOnSignIn:    s.cfg.updateAccountOnSignIn(),
				AllowSignUp:              allowSignUp,
			},
		)
		if err != nil {
			if errors.Is(err, ErrAccountNotLinked) {
				return s.oauthCallbackError(
					w, state, "account_not_linked", CodeAccountNotLinked,
					"The account is not linked.", http.StatusForbidden, err,
				)
			}
			if errors.Is(err, ErrSignUpDisabled) {
				return s.oauthCallbackError(
					w, state, "signup_disabled", CodeOAuthSignUpDisabled,
					"Social sign up is disabled.", http.StatusForbidden, err,
				)
			}
			if errors.Is(err, ErrConflict) {
				return s.oauthCallbackError(
					w, state, "unable_to_link_account", CodeConflict,
					"The social account could not be linked.", http.StatusConflict, err,
				)
			}
			return s.oauthCallbackError(
				w, state, "internal_server_error", CodeInternal,
				"Social sign in could not be completed.", http.StatusInternalServerError, err,
			)
		}
		s.revokePreviousBrowserSession(r.Context(), r, raw)
		s.setSessionCookie(w, raw, createdSession.ExpiresAt)
		if err := s.ensureCSRFCookie(w, r); err != nil {
			return err
		}
		destination := state.ReturnTo
		if isNew && state.NewUserReturnTo != "" {
			destination = state.NewUserReturnTo
		}
		if destination != "" {
			w.Header().Set("Location", destination)
			w.WriteHeader(http.StatusFound)
			return nil
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"redirect": false, "token": nil, "user": user, "isNewUser": isNew,
		})
		return nil
	}
}

func (s *Server) trustedOAuthProvider(request *http.Request, providerID string) (bool, error) {
	trustedProviders := s.cfg.Account.TrustedProviders
	if s.cfg.Account.TrustedProviderResolver != nil {
		resolved, err := s.cfg.Account.TrustedProviderResolver.TrustedProviders(request.Context(), request)
		if err != nil {
			return false, err
		}
		trustedProviders = resolved
	}
	for _, raw := range trustedProviders {
		trusted := strings.ToLower(strings.TrimSpace(raw))
		if !validProviderID(trusted) {
			return false, errors.New("betterauth: trusted provider resolver returned an invalid provider")
		}
		if _, configured := s.cfg.SocialProviders[trusted]; !configured && trusted != "email-password" {
			return false, errors.New("betterauth: trusted provider resolver returned an unconfigured provider")
		}
		if trusted == providerID {
			return true, nil
		}
	}
	return false, nil
}

func (s *Server) oauthCallbackError(
	w http.ResponseWriter,
	state OAuthState,
	redirectCode string,
	code ErrorCode,
	message string,
	status int,
	cause error,
) error {
	if state.ErrorReturnTo == "" {
		return publicError(code, message, status, cause)
	}
	destination, err := url.Parse(state.ErrorReturnTo)
	if err != nil {
		return publicError(CodeInternal, "Social sign in could not be completed.", http.StatusInternalServerError, err)
	}
	query := destination.Query()
	query.Set("error", redirectCode)
	destination.RawQuery = query.Encode()
	w.Header().Set("Location", destination.String())
	w.WriteHeader(http.StatusFound)
	return nil
}

func safeProviderError(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "access_denied", "account_selection_required", "consent_required", "interaction_required",
		"login_required", "server_error", "temporarily_unavailable":
		return strings.ToLower(strings.TrimSpace(raw))
	default:
		return "provider_error"
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
