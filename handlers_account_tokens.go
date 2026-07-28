package betterauth

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"
)

type providerTokenRequest struct {
	ProviderID string `json:"providerId"`
	AccountID  string `json:"accountId,omitempty"`
}

func (s *Server) handleGetAccessToken(w http.ResponseWriter, r *http.Request) error {
	if err := s.requireCSRF(r); err != nil {
		return err
	}
	_, user, _, err := s.sessionFromRequest(r.Context(), r)
	if err != nil {
		return err
	}
	var input providerTokenRequest
	if err := s.decodeJSON(w, r, &input); err != nil {
		return err
	}
	stored, err := s.providerAccount(r.Context(), user.ID, input)
	if err != nil {
		return err
	}
	tokens, err := s.decryptProviderTokens(r.Context(), stored.Tokens)
	if err != nil {
		return publicError(CodeInternal, "Provider token could not be read.", http.StatusInternalServerError, err)
	}
	if tokens.AccessToken == "" ||
		!tokens.AccessTokenExpiresAt.IsZero() && !tokens.AccessTokenExpiresAt.After(s.cfg.Clock.Now().UTC().Add(30*time.Second)) {
		tokens, err = s.refreshProviderAccount(r.Context(), user.ID, stored, tokens)
		if err != nil {
			return err
		}
	}
	writeProviderToken(w, tokens)
	return nil
}

func (s *Server) handleRefreshProviderToken(w http.ResponseWriter, r *http.Request) error {
	if err := s.requireCSRF(r); err != nil {
		return err
	}
	_, user, _, err := s.sessionFromRequest(r.Context(), r)
	if err != nil {
		return err
	}
	var input providerTokenRequest
	if err := s.decodeJSON(w, r, &input); err != nil {
		return err
	}
	stored, err := s.providerAccount(r.Context(), user.ID, input)
	if err != nil {
		return err
	}
	tokens, err := s.decryptProviderTokens(r.Context(), stored.Tokens)
	if err != nil {
		return publicError(CodeInternal, "Provider token could not be refreshed.", http.StatusInternalServerError, err)
	}
	tokens, err = s.refreshProviderAccount(r.Context(), user.ID, stored, tokens)
	if err != nil {
		return err
	}
	writeProviderToken(w, tokens)
	return nil
}

func (s *Server) providerAccount(
	ctx context.Context,
	userID string,
	input providerTokenRequest,
) (StoredOAuthAccount, error) {
	providerID := strings.ToLower(strings.TrimSpace(input.ProviderID))
	accountID := strings.TrimSpace(input.AccountID)
	if !validProviderID(providerID) || len(accountID) > 512 || providerID == credentialProvider {
		return StoredOAuthAccount{}, publicError(
			CodeBadRequest, "Invalid provider account.", http.StatusBadRequest, nil,
		)
	}
	account, err := s.store.OAuthAccountTokens(ctx, userID, providerID, accountID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return StoredOAuthAccount{}, publicError(
				CodeNotFound, "Provider account not found.", http.StatusNotFound, err,
			)
		}
		return StoredOAuthAccount{}, publicError(
			CodeInternal, "Provider account could not be read.", http.StatusInternalServerError, err,
		)
	}
	return account, nil
}

func (s *Server) refreshProviderAccount(
	ctx context.Context,
	userID string,
	stored StoredOAuthAccount,
	current ProviderTokens,
) (ProviderTokens, error) {
	provider, exists := s.cfg.SocialProviders[stored.Account.Provider]
	refresher, refreshable := provider.(OAuthTokenRefresher)
	if !exists || !refreshable || current.RefreshToken == "" ||
		!current.RefreshTokenExpiresAt.IsZero() && !current.RefreshTokenExpiresAt.After(s.cfg.Clock.Now().UTC()) {
		return ProviderTokens{}, publicError(
			CodeProviderFailure, "Provider token could not be refreshed.", http.StatusBadGateway, nil,
		)
	}
	requestContext, cancel := context.WithTimeout(ctx, s.cfg.ProviderTimeout)
	defer cancel()
	refreshed, err := refresher.Refresh(requestContext, current.RefreshToken)
	if err != nil || refreshed.AccessToken == "" {
		return ProviderTokens{}, publicError(
			CodeProviderFailure, "Provider token could not be refreshed.", http.StatusBadGateway, err,
		)
	}
	if refreshed.RefreshToken == "" {
		refreshed.RefreshToken = current.RefreshToken
	}
	if refreshed.RefreshTokenExpiresAt.IsZero() {
		refreshed.RefreshTokenExpiresAt = current.RefreshTokenExpiresAt
	}
	if refreshed.IDToken == "" {
		refreshed.IDToken = current.IDToken
	}
	if refreshed.Scope == "" {
		refreshed.Scope = current.Scope
	}
	encrypted, err := s.encryptProviderTokens(ctx, refreshed)
	if err != nil {
		return ProviderTokens{}, publicError(
			CodeInternal, "Provider token could not be refreshed.", http.StatusInternalServerError, err,
		)
	}
	if err := s.store.UpdateOAuthAccountTokens(
		ctx, userID, stored.Account.ID, encrypted, s.cfg.Clock.Now().UTC(),
	); err != nil {
		return ProviderTokens{}, publicError(
			CodeInternal, "Provider token could not be refreshed.", http.StatusInternalServerError, err,
		)
	}
	return refreshed, nil
}

func (s *Server) decryptProviderTokens(ctx context.Context, tokens ProviderTokens) (ProviderTokens, error) {
	var err error
	tokens.AccessToken, err = openOptional(ctx, s.cfg.ProviderTokenCipher, tokens.AccessToken)
	if err != nil {
		return ProviderTokens{}, err
	}
	tokens.RefreshToken, err = openOptional(ctx, s.cfg.ProviderTokenCipher, tokens.RefreshToken)
	if err != nil {
		return ProviderTokens{}, err
	}
	tokens.IDToken, err = openOptional(ctx, s.cfg.ProviderTokenCipher, tokens.IDToken)
	if err != nil {
		return ProviderTokens{}, err
	}
	return tokens, nil
}

func openOptional(ctx context.Context, cipher TokenCipher, value string) (string, error) {
	if value == "" {
		return "", nil
	}
	if cipher == nil {
		return "", errors.New("betterauth: provider token cipher is not configured")
	}
	return cipher.Open(ctx, value)
}

func writeProviderToken(w http.ResponseWriter, tokens ProviderTokens) {
	writeJSON(w, http.StatusOK, map[string]any{
		"accessToken": tokens.AccessToken, "tokenType": "Bearer",
		"accessTokenExpiresAt": nullableTimeValue(tokens.AccessTokenExpiresAt),
		"scope":                tokens.Scope,
	})
}
