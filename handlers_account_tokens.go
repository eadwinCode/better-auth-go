package betterauth

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"
)

type providerTokenRequest struct {
	// AccountID is the Better Auth account row ID in the v1.7 API.
	AccountID string `json:"accountId,omitempty"`
	// ProviderID retains the pre-1.7 provider/account-subject selector.
	ProviderID string `json:"providerId,omitempty"`
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
		!tokens.AccessTokenExpiresAt.IsZero() && !tokens.AccessTokenExpiresAt.After(s.cfg.Clock.Now().UTC().Add(5*time.Second)) {
		tokens, err = s.refreshProviderAccount(r.Context(), user.ID, stored, tokens)
		if err != nil {
			return err
		}
	}
	writeAccessToken(w, tokens)
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
	writeRefreshedProviderToken(w, stored, tokens)
	return nil
}

func (s *Server) providerAccount(
	ctx context.Context,
	userID string,
	input providerTokenRequest,
) (StoredOAuthAccount, error) {
	providerID := strings.ToLower(strings.TrimSpace(input.ProviderID))
	accountID := strings.TrimSpace(input.AccountID)
	if (providerID == "" && accountID == "") || len(accountID) > 512 ||
		(providerID != "" && (!validProviderID(providerID) || providerID == credentialProvider)) {
		return StoredOAuthAccount{}, publicError(
			CodeBadRequest, "Invalid provider account.", http.StatusBadRequest, nil,
		)
	}
	var (
		account StoredOAuthAccount
		err     error
	)
	if providerID == "" {
		account, err = s.store.OAuthAccountTokensByID(ctx, userID, accountID)
		if err == nil {
			providerID = account.Account.Provider
		}
	} else {
		account, err = s.store.OAuthAccountTokens(ctx, userID, providerID, accountID)
	}
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return StoredOAuthAccount{}, publicError(
				CodeAccountNotFound, "Account not found", http.StatusBadRequest, err,
			)
		}
		return StoredOAuthAccount{}, publicError(
			CodeInternal, "Provider account could not be read.", http.StatusInternalServerError, err,
		)
	}
	if providerID == credentialProvider {
		return StoredOAuthAccount{}, publicError(
			CodeProviderNotSupported, "Provider credential is not supported.",
			http.StatusBadRequest, nil,
		)
	}
	if _, exists := s.cfg.SocialProviders[providerID]; !exists {
		return StoredOAuthAccount{}, publicError(
			CodeProviderNotSupported,
			"Provider "+providerID+" is not supported.",
			http.StatusBadRequest,
			nil,
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
	if !exists {
		return ProviderTokens{}, publicError(
			CodeProviderNotSupported,
			"Provider "+stored.Account.Provider+" is not supported.",
			http.StatusBadRequest,
			nil,
		)
	}
	if !refreshable {
		return ProviderTokens{}, publicError(
			CodeTokenRefreshUnsupported,
			"Provider "+stored.Account.Provider+" does not support token refreshing.",
			http.StatusBadRequest,
			nil,
		)
	}
	if current.RefreshToken == "" ||
		!current.RefreshTokenExpiresAt.IsZero() && !current.RefreshTokenExpiresAt.After(s.cfg.Clock.Now().UTC()) {
		return ProviderTokens{}, publicError(
			CodeRefreshTokenNotFound, "Refresh token not found", http.StatusBadRequest, nil,
		)
	}
	requestContext, cancel := context.WithTimeout(ctx, s.cfg.ProviderTimeout)
	defer cancel()
	refreshed, err := refresher.Refresh(requestContext, current.RefreshToken)
	if err != nil || refreshed.AccessToken == "" {
		return ProviderTokens{}, publicError(
			CodeFailedRefreshToken, "Failed to refresh access token", http.StatusBadRequest, err,
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
	} else {
		refreshed.Scope = mergeOAuthScopes(current.Scope, refreshed.Scope)
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

func writeAccessToken(w http.ResponseWriter, tokens ProviderTokens) {
	response := map[string]any{
		"accessToken": tokens.AccessToken,
		"scopes":      providerScopes(tokens.Scope),
	}
	if !tokens.AccessTokenExpiresAt.IsZero() {
		response["accessTokenExpiresAt"] = tokens.AccessTokenExpiresAt
	}
	if tokens.IDToken != "" {
		response["idToken"] = tokens.IDToken
	}
	writeJSON(w, http.StatusOK, response)
}

func writeRefreshedProviderToken(
	w http.ResponseWriter,
	stored StoredOAuthAccount,
	tokens ProviderTokens,
) {
	response := map[string]any{
		"accessToken": tokens.AccessToken,
		"scope":       tokens.Scope,
		"providerId":  stored.Account.Provider,
		"accountId":   stored.Account.ProviderAccountID,
	}
	if !tokens.AccessTokenExpiresAt.IsZero() {
		response["accessTokenExpiresAt"] = tokens.AccessTokenExpiresAt
	}
	if !tokens.RefreshTokenExpiresAt.IsZero() {
		response["refreshTokenExpiresAt"] = tokens.RefreshTokenExpiresAt
	}
	if tokens.IDToken != "" {
		response["idToken"] = tokens.IDToken
	}
	writeJSON(w, http.StatusOK, response)
}

func providerScopes(scope string) []string {
	if scope == "" {
		return []string{}
	}
	parts := strings.Split(scope, ",")
	if len(parts) == 1 {
		parts = strings.Fields(scope)
	}
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if part = strings.TrimSpace(part); part != "" {
			result = append(result, part)
		}
	}
	return result
}
