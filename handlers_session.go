package betterauth

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
)

type signOutRequest struct {
	CallbackURL     string `json:"callbackURL,omitempty"`
	DisableRedirect bool   `json:"disableRedirect,omitempty"`
	State           string `json:"state,omitempty"`
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) error {
	session, user, _, err := s.sessionFromRequest(r.Context(), r)
	if err != nil {
		var authErr *Error
		if errors.As(err, &authErr) && authErr.Code == CodeUnauthorized {
			writeJSON(w, http.StatusOK, nil)
			return nil
		}
		return err
	}
	if err := s.ensureCSRFCookie(w, r); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"session": session, "user": user})
	return nil
}

func (s *Server) handleSignOut(w http.ResponseWriter, r *http.Request) error {
	if err := s.requireCSRF(r); err != nil {
		return err
	}
	var input signOutRequest
	if r.ContentLength != 0 {
		if err := s.decodeJSON(w, r, &input); err != nil {
			return err
		}
	}
	if len(input.State) > 1024 {
		return publicError(CodeBadRequest, "Logout state is invalid.", http.StatusBadRequest, nil)
	}
	callbackURL, err := s.allowedRedirect(input.CallbackURL)
	if err != nil {
		return err
	}
	_, user, raw, sessionErr := s.sessionFromRequest(r.Context(), r)
	providerLogoutURL := ""
	if sessionErr == nil {
		accounts, listErr := s.store.ListAccounts(r.Context(), user.ID)
		if listErr == nil {
			for index := len(accounts) - 1; index >= 0; index-- {
				account := accounts[index]
				provider, configured := s.cfg.SocialProviders[account.Provider]
				logoutProvider, supported := provider.(OAuthEndSessionProvider)
				if !configured || !supported {
					continue
				}
				stored, tokenErr := s.store.OAuthAccountTokens(
					r.Context(), user.ID, account.Provider, account.ProviderAccountID,
				)
				if tokenErr != nil {
					continue
				}
				tokens, tokenErr := s.decryptProviderTokens(r.Context(), stored.Tokens)
				if tokenErr != nil {
					continue
				}
				candidate, logoutErr := logoutProvider.EndSessionURL(OAuthEndSessionRequest{
					IDToken: tokens.IDToken, PostLogoutRedirectURI: callbackURL,
					State: input.State,
				})
				if logoutErr != nil || candidate == "" {
					continue
				}
				parsed, parseErr := url.Parse(candidate)
				if parseErr != nil || parsed == nil || parsed.Scheme != "https" ||
					parsed.Host == "" || parsed.User != nil || strings.Contains(parsed.Host, "@") {
					continue
				}
				providerLogoutURL = parsed.String()
				break
			}
		}
	}
	if sessionErr == nil {
		_ = s.store.RevokeSession(r.Context(), HashToken(raw), s.cfg.Clock.Now().UTC())
	}
	s.clearSessionCookie(w)
	response := map[string]any{"success": true}
	if providerLogoutURL != "" {
		response["url"] = providerLogoutURL
		response["redirect"] = !input.DisableRedirect
		if !input.DisableRedirect {
			w.Header().Set("Location", providerLogoutURL)
		}
	}
	writeJSON(w, http.StatusOK, response)
	return nil
}

func (s *Server) handleRefreshSession(w http.ResponseWriter, r *http.Request) error {
	if err := s.requireCSRF(r); err != nil {
		return err
	}
	current, user, raw, err := s.sessionFromRequest(r.Context(), r)
	if err != nil {
		return err
	}
	replacement, replacementRaw, err := s.newSession(user.ID, s.cfg.SessionDuration)
	if err != nil {
		return err
	}
	replacement.ImpersonatorID = current.ImpersonatorID
	replacement.ImpersonationID = current.ImpersonationID
	replacement, err = s.store.RotateSession(r.Context(), HashToken(raw), replacement)
	if err != nil {
		return publicError(CodeUnauthorized, "Authentication required.", http.StatusUnauthorized, err)
	}
	s.setSessionCookie(w, replacementRaw, replacement.ExpiresAt)
	writeJSON(w, http.StatusOK, map[string]any{"session": replacement, "user": user})
	return nil
}
