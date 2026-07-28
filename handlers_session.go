package betterauth

import (
	"errors"
	"net/http"
)

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
	_, _, raw, err := s.sessionFromRequest(r.Context(), r)
	if err == nil {
		_ = s.store.RevokeSession(r.Context(), HashToken(raw), s.cfg.Clock.Now().UTC())
	}
	s.clearSessionCookie(w)
	writeJSON(w, http.StatusOK, map[string]bool{"success": true})
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

func (s *Server) handleRevokeSession(w http.ResponseWriter, r *http.Request) error {
	if err := s.requireCSRF(r); err != nil {
		return err
	}
	_, _, raw, err := s.sessionFromRequest(r.Context(), r)
	if err != nil {
		return err
	}
	if err := s.store.RevokeSession(r.Context(), HashToken(raw), s.cfg.Clock.Now().UTC()); err != nil {
		return publicError(CodeInternal, "Session could not be revoked.", http.StatusInternalServerError, err)
	}
	s.clearSessionCookie(w)
	writeJSON(w, http.StatusOK, map[string]bool{"success": true})
	return nil
}
