package betterauth

import (
	"net/http"
	"strings"
)

type impersonateRequest struct {
	UserID string `json:"userId"`
}

func (s *Server) handleImpersonate(w http.ResponseWriter, r *http.Request) error {
	if err := s.requireCSRF(r); err != nil {
		return err
	}
	actorSession, actor, rawActorToken, err := s.sessionFromRequest(r.Context(), r)
	if err != nil {
		return err
	}
	var input impersonateRequest
	if err := s.decodeJSON(w, r, &input); err != nil {
		return err
	}
	input.UserID = strings.TrimSpace(input.UserID)
	if input.UserID == "" || input.UserID == actor.ID {
		return publicError(CodeBadRequest, "Invalid impersonation target.", http.StatusBadRequest, nil)
	}
	if err := s.rateLimit(r.Context(), r, "admin/impersonate-user", actor.ID); err != nil {
		return err
	}
	subject, err := s.store.FindUserByID(r.Context(), input.UserID)
	if err != nil || subject.DisabledAt != nil {
		return publicError(CodeNotFound, "User not found.", http.StatusNotFound, err)
	}
	if err := s.cfg.ImpersonationAuthorizer.CanImpersonate(r.Context(), actor, subject); err != nil {
		return publicError(CodeForbidden, "Impersonation is not allowed.", http.StatusForbidden, err)
	}
	session, raw, err := s.newSession(subject.ID, s.cfg.ImpersonationDuration)
	if err != nil {
		return err
	}
	impersonationID, err := s.newID()
	if err != nil {
		return err
	}
	auditID, err := s.newID()
	if err != nil {
		return err
	}
	session.ImpersonatorID = actor.ID
	session.ImpersonationID = impersonationID
	audit := AuditEvent{
		ID: auditID, SchemaVersion: 1, Action: AuditImpersonationStart,
		ActorUserID: actor.ID, SubjectUserID: subject.ID, SessionID: session.ID,
		OccurredAt: session.CreatedAt, Request: s.requestMetadata(r),
		Details: map[string]string{"actorSessionId": actorSession.ID, "impersonationId": impersonationID},
	}
	session, err = s.store.RotateSessionWithAudit(r.Context(), HashToken(rawActorToken), session, audit)
	if err != nil {
		return publicError(CodeInternal, "Impersonation could not be started.", http.StatusInternalServerError, err)
	}
	s.setSessionCookie(w, raw, session.ExpiresAt)
	writeJSON(w, http.StatusOK, map[string]any{"session": session, "user": subject})
	return nil
}

func (s *Server) handleStopImpersonating(w http.ResponseWriter, r *http.Request) error {
	if err := s.requireCSRF(r); err != nil {
		return err
	}
	impersonatedSession, subject, rawToken, err := s.sessionFromRequest(r.Context(), r)
	if err != nil {
		return err
	}
	if impersonatedSession.ImpersonatorID == "" || impersonatedSession.ImpersonationID == "" {
		return publicError(CodeBadRequest, "No impersonation session is active.", http.StatusBadRequest, nil)
	}
	if err := s.rateLimit(r.Context(), r, "admin/stop-impersonating", impersonatedSession.ImpersonatorID); err != nil {
		return err
	}
	actor, err := s.store.FindUserByID(r.Context(), impersonatedSession.ImpersonatorID)
	if err != nil || actor.DisabledAt != nil {
		return publicError(CodeUnauthorized, "Authentication required.", http.StatusUnauthorized, err)
	}
	replacement, replacementRaw, err := s.newSession(actor.ID, s.cfg.SessionDuration)
	if err != nil {
		return err
	}
	auditID, err := s.newID()
	if err != nil {
		return err
	}
	audit := AuditEvent{
		ID: auditID, SchemaVersion: 1, Action: AuditImpersonationStop,
		ActorUserID: actor.ID, SubjectUserID: subject.ID, SessionID: replacement.ID,
		OccurredAt: replacement.CreatedAt, Request: s.requestMetadata(r),
		Details: map[string]string{
			"impersonatedSessionId": impersonatedSession.ID,
			"impersonationId":       impersonatedSession.ImpersonationID,
		},
	}
	replacement, err = s.store.RotateSessionWithAudit(r.Context(), HashToken(rawToken), replacement, audit)
	if err != nil {
		return publicError(CodeInternal, "Impersonation could not be stopped.", http.StatusInternalServerError, err)
	}
	s.setSessionCookie(w, replacementRaw, replacement.ExpiresAt)
	writeJSON(w, http.StatusOK, map[string]any{"session": replacement, "user": actor})
	return nil
}
