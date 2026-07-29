package betterauth

import (
	"context"
	"errors"
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
	actorAdmin, err := s.isConfiguredAdmin(r.Context(), actor)
	if err != nil {
		return publicError(CodeForbidden, "Impersonation is not allowed.", http.StatusForbidden, err)
	}
	if s.adminSelectionConfigured() && !actorAdmin {
		return publicError(
			CodeCannotImpersonateUsers, "Impersonation is not allowed.", http.StatusForbidden, nil,
		)
	}
	if err := s.cfg.ImpersonationAuthorizer.CanImpersonate(r.Context(), actor, subject); err != nil {
		return publicError(CodeCannotImpersonateUsers, "Impersonation is not allowed.", http.StatusForbidden, err)
	}
	subjectAdmin, err := s.isConfiguredAdmin(r.Context(), subject)
	if err != nil {
		return publicError(CodeForbidden, "Impersonation is not allowed.", http.StatusForbidden, err)
	}
	if subjectAdmin && !s.cfg.Admin.AllowImpersonatingAdmins {
		return publicError(
			CodeCannotImpersonateAdmins, "Administrators cannot impersonate other administrators.",
			http.StatusForbidden, nil,
		)
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

func (s *Server) adminSelectionConfigured() bool {
	return s.cfg.Admin.RoleResolver != nil || len(s.cfg.Admin.AdminUserIDs) > 0
}

func (s *Server) isConfiguredAdmin(ctx context.Context, user User) (bool, error) {
	for _, id := range s.cfg.Admin.AdminUserIDs {
		if id == user.ID {
			return true, nil
		}
	}
	if len(s.cfg.Admin.AdminUserIDs) > 0 {
		// Better Auth v1.6 gives the explicit ID list precedence over role
		// selection when it is configured.
		return false, nil
	}
	if s.cfg.Admin.RoleResolver == nil {
		return false, nil
	}
	roles, err := s.cfg.Admin.RoleResolver.Roles(ctx, user)
	if err != nil {
		return false, err
	}
	if len(roles) == 0 {
		roles = []string{s.cfg.Admin.DefaultRole}
	}
	for _, raw := range roles {
		role := strings.ToLower(strings.TrimSpace(raw))
		if !validRoleName(role) {
			return false, errors.New("betterauth: admin role resolver returned an invalid role")
		}
		for _, adminRole := range s.cfg.Admin.AdminRoles {
			if role == adminRole {
				return true, nil
			}
		}
	}
	return false, nil
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
