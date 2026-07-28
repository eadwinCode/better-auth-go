package organization

import (
	"net/http"
	"strings"
	"time"

	betterauth "github.com/eadwinCode/better-auth-go"
)

func (instance *runtime) plugin() betterauth.Plugin {
	session := []betterauth.RequestHook{betterauth.SessionMiddleware}
	mutation := []betterauth.RequestHook{
		betterauth.SessionMiddleware, betterauth.CSRFMiddleware,
	}
	sensitive := []betterauth.RequestHook{
		betterauth.FreshSessionMiddleware, betterauth.CSRFMiddleware,
	}
	return betterauth.Plugin{
		ID:     "organization",
		Schema: instance.schema,
		Endpoints: []betterauth.PluginEndpoint{
			post("createOrganization", "/organization/create", mutation,
				createOrganizationValidator(), instance.createOrganization),
			post("checkOrganizationSlug", "/organization/check-slug", session,
				objectValidator(requiredStringField("slug", 128)), instance.checkSlug),
			post("updateOrganization", "/organization/update", mutation,
				updateOrganizationValidator(), instance.updateOrganization),
			post("deleteOrganization", "/organization/delete", sensitive,
				objectValidator(requiredStringField("organizationId", 512)), instance.deleteOrganization),
			get("getFullOrganization", "/organization/get-full-organization", session,
				organizationQueryValidator(), instance.getFullOrganization),
			post("setActiveOrganization", "/organization/set-active", mutation,
				nullableOrganizationValidator(), instance.setActiveOrganization),
			get("listOrganizations", "/organization/list", session,
				paginationQueryValidator(map[string]betterauth.FieldValidation{}),
				instance.listOrganizations),

			post("removeMember", "/organization/remove-member", sensitive,
				memberMutationValidator("memberId"), instance.removeMember),
			post("updateMemberRole", "/organization/update-member-role", sensitive,
				updateMemberRoleValidator(), instance.updateMemberRole),
			get("getActiveMember", "/organization/get-active-member", session,
				organizationQueryValidator(), instance.getActiveMember),
			post("leaveOrganization", "/organization/leave", sensitive,
				objectValidator(requiredStringField("organizationId", 512)), instance.leaveOrganization),
			get("listMembers", "/organization/list-members", session,
				pagedOrganizationQueryValidator(), instance.listMembers),
			get("getActiveMemberRole", "/organization/get-active-member-role", session,
				organizationQueryValidator(), instance.getActiveMemberRole),

			post("inviteMember", "/organization/invite-member", mutation,
				inviteMemberValidator(), instance.inviteMember),
			post("acceptInvitation", "/organization/accept-invitation", mutation,
				objectValidator(requiredStringField("invitationId", 512)), instance.acceptInvitation),
			post("rejectInvitation", "/organization/reject-invitation", mutation,
				objectValidator(requiredStringField("invitationId", 512)), instance.rejectInvitation),
			post("cancelInvitation", "/organization/cancel-invitation", mutation,
				objectValidator(requiredStringField("invitationId", 512)), instance.cancelInvitation),
			get("getInvitation", "/organization/get-invitation", session,
				objectValidator(requiredStringField("invitationId", 512)), instance.getInvitation),
			get("listInvitations", "/organization/list-invitations", session,
				pagedOrganizationQueryValidator(), instance.listInvitations),
			get("listUserInvitations", "/organization/list-user-invitations", session,
				paginationQueryValidator(map[string]betterauth.FieldValidation{}),
				instance.listUserInvitations),

			post("createTeam", "/organization/create-team", mutation,
				teamMutationValidator(true), instance.createTeam),
			post("removeTeam", "/organization/remove-team", sensitive,
				teamIDValidator(), instance.removeTeam),
			post("updateTeam", "/organization/update-team", mutation,
				updateTeamValidator(), instance.updateTeam),
			get("listTeams", "/organization/list-teams", session,
				pagedOrganizationQueryValidator(), instance.listTeams),
			post("setActiveTeam", "/organization/set-active-team", mutation,
				nullableTeamValidator(), instance.setActiveTeam),
			get("listUserTeams", "/organization/list-user-teams", session,
				pagedOrganizationQueryValidator(), instance.listUserTeams),
			get("listTeamMembers", "/organization/list-team-members", session,
				paginationQueryValidator(requiredStringField("teamId", 512)),
				instance.listTeamMembers),
			post("addTeamMember", "/organization/add-team-member", mutation,
				teamMemberValidator(), instance.addTeamMember),
			post("removeTeamMember", "/organization/remove-team-member", mutation,
				teamMemberValidator(), instance.removeTeamMember),

			post("hasPermission", "/organization/has-permission", session,
				hasPermissionValidator(), instance.hasPermission),
			post("createOrganizationRole", "/organization/create-role", sensitive,
				roleCreateValidator(), instance.createRole),
			post("deleteOrganizationRole", "/organization/delete-role", sensitive,
				roleMutationValidator(), instance.deleteRole),
			get("listOrganizationRoles", "/organization/list-roles", session,
				pagedOrganizationQueryValidator(), instance.listRoles),
			get("getOrganizationRole", "/organization/get-role", session,
				roleQueryValidator(), instance.getRole),
			post("updateOrganizationRole", "/organization/update-role", sensitive,
				roleUpdateValidator(), instance.updateRole),
		},
		RateLimits: []betterauth.PluginRateLimitRule{{
			Matcher: func(context *betterauth.HookContext) bool {
				return strings.HasPrefix(context.Path, "/organization/") &&
					context.Request != nil && context.Request.Method == http.MethodPost
			},
			Action: "organization.mutation", Window: time.Minute, Max: 60,
			AccountKey: func(context *betterauth.HookContext) string {
				if context.User != nil {
					return context.User.ID
				}
				return ""
			},
		}},
	}
}

func post(
	name, path string,
	use []betterauth.RequestHook,
	validator betterauth.EndpointValidator,
	handler betterauth.PluginEndpointHandler,
) betterauth.PluginEndpoint {
	return betterauth.PluginEndpoint{
		Name: name, Path: path, Method: http.MethodPost,
		Use: use, BodyValidator: validator, Handler: handler,
	}
}

func get(
	name, path string,
	use []betterauth.RequestHook,
	validator betterauth.EndpointValidator,
	handler betterauth.PluginEndpointHandler,
) betterauth.PluginEndpoint {
	return betterauth.PluginEndpoint{
		Name: name, Path: path, Method: http.MethodGet,
		Use: use, QueryValidator: validator, Handler: handler,
	}
}
