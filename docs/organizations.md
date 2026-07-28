# Organizations

`plugin/organization` implements the Better Auth v1.6 organization, membership,
invitation, team, active-context, permission, and dynamic-role server contract.
It is adapter-independent and contributes its models through the normal merged
schema.

## Configure

```go
import (
	"github.com/eadwinCode/better-auth-go/plugin/organization"
)

organizations, err := organization.New(organization.Config{
	DeliverInvitation: func(
		ctx *betterauth.HookContext,
		invitation organization.Invitation,
		tenant organization.Organization,
		inviter betterauth.User,
	) error {
		return sendOrganizationInvitation(
			ctx.Context, invitation, tenant, inviter,
		)
	},
})
if err != nil {
	return err
}
config.Plugins = append(config.Plugins, organizations)
```

Run the normal SQL migration with `auth.Schema()`, or call MongoDB
`EnsureIndexes(ctx, auth.Schema())`, after adding the plugin. The schema adds
`organization`, `member`, `invitation`, `team`, `teamMember`, and
`organizationRole`, plus `activeOrganizationId` and `activeTeamId` on sessions.

Configuration is immutable and fail-closed. Limits, invitation lifetime,
access-control statements, static roles, hooks, mail delivery, and schema names
can be customized. The defaults provide `owner`, `admin`, and `member`.

## HTTP surface

All paths are mounted below the configured authentication base path:

- organization create, slug check, update, delete, full retrieval, list, and
  active selection;
- member list, removal, role update, active member/role, and self-leave;
- invitation create/resend, accept, reject, cancel, get, organization list,
  and current-user list;
- team create, update, remove, list, active selection, user-team list, and
  team-member add/remove/list;
- permission checks and dynamic-role create, update, delete, get, and list.

The paths match Better Auth v1.6, including
`POST /organization/create`, `POST /organization/invite-member`,
`POST /organization/accept-invitation`, and the corresponding
`/organization/*` management routes.

Cookie-authenticated mutations require a trusted origin and CSRF token.
Destructive and privilege-changing operations additionally require a fresh
session. List routes accept bounded `limit` and `offset` query parameters.
Unknown request fields are rejected.

## Authorization and invariants

Every organization-scoped operation loads the authenticated user's membership
for the exact stored target. An organization, member, invitation, team, or role
identifier supplied by a request is never treated as authorization.

Owner changes, invitation consumption, limit checks, membership changes,
cascades, and their audit records are transactional. The final owner cannot
leave, be removed, or be demoted. A non-owner cannot assign or remove the owner
role. Team membership cannot cross an organization boundary. Dynamic roles
cannot grant permissions the actor does not possess.

Invitation email addresses are canonicalized. Acceptance requires an
authenticated account with a matching verified email, and the guarded pending
transition has a single winner. Delivery occurs only after the invitation is
durable.

Setting an active organization or team rotates the opaque browser session,
persists the selected IDs only on the replacement session, and emits an audit
event. Active state remains a convenience default; every later authorization
decision rechecks durable membership.

## Hooks and provisioning

`BeforeMutation` and `AfterMutation` receive detached `MutationEvent` values for
all organization-domain mutations. More specific organization/member/invitation
creation hooks are also available. Hook failures roll back the domain change
and its audit event.

Use `AfterOrganizationCreate` for idempotent personal-team provisioning. Key
external work by `Organization.ID`, and prefer an outbox or idempotent job
runner when provisioning calls another service.

## Server-only member creation

Direct member creation is deliberately not an HTTP endpoint:

```go
manager, err := organization.NewManager(config)
if err != nil {
	return err
}
authConfig.Plugins = append(authConfig.Plugins, manager.Plugin())

member, err := manager.AddMember(ctx, organization.AddMemberInput{
	Database:       database,
	OrganizationID: organizationID,
	UserID:         userID,
	ActorUserID:    administratorID,
	Roles:          []string{"member"},
	Clock:          clock,      // optional; injectable for deterministic tests
	GenerateID:     generateID, // optional; cryptographically random by default
})
```

The application must authorize this trusted server call. The manager validates
the organization, user, roles, and configured member limit, then commits the
membership and durable actor/subject audit record together.
