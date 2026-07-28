# ADR 0006: Organization, membership, invitation, team, and access-control contract

- Status: Accepted
- Date: 2026-07-28
- Scope: isolated `plugin/organization` pull request

## Context

Better Auth v1.6's organization plugin is a tenant-authorization subsystem, not
just an organization CRUD table. It includes memberships, invitations, active
organization/team session state, teams, built-in and dynamic roles, permission
checks, server-only direct membership, lifecycle hooks, limits, and mail
delivery.

Every identifier in this domain is attacker-controlled. Authorization must be
derived from the authenticated user's current membership in the target
organization, never from a role, organization ID, member ID, team ID, or email
supplied by the request.

## Decision

### Better Auth-shaped surface

The plugin implements these HTTP groups:

- organization: create, check slug, list, set active, get full, update, delete;
- invitations: invite, accept, reject, cancel, get, list for organization, list
  for current user;
- members: list, remove, update role, get active member/role, leave;
- permissions: check/has permission;
- dynamic roles: create, delete, list, get, update;
- teams: create, list, update, remove, set active, list user teams, list team
  members, add team member, remove team member.

Direct member creation remains a server-only `Manager` operation and is never
mounted over HTTP.

### Data model

The plugin contributes `organization`, `member`, `invitation`, `team`,
`teamMember`, and `organizationRole` models, and adds `activeOrganizationId` and
`activeTeamId` to sessions.

Required uniqueness:

- organization slug is globally unique;
- one membership exists per organization/user pair;
- one pending invitation exists per organization/normalized-email pair;
- team names are unique within an organization;
- one team membership exists per team/user pair;
- dynamic role names are unique within an organization.

Compound uniqueness that cannot be expressed by the generic single-field
schema is installed explicitly by MongoDB and SQL adapter migration helpers.

### Authorization

Default roles are `owner`, `admin`, and `member`. Roles are stored as a
canonical sorted comma-separated set for Better Auth compatibility. The native
authorization engine compiles immutable resource/action statements and grants:

- owner: every built-in organization, member, invitation, team, and access
  control action;
- admin: organization update/read, member/invitation/team management, and access
  control read, but not organization deletion or owner assignment/removal;
- member: organization/member/team read and self-leave.

Applications may add immutable static roles and resource/action statements.
Dynamic roles are organization-scoped, bounded in count, validated against the
same statement vocabulary, and cannot grant permissions the acting member does
not possess.

Every organization-scoped endpoint resolves the target first, then loads the
actor membership for that exact organization and evaluates permission. Active
session state is a convenience default only; it never substitutes for the
target-scoped membership check.

Owner invariants are transactional:

- an organization always retains at least one owner;
- the final owner cannot leave, be removed, or lose the owner role;
- non-owners cannot assign or remove the owner role;
- organization deletion requires owner permission.

### Invitations

Invitation emails are normalized before lookup. Tokens/IDs are random and
unguessable; invitation lookup never authorizes acceptance by ID alone.
Acceptance requires an authenticated user whose normalized verified account
email matches the invitation email. Status transitions are guarded and
one-winner: pending to accepted, rejected, canceled, or expired.

Creating/resending an invitation applies organization and per-email limits,
validates every assigned role and optional team in the same organization, and
uses an injectable delivery port. Delivery occurs only after durable creation;
failures are surfaced without exposing membership or account existence.

### Teams

Teams and team memberships are always constrained by organization. Adding a
team member requires an existing organization membership. Active team changes
require both current organization membership and team membership; changing or
clearing the active organization clears an incompatible active team.

### Session state

Setting active organization/team rotates the current session with guarded
expected-old values. Removing a user or team clears incompatible active state
across that user's sessions. Authorization always rechecks durable membership,
so stale session metadata cannot preserve access.

### Requests, hooks, limits, and audit

Cookie-authenticated mutations require trusted origin and CSRF. Destructive or
privilege-changing operations require a fresh session. Configurable hooks run
before and after organization, member, invitation, team, and role mutations;
callbacks are request-scoped, concurrency-safe, and cannot bypass core
authorization or owner invariants.

Creation, deletion, membership/role changes, invitation transitions, team
changes, dynamic-role changes, and active-context changes produce durable audit
events without invitation tokens or private metadata.

All list endpoints have bounded pagination. Organization/member/invitation/team
and role counts have fail-closed configured maxima and transactional checks.

## Compatibility notes

HTTP paths and primary request/response shapes follow Better Auth v1.6.
Native Go intentionally strengthens:

- fresh-session requirements for destructive/privilege-changing mutations;
- verified-email binding for invitation acceptance;
- transactional last-owner and compound-uniqueness invariants;
- durable audits for tenant authorization changes;
- server-only direct member addition;
- authorization rechecks instead of trusting active session metadata.

## Verification plan

- black-box organization, active context, invitation, member, team, permission,
  and dynamic-role flows;
- cross-tenant ID substitution for every mutation family;
- last-owner, duplicate slug/member/invitation/team/role, invitation race,
  stale session, unverified/mismatched email, and privilege-escalation failures;
- concurrent creation/acceptance/owner-change one-winner tests;
- hook ordering and fail-closed callback tests;
- SQLite/PostgreSQL/MongoDB compound index and cascade/transaction tests;
- fuzzing for slug, role-set, permission, pagination, and invitation parsing;
- full test, vet, race, static, fuzz, and vulnerability gates.

