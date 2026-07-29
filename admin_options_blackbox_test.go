package betterauth_test

import (
	"context"
	"errors"
	"net/http"
	"testing"

	betterauth "github.com/eadwinCode/better-auth-go"
)

type nameAdminRoles struct {
	fail bool
}

func (resolver nameAdminRoles) Roles(
	_ context.Context,
	user betterauth.User,
) ([]string, error) {
	if resolver.fail {
		return nil, errors.New("role backend unavailable")
	}
	if user.Name == "Admin" {
		return []string{"admin"}, nil
	}
	return []string{"user"}, nil
}

func adminOptionsClients(
	t *testing.T,
	allowAdmins bool,
	resolver betterauth.AdminRoleResolver,
) (*testClient, *testClient) {
	t.Helper()
	actor, _ := newBlackBoxServerConfig(t, func(config *betterauth.Config) {
		config.Admin.RoleResolver = resolver
		config.Admin.AllowImpersonatingAdmins = allowAdmins
	})
	target := &testClient{handler: actor.handler, database: actor.database}
	return actor, target
}

func signupAdminOptionUser(
	t *testing.T,
	client *testClient,
	email string,
	name string,
) string {
	t.Helper()
	response := goResponse(client.request(t, http.MethodPost, "/sign-up/email", map[string]any{
		"email": email, "password": "correct horse battery staple", "name": name,
	}, false))
	if response.status != http.StatusOK {
		t.Fatalf("signup status=%d body=%s", response.status, response.body)
	}
	return responseUser(t, response)["id"].(string)
}

func TestAdminOptionsRejectAdminTargetsByDefault(t *testing.T) {
	t.Parallel()
	actor, target := adminOptionsClients(t, false, nameAdminRoles{})
	signupAdminOptionUser(t, actor, "admin-one@example.com", "Admin")
	targetID := signupAdminOptionUser(t, target, "admin-two@example.com", "Admin")
	response := goResponse(actor.request(t, http.MethodPost, "/admin/impersonate-user", map[string]any{
		"userId": targetID,
	}, true))
	if response.status != http.StatusForbidden ||
		decodeObject(t, response.body)["code"] != "YOU_CANNOT_IMPERSONATE_ADMINS" {
		t.Fatalf("admin target was not rejected: status=%d body=%s", response.status, response.body)
	}
}

func TestAdminOptionsCanExplicitlyAllowAdminTargets(t *testing.T) {
	t.Parallel()
	actor, target := adminOptionsClients(t, true, nameAdminRoles{})
	signupAdminOptionUser(t, actor, "allowed-admin-one@example.com", "Admin")
	targetID := signupAdminOptionUser(t, target, "allowed-admin-two@example.com", "Admin")
	response := goResponse(actor.request(t, http.MethodPost, "/admin/impersonate-user", map[string]any{
		"userId": targetID,
	}, true))
	if response.status != http.StatusOK || responseUser(t, response)["id"] != targetID {
		t.Fatalf("explicit admin-target impersonation failed: status=%d body=%s", response.status, response.body)
	}
}

func TestAdminSelectionAndResolverFailuresDenyImpersonation(t *testing.T) {
	t.Parallel()
	t.Run("non-admin actor", func(t *testing.T) {
		actor, target := adminOptionsClients(t, false, nameAdminRoles{})
		signupAdminOptionUser(t, actor, "ordinary@example.com", "Ordinary")
		targetID := signupAdminOptionUser(t, target, "ordinary-target@example.com", "Target")
		response := goResponse(actor.request(t, http.MethodPost, "/admin/impersonate-user", map[string]any{
			"userId": targetID,
		}, true))
		if response.status != http.StatusForbidden ||
			decodeObject(t, response.body)["code"] != "YOU_ARE_NOT_ALLOWED_TO_IMPERSONATE_USERS" {
			t.Fatalf("non-admin selection response=%d %s", response.status, response.body)
		}
	})
	t.Run("resolver failure", func(t *testing.T) {
		actor, target := adminOptionsClients(t, false, nameAdminRoles{fail: true})
		signupAdminOptionUser(t, actor, "resolver@example.com", "Admin")
		targetID := signupAdminOptionUser(t, target, "resolver-target@example.com", "Target")
		response := goResponse(actor.request(t, http.MethodPost, "/admin/impersonate-user", map[string]any{
			"userId": targetID,
		}, true))
		if response.status != http.StatusForbidden {
			t.Fatalf("resolver failure did not deny: %d %s", response.status, response.body)
		}
	})
}

func TestAdminUserIDsAreImmutableAndSelectActors(t *testing.T) {
	t.Parallel()
	const expectedFirstUserID = "test-token-001-0000000000000001"
	adminIDs := []string{expectedFirstUserID}
	actor, _ := newBlackBoxServerConfig(t, func(config *betterauth.Config) {
		config.Admin.AdminUserIDs = adminIDs
	})
	// New must own an immutable copy rather than observing caller mutation.
	adminIDs[0] = "mutated-after-construction"
	target := &testClient{handler: actor.handler, database: actor.database}
	actorID := signupAdminOptionUser(t, actor, "id-admin@example.com", "Ordinary")
	if actorID != expectedFirstUserID {
		t.Fatalf("fixture user ID=%q, want %q", actorID, expectedFirstUserID)
	}
	targetID := signupAdminOptionUser(t, target, "id-target@example.com", "Target")
	response := goResponse(actor.request(t, http.MethodPost, "/admin/impersonate-user", map[string]any{
		"userId": targetID,
	}, true))
	if response.status != http.StatusOK || responseUser(t, response)["id"] != targetID {
		t.Fatalf("explicit admin user ID was not honored: status=%d body=%s", response.status, response.body)
	}
}

func TestAdminUserIDsTakePrecedenceOverResolvedRoles(t *testing.T) {
	t.Parallel()
	actor, _ := newBlackBoxServerConfig(t, func(config *betterauth.Config) {
		config.Admin.AdminUserIDs = []string{"some-other-admin"}
		config.Admin.RoleResolver = nameAdminRoles{}
	})
	target := &testClient{handler: actor.handler, database: actor.database}
	signupAdminOptionUser(t, actor, "precedence-admin@example.com", "Admin")
	targetID := signupAdminOptionUser(t, target, "precedence-target@example.com", "Target")
	response := goResponse(actor.request(t, http.MethodPost, "/admin/impersonate-user", map[string]any{
		"userId": targetID,
	}, true))
	if response.status != http.StatusForbidden ||
		decodeObject(t, response.body)["code"] != "YOU_ARE_NOT_ALLOWED_TO_IMPERSONATE_USERS" {
		t.Fatalf("adminUserIds did not override role selection: status=%d body=%s", response.status, response.body)
	}
}
