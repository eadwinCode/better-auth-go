package organization

import (
	"net/http"
	"testing"
)

func TestOrganizationConfigAndCompoundSchema(t *testing.T) {
	plugin, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	if plugin.ID != "organization" {
		t.Fatalf("unexpected plugin id %q", plugin.ID)
	}
	tests := map[string]string{
		ModelMember:           "member_organization_user_unique",
		ModelInvitation:       "invitation_organization_email_unique",
		ModelTeam:             "team_organization_name_unique",
		ModelTeamMember:       "team_member_team_user_unique",
		ModelOrganizationRole: "organization_role_name_unique",
	}
	for model, expected := range tests {
		indexes := plugin.Schema[model].Indexes
		if len(indexes) != 1 || indexes[0].Name != expected || !indexes[0].Unique {
			t.Fatalf("%s compound indexes: %#v", model, indexes)
		}
	}
}

func TestOrganizationEndpointSurfaceMatchesBetterAuthV1(t *testing.T) {
	plugin, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	expected := map[string]string{
		"/organization/create":                 http.MethodPost,
		"/organization/check-slug":             http.MethodPost,
		"/organization/update":                 http.MethodPost,
		"/organization/delete":                 http.MethodPost,
		"/organization/get-full-organization":  http.MethodGet,
		"/organization/set-active":             http.MethodPost,
		"/organization/list":                   http.MethodGet,
		"/organization/remove-member":          http.MethodPost,
		"/organization/update-member-role":     http.MethodPost,
		"/organization/get-active-member":      http.MethodGet,
		"/organization/leave":                  http.MethodPost,
		"/organization/list-members":           http.MethodGet,
		"/organization/get-active-member-role": http.MethodGet,
		"/organization/invite-member":          http.MethodPost,
		"/organization/accept-invitation":      http.MethodPost,
		"/organization/reject-invitation":      http.MethodPost,
		"/organization/cancel-invitation":      http.MethodPost,
		"/organization/get-invitation":         http.MethodGet,
		"/organization/list-invitations":       http.MethodGet,
		"/organization/list-user-invitations":  http.MethodGet,
		"/organization/create-team":            http.MethodPost,
		"/organization/remove-team":            http.MethodPost,
		"/organization/update-team":            http.MethodPost,
		"/organization/list-teams":             http.MethodGet,
		"/organization/set-active-team":        http.MethodPost,
		"/organization/list-user-teams":        http.MethodGet,
		"/organization/list-team-members":      http.MethodGet,
		"/organization/add-team-member":        http.MethodPost,
		"/organization/remove-team-member":     http.MethodPost,
		"/organization/has-permission":         http.MethodPost,
		"/organization/create-role":            http.MethodPost,
		"/organization/delete-role":            http.MethodPost,
		"/organization/list-roles":             http.MethodGet,
		"/organization/get-role":               http.MethodGet,
		"/organization/update-role":            http.MethodPost,
	}
	if len(plugin.Endpoints) != len(expected) {
		t.Fatalf("endpoint count = %d, want %d", len(plugin.Endpoints), len(expected))
	}
	for _, endpoint := range plugin.Endpoints {
		method, exists := expected[endpoint.Path]
		if !exists || method != endpoint.Method || endpoint.Handler == nil ||
			endpoint.BodyValidator == nil && endpoint.QueryValidator == nil {
			t.Fatalf("unexpected or incomplete endpoint: %#v", endpoint)
		}
		delete(expected, endpoint.Path)
	}
	if len(expected) != 0 {
		t.Fatalf("missing endpoints: %#v", expected)
	}
}

func TestOrganizationAccessDefaultsAndValidation(t *testing.T) {
	instance := &runtime{roles: defaultRoles(defaultStatements())}
	if !instance.staticPermission("owner", "organization", "delete") {
		t.Fatal("owner lost organization deletion")
	}
	if instance.staticPermission("admin", "organization", "delete") {
		t.Fatal("admin gained organization deletion")
	}
	if instance.staticPermission("member", "member", "update") {
		t.Fatal("member gained role mutation")
	}
	if _, err := canonicalRoles([]string{"admin", "member,admin"}); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Config{CreatorRole: "missing"}); err == nil {
		t.Fatal("undefined creator role accepted")
	}
	if _, err := New(Config{
		Roles: map[string]Role{
			"billing": {Permission: Permission{"invoice": {"delete"}}},
		},
	}); err == nil {
		t.Fatal("unknown permission statement accepted")
	}
}
