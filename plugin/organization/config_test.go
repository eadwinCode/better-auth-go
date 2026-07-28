package organization

import (
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
