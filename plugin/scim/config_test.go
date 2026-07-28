package scim

import (
	"testing"

	betterauth "github.com/eadwinCode/better-auth-go"
)

func TestNewContributesHashOnlyProviderSchemaAndMetadataEndpoints(t *testing.T) {
	t.Parallel()
	plugin, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	if plugin.ID != "scim" {
		t.Fatalf("plugin id = %q", plugin.ID)
	}
	model, exists := plugin.Schema[ModelSCIMProvider]
	if !exists {
		t.Fatal("scimProvider schema is missing")
	}
	for _, field := range []string{
		"id", "providerId", "tokenHash", "organizationId", "userId",
		"createdAt", "updatedAt", "lastUsedAt", "expiresAt",
	} {
		if _, exists = model.Fields[field]; !exists {
			t.Fatalf("schema field %q is missing", field)
		}
	}
	if model.Fields["tokenHash"].Returned {
		t.Fatal("token hash must never be returned")
	}
	if !model.Fields["providerId"].Unique || !model.Fields["tokenHash"].Unique {
		t.Fatal("provider id and token hash must be unique")
	}
	if len(plugin.Endpoints) != 5 {
		t.Fatalf("metadata endpoints = %d", len(plugin.Endpoints))
	}
}

func TestNewRejectsRawOrReservedDefaultConnections(t *testing.T) {
	t.Parallel()
	for _, connection := range []DefaultConnection{
		{ProviderID: "credential", TokenHash: betterauth.HashToken("secret")},
		{ProviderID: "directory", TokenHash: "raw-token"},
	} {
		if _, err := New(Config{
			DefaultConnections: []DefaultConnection{connection},
		}); err == nil {
			t.Fatalf("accepted invalid connection %#v", connection)
		}
	}
}

func TestNewRequiresAuthorizerForOrganizationConnection(t *testing.T) {
	t.Parallel()
	_, err := New(Config{
		DefaultConnections: []DefaultConnection{{
			ProviderID: "directory", TokenHash: betterauth.HashToken("secret"),
			OrganizationID: "org",
		}},
	})
	if err == nil {
		t.Fatal("expected missing organization authorizer to fail")
	}
}

func TestExistingUserLinkingRequiresExplicitConstraint(t *testing.T) {
	t.Parallel()
	if _, err := New(Config{
		LinkExistingUsers: ExistingUserLinkPolicy{Enabled: true},
	}); err == nil {
		t.Fatal("unconstrained existing-user linking was accepted")
	}
	if _, err := New(Config{
		LinkExistingUsers: ExistingUserLinkPolicy{
			Enabled: true, TrustedDomains: []string{"example.com"},
		},
	}); err != nil {
		t.Fatalf("constrained existing-user linking failed: %v", err)
	}
}

type stubOrganizationAuthorizer struct{}

func (stubOrganizationAuthorizer) AuthorizeSCIMConnection(
	*betterauth.HookContext, string,
) error {
	return nil
}

func (stubOrganizationAuthorizer) IsSCIMMember(
	*betterauth.HookContext, string, string,
) (bool, error) {
	return true, nil
}

func (stubOrganizationAuthorizer) AddSCIMMember(
	*betterauth.HookContext, string, string,
) error {
	return nil
}

func (stubOrganizationAuthorizer) RemoveSCIMMember(
	*betterauth.HookContext, string, string,
) error {
	return nil
}

var _ OrganizationAuthorizer = stubOrganizationAuthorizer{}
