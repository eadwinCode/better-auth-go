package sqladapter

import (
	"testing"

	betterauth "github.com/eadwinCode/better-auth-go"
)

func TestPhysicalSchemaPreservesAndMapsCompoundIndexes(t *testing.T) {
	schema, err := physicalSchema(betterauth.Schema{
		"membership": {
			ModelName: "auth_memberships",
			Fields: map[string]betterauth.FieldSchema{
				"id":             {Type: betterauth.FieldString, FieldName: "membership_id"},
				"organizationId": {Type: betterauth.FieldString, FieldName: "organization_id"},
				"userId":         {Type: betterauth.FieldString, FieldName: "user_id"},
			},
			Indexes: []betterauth.IndexSchema{{
				Name: "membership_organization_user_unique",
				Fields: []string{
					"organizationId", "userId",
				},
				Unique: true,
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	model := schema["auth_memberships"]
	if len(model.Indexes) != 1 {
		t.Fatalf("compound indexes were dropped: %#v", model.Indexes)
	}
	index := model.Indexes[0]
	if index.Name != "membership_organization_user_unique" || !index.Unique ||
		len(index.Fields) != 2 || index.Fields[0] != "organization_id" ||
		index.Fields[1] != "user_id" {
		t.Fatalf("compound index was not mapped: %#v", index)
	}
}

func TestPhysicalSchemaRejectsUnknownCompoundIndexField(t *testing.T) {
	_, err := physicalSchema(betterauth.Schema{
		"membership": {
			Fields: map[string]betterauth.FieldSchema{
				"id": {Type: betterauth.FieldString},
			},
			Indexes: []betterauth.IndexSchema{{
				Name: "invalid", Fields: []string{"missing"},
			}},
		},
	})
	if err == nil {
		t.Fatal("unknown compound-index field was accepted")
	}
}
