package scim

import (
	"encoding/json"
	"testing"
)

func TestPatchOperationsSupportWritableUserFields(t *testing.T) {
	t.Parallel()
	active := true
	input := UserInput{
		UserName: "old@example.com", ExternalID: "old-id",
		Name:   &Name{Formatted: "Old Name"},
		Emails: []Email{{Value: "old@example.com", Primary: true}}, Active: &active,
	}
	err := applyPatchOperations(&input, []PatchOperation{
		{Operation: "replace", Path: "userName", Value: "new@example.com"},
		{Operation: "replace", Path: "externalId", Value: "new-id"},
		{Operation: "replace", Path: "name.givenName", Value: "New"},
		{Operation: "replace", Path: "name.familyName", Value: "Person"},
		{Operation: "replace", Path: "active", Value: false},
	})
	if err != nil {
		t.Fatal(err)
	}
	if input.UserName != "new@example.com" || input.ExternalID != "new-id" ||
		input.Name.Formatted != "" || input.Name.GivenName != "New" ||
		input.Name.FamilyName != "Person" || input.Active == nil || *input.Active {
		t.Fatalf("patched input = %#v", input)
	}
}

func FuzzPatchOperations(f *testing.F) {
	f.Add("replace", "userName", `"user@example.com"`)
	f.Add("remove", "externalId", `null`)
	f.Add("add", "name.givenName", `"Ada"`)
	f.Fuzz(func(t *testing.T, operation, path, raw string) {
		var value any
		if json.Unmarshal([]byte(raw), &value) != nil {
			value = raw
		}
		active := true
		input := UserInput{
			UserName: "user@example.com", Active: &active,
			Emails: []Email{{Value: "user@example.com", Primary: true}},
		}
		_ = applyPatchOperations(&input, []PatchOperation{{
			Operation: operation, Path: path, Value: value,
		}})
	})
}

func FuzzSCIMUserJSON(f *testing.F) {
	f.Add(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"user@example.com"}`)
	f.Add(`{"userName":42}`)
	f.Add(`null`)
	validator := userInputValidator()
	f.Fuzz(func(t *testing.T, raw string) {
		var value any
		if json.Unmarshal([]byte(raw), &value) != nil {
			return
		}
		_ = validator.Validate(value)
	})
}
