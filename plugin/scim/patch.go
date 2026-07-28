package scim

import (
	"errors"
	"fmt"
	"strings"
)

func applyPatchOperations(input *UserInput, operations []PatchOperation) error {
	if input == nil {
		return errors.New("scim: patch target is nil")
	}
	for _, operation := range operations {
		op := strings.ToLower(strings.TrimSpace(operation.Operation))
		path := normalizePatchPath(operation.Path)
		if path == "" {
			object, ok := operation.Value.(map[string]any)
			if !ok || op == "remove" {
				return errors.New("scim: pathless patch requires an object")
			}
			for key, value := range object {
				if err := applyPatchValue(input, op, normalizePatchPath(key), value); err != nil {
					return err
				}
			}
			continue
		}
		if err := applyPatchValue(input, op, path, operation.Value); err != nil {
			return err
		}
	}
	return nil
}

func applyPatchValue(input *UserInput, operation, path string, value any) error {
	remove := operation == "remove"
	switch path {
	case "active":
		if remove {
			return errors.New("scim: active cannot be removed")
		}
		active, ok := value.(bool)
		if !ok {
			return errors.New("scim: active must be boolean")
		}
		input.Active = &active
	case "username":
		if remove {
			return errors.New("scim: userName cannot be removed")
		}
		username, ok := value.(string)
		if !ok {
			return errors.New("scim: userName must be string")
		}
		input.UserName = username
		if len(input.Emails) == 1 && input.Emails[0].Primary {
			input.Emails[0].Value = username
		}
	case "externalid":
		if remove {
			input.ExternalID = ""
			return nil
		}
		externalID, ok := value.(string)
		if !ok {
			return errors.New("scim: externalId must be string")
		}
		input.ExternalID = externalID
	case "name":
		if remove {
			input.Name = nil
			return nil
		}
		object, ok := value.(map[string]any)
		if !ok {
			return errors.New("scim: name must be object")
		}
		for key, nested := range object {
			if err := applyPatchValue(input, operation, "name."+strings.ToLower(key), nested); err != nil {
				return err
			}
		}
	case "name.formatted", "name.givenname", "name.familyname":
		if input.Name == nil {
			input.Name = &Name{}
		}
		text := ""
		if !remove {
			var ok bool
			text, ok = value.(string)
			if !ok {
				return fmt.Errorf("scim: %s must be string", path)
			}
		}
		switch path {
		case "name.formatted":
			input.Name.Formatted = text
		case "name.givenname":
			input.Name.Formatted = ""
			input.Name.GivenName = text
		case "name.familyname":
			input.Name.Formatted = ""
			input.Name.FamilyName = text
		}
	case "emails":
		if remove {
			input.Emails = nil
			return nil
		}
		emails, err := patchEmails(value)
		if err != nil {
			return err
		}
		if operation == "add" {
			input.Emails = append(input.Emails, emails...)
		} else {
			input.Emails = emails
		}
	case "emails.value":
		if remove {
			input.Emails = nil
			return nil
		}
		email, ok := value.(string)
		if !ok {
			return errors.New("scim: emails.value must be string")
		}
		input.Emails = []Email{{Value: email, Primary: true}}
	default:
		return errors.New("scim: unsupported patch path")
	}
	return nil
}

func patchEmails(value any) ([]Email, error) {
	values, ok := value.([]any)
	if !ok {
		if object, objectOK := value.(map[string]any); objectOK {
			values = []any{object}
		} else {
			return nil, errors.New("scim: emails must be an array")
		}
	}
	result := make([]Email, 0, len(values))
	for _, item := range values {
		object, ok := item.(map[string]any)
		if !ok {
			return nil, errors.New("scim: email must be an object")
		}
		value, ok := object["value"].(string)
		if !ok {
			return nil, errors.New("scim: email value must be string")
		}
		primary, _ := object["primary"].(bool)
		result = append(result, Email{Value: value, Primary: primary})
	}
	return result, nil
}

func normalizePatchPath(value string) string {
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(value, "/")
	value = strings.ReplaceAll(value, "/", ".")
	return strings.ToLower(value)
}
