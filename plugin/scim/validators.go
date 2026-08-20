package scim

import (
	"errors"
	"fmt"
	"net/mail"
	"net/url"
	"strconv"
	"strings"

	betterauth "github.com/eadwinCode/better-auth-go"
)

func scimString(required bool, maximum int) betterauth.FieldValidation {
	minimum := 0
	if required {
		minimum = 1
	}
	return betterauth.FieldValidation{
		Kind: betterauth.ValidationString, Required: required,
		MinLength: minimum, MaxLength: maximum,
	}
}

func generateTokenValidator() betterauth.ObjectValidator {
	return betterauth.ObjectValidator{Fields: map[string]betterauth.FieldValidation{
		"providerId":     scimString(true, 128),
		"organizationId": scimString(false, 512),
	}}
}

func providerIDValidator() betterauth.ObjectValidator {
	return betterauth.ObjectValidator{Fields: map[string]betterauth.FieldValidation{
		"providerId": scimString(true, 128),
	}}
}

func listUsersValidator(config Config) betterauth.EndpointValidator {
	base := betterauth.ObjectValidator{Fields: map[string]betterauth.FieldValidation{
		"filter":     scimString(false, config.MaxFilterBytes),
		"startIndex": {Kind: betterauth.ValidationInteger},
		"count":      {Kind: betterauth.ValidationInteger},
	}}
	return betterauth.EndpointValidatorFunc(func(value any) error {
		// Media-type enforcement runs in bearer middleware. A nil decoded value
		// may therefore be an unsupported content type rather than an empty JSON
		// document.
		if value == nil {
			return nil
		}
		if err := base.Validate(value); err != nil {
			return err
		}
		query, _ := value.(url.Values)
		for _, name := range []string{"startIndex", "count"} {
			raw := query.Get(name)
			if raw == "" {
				continue
			}
			number, err := strconv.Atoi(raw)
			if err != nil || number < 0 || (name == "count" && number > config.MaxPageSize) {
				return fmt.Errorf("%s is out of bounds", name)
			}
		}
		return nil
	})
}

func userInputValidator() betterauth.EndpointValidator {
	base := betterauth.ObjectValidator{Fields: map[string]betterauth.FieldValidation{
		"schemas":      {Kind: betterauth.ValidationArray},
		"userName":     scimString(true, 320),
		"externalId":   scimString(false, 512),
		"name":         {Kind: betterauth.ValidationObject, Nullable: true},
		"emails":       {Kind: betterauth.ValidationArray},
		"phoneNumbers": {Kind: betterauth.ValidationArray},
		"addresses":    {Kind: betterauth.ValidationArray},
		"roles":        {Kind: betterauth.ValidationArray},
		"entitlements": {Kind: betterauth.ValidationArray},
		"active":       {Kind: betterauth.ValidationBoolean},
	}}
	return betterauth.EndpointValidatorFunc(func(value any) error {
		if value == nil {
			return nil
		}
		if err := base.Validate(value); err != nil {
			return err
		}
		input, err := decodeUserInput(value)
		if err != nil {
			return err
		}
		_, err = normalizeUserInput(input)
		return err
	})
}

func patchValidator(maxOperations int) betterauth.EndpointValidator {
	base := betterauth.ObjectValidator{Fields: map[string]betterauth.FieldValidation{
		"schemas":    {Kind: betterauth.ValidationArray, Required: true},
		"Operations": {Kind: betterauth.ValidationArray, Required: true},
	}}
	return betterauth.EndpointValidatorFunc(func(value any) error {
		if value == nil {
			return nil
		}
		if err := base.Validate(value); err != nil {
			return err
		}
		request, err := decodePatchRequest(value)
		if err != nil {
			return err
		}
		if len(request.Operations) == 0 || len(request.Operations) > maxOperations {
			return errors.New("operations is out of bounds")
		}
		if !containsFold(request.Schemas, SchemaPatch) {
			return errors.New("PatchOp schema is required")
		}
		for _, operation := range request.Operations {
			switch strings.ToLower(strings.TrimSpace(operation.Operation)) {
			case "add", "replace", "remove":
			default:
				return errors.New("unsupported patch operation")
			}
			if len(operation.Path) > 256 {
				return errors.New("patch path is too large")
			}
		}
		return nil
	})
}

func normalizeUserInput(input UserInput) (UserInput, error) {
	input.UserName = strings.ToLower(strings.TrimSpace(input.UserName))
	input.ExternalID = strings.TrimSpace(input.ExternalID)
	if input.UserName == "" || len(input.UserName) > 320 ||
		len(input.ExternalID) > 512 {
		return input, errors.New("invalid user identity")
	}
	if len(input.Schemas) > 0 && !containsFold(input.Schemas, SchemaUser) {
		return input, errors.New("user schema is required")
	}
	primary := 0
	for index := range input.Emails {
		input.Emails[index].Value = strings.ToLower(strings.TrimSpace(input.Emails[index].Value))
		if input.Emails[index].Value == "" || len(input.Emails[index].Value) > 320 {
			return input, errors.New("invalid email")
		}
		if input.Emails[index].Primary {
			primary++
		}
	}
	if primary > 1 {
		return input, errors.New("multiple primary emails")
	}
	email := primaryEmail(input)
	address, err := mail.ParseAddress(email)
	if err != nil || !strings.EqualFold(address.Address, email) {
		return input, errors.New("invalid email")
	}
	if input.Name != nil {
		input.Name.Formatted = strings.TrimSpace(input.Name.Formatted)
		input.Name.GivenName = strings.TrimSpace(input.Name.GivenName)
		input.Name.FamilyName = strings.TrimSpace(input.Name.FamilyName)
		if len(input.Name.Formatted) > 512 || len(input.Name.GivenName) > 256 ||
			len(input.Name.FamilyName) > 256 {
			return input, errors.New("name is too large")
		}
	}
	return input, nil
}

func containsFold(values []string, wanted string) bool {
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), wanted) {
			return true
		}
	}
	return false
}
