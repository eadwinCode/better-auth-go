package organization

import (
	"errors"
	"net/mail"
	"strings"

	betterauth "github.com/eadwinCode/better-auth-go"
)

func stringRule(required bool, maximum int) betterauth.FieldValidation {
	return betterauth.FieldValidation{
		Kind: betterauth.ValidationString, Required: required,
		MinLength: map[bool]int{true: 1}[required], MaxLength: maximum,
	}
}

func requiredStringField(name string, maximum int) map[string]betterauth.FieldValidation {
	return map[string]betterauth.FieldValidation{name: stringRule(true, maximum)}
}

func objectValidator(fields map[string]betterauth.FieldValidation) betterauth.ObjectValidator {
	return betterauth.ObjectValidator{Fields: fields}
}

func organizationQueryValidator() betterauth.ObjectValidator {
	return objectValidator(map[string]betterauth.FieldValidation{
		"organizationId": stringRule(false, 512),
	})
}

func pagedOrganizationQueryValidator() betterauth.ObjectValidator {
	return objectValidator(map[string]betterauth.FieldValidation{
		"organizationId": stringRule(false, 512),
		"limit":          {Kind: betterauth.ValidationInteger},
		"offset":         {Kind: betterauth.ValidationInteger},
	})
}

func paginationQueryValidator(fields map[string]betterauth.FieldValidation) betterauth.ObjectValidator {
	fields["limit"] = betterauth.FieldValidation{Kind: betterauth.ValidationInteger}
	fields["offset"] = betterauth.FieldValidation{Kind: betterauth.ValidationInteger}
	return objectValidator(fields)
}

func createOrganizationValidator() betterauth.ObjectValidator {
	return objectValidator(map[string]betterauth.FieldValidation{
		"name": stringRule(true, 128), "slug": stringRule(true, 128),
		"logo":     stringRule(false, 2048),
		"metadata": {Kind: betterauth.ValidationObject},
	})
}

func updateOrganizationValidator() betterauth.ObjectValidator {
	return objectValidator(map[string]betterauth.FieldValidation{
		"organizationId": stringRule(true, 512),
		"name":           stringRule(false, 128), "slug": stringRule(false, 128),
		"logo":     {Kind: betterauth.ValidationString, Nullable: true, MaxLength: 2048},
		"metadata": {Kind: betterauth.ValidationObject, Nullable: true},
	})
}

func nullableOrganizationValidator() betterauth.ObjectValidator {
	return objectValidator(map[string]betterauth.FieldValidation{
		"organizationId": {
			Kind: betterauth.ValidationString, Nullable: true, MaxLength: 512,
		},
	})
}

func memberMutationValidator(name string) betterauth.ObjectValidator {
	return objectValidator(map[string]betterauth.FieldValidation{
		name: stringRule(true, 512), "organizationId": stringRule(false, 512),
	})
}

func updateMemberRoleValidator() betterauth.ObjectValidator {
	return objectValidator(map[string]betterauth.FieldValidation{
		"memberId": stringRule(true, 512), "role": stringRule(true, 512),
		"organizationId": stringRule(false, 512),
	})
}

func inviteMemberValidator() betterauth.EndpointValidator {
	base := objectValidator(map[string]betterauth.FieldValidation{
		"email": stringRule(true, 320), "role": stringRule(true, 512),
		"teamId": stringRule(false, 512), "organizationId": stringRule(false, 512),
		"resend": {Kind: betterauth.ValidationBoolean},
	})
	return betterauth.EndpointValidatorFunc(func(value any) error {
		if err := base.Validate(value); err != nil {
			return err
		}
		object, _ := value.(map[string]any)
		email, _ := object["email"].(string)
		address, err := mail.ParseAddress(strings.TrimSpace(email))
		if err != nil || !strings.EqualFold(address.Address, strings.TrimSpace(email)) {
			return errors.New("email is invalid")
		}
		return nil
	})
}

func teamMutationValidator(requireName bool) betterauth.ObjectValidator {
	return objectValidator(map[string]betterauth.FieldValidation{
		"name":           stringRule(requireName, 128),
		"organizationId": stringRule(false, 512),
	})
}

func teamIDValidator() betterauth.ObjectValidator {
	return objectValidator(requiredStringField("teamId", 512))
}

func updateTeamValidator() betterauth.ObjectValidator {
	return objectValidator(map[string]betterauth.FieldValidation{
		"teamId": stringRule(true, 512), "name": stringRule(true, 128),
	})
}

func nullableTeamValidator() betterauth.ObjectValidator {
	return objectValidator(map[string]betterauth.FieldValidation{
		"teamId": {Kind: betterauth.ValidationString, Nullable: true, MaxLength: 512},
	})
}

func teamMemberValidator() betterauth.ObjectValidator {
	return objectValidator(map[string]betterauth.FieldValidation{
		"teamId": stringRule(true, 512), "userId": stringRule(true, 512),
	})
}

func hasPermissionValidator() betterauth.ObjectValidator {
	return objectValidator(map[string]betterauth.FieldValidation{
		"organizationId": stringRule(false, 512),
		"permission":     {Kind: betterauth.ValidationObject, Required: true},
	})
}

func roleCreateValidator() betterauth.ObjectValidator {
	return objectValidator(map[string]betterauth.FieldValidation{
		"organizationId": stringRule(false, 512), "role": stringRule(true, 64),
		"permission": {Kind: betterauth.ValidationObject, Required: true},
	})
}

func roleMutationValidator() betterauth.ObjectValidator {
	return objectValidator(map[string]betterauth.FieldValidation{
		"organizationId": stringRule(false, 512), "role": stringRule(true, 64),
	})
}

func roleUpdateValidator() betterauth.ObjectValidator {
	return objectValidator(map[string]betterauth.FieldValidation{
		"organizationId": stringRule(false, 512), "role": stringRule(true, 64),
		"permission": {Kind: betterauth.ValidationObject, Required: true},
	})
}

func roleQueryValidator() betterauth.ObjectValidator {
	return roleMutationValidator()
}
