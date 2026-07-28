package organization

import (
	"errors"
	"slices"
	"strings"
)

func defaultStatements() map[string][]string {
	return map[string][]string{
		"organization": {"create", "read", "update", "delete"},
		"member":       {"create", "read", "update", "delete"},
		"invitation":   {"create", "read", "cancel"},
		"team":         {"create", "read", "update", "delete"},
		"ac":           {"create", "read", "update", "delete"},
	}
}

func defaultRoles(statements map[string][]string) map[string]Role {
	owner := make(Permission, len(statements))
	for resource, actions := range statements {
		owner[resource] = slices.Clone(actions)
	}
	return map[string]Role{
		"owner": {Permission: owner},
		"admin": {Permission: Permission{
			"organization": {"read", "update"},
			"member":       {"create", "read", "update", "delete"},
			"invitation":   {"create", "read", "cancel"},
			"team":         {"create", "read", "update", "delete"},
			"ac":           {"read"},
		}},
		"member": {Permission: Permission{
			"organization": {"read"}, "member": {"read"}, "team": {"read"},
		}},
	}
}

func normalizePermission(
	input Permission,
	statements map[string][]string,
) (Permission, error) {
	result := make(Permission, len(input))
	for resource, actions := range input {
		resource = strings.ToLower(strings.TrimSpace(resource))
		allowed, exists := statements[resource]
		if !exists || len(actions) == 0 {
			return nil, errors.New("organization: permission references unknown resource")
		}
		normalized := make([]string, len(actions))
		for index, action := range actions {
			action = strings.ToLower(strings.TrimSpace(action))
			if !slices.Contains(allowed, action) {
				return nil, errors.New("organization: permission references unknown action")
			}
			normalized[index] = action
		}
		slices.Sort(normalized)
		result[resource] = slices.Compact(normalized)
	}
	return result, nil
}

func canonicalRoles(values []string) (string, error) {
	var result []string
	for _, value := range values {
		for _, role := range strings.Split(value, ",") {
			role = strings.ToLower(strings.TrimSpace(role))
			if !validRoleName(role) {
				return "", errors.New("organization: invalid role")
			}
			result = append(result, role)
		}
	}
	slices.Sort(result)
	return strings.Join(slices.Compact(result), ","), nil
}

func hasRole(value, role string) bool {
	return slices.Contains(strings.Split(value, ","), role)
}

func (instance *runtime) staticPermission(roles, resource, action string) bool {
	for _, name := range strings.Split(roles, ",") {
		role, exists := instance.roles[name]
		if exists && slices.Contains(role.Permission[resource], action) {
			return true
		}
	}
	return false
}
