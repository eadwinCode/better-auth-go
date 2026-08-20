package scim

import (
	"net/http"
	"strings"

	betterauth "github.com/eadwinCode/better-auth-go"
)

var scimPrimaryAttributes = [...]string{
	"emails", "phoneNumbers", "addresses", "roles", "entitlements",
}

// normalizeSCIMIngress implements the Better Auth v1.7.1 compatibility rule:
// the exact strings "true" and "false" are accepted case-insensitively for
// User.active and the primary subattribute. Whitespace and other truthy values
// deliberately remain invalid.
func (instance *runtime) normalizeSCIMIngress(
	hook *betterauth.HookContext,
) (*betterauth.PluginResponse, error) {
	if hook == nil || hook.Body == nil ||
		!strings.HasPrefix(hook.Path, "/scim/v2/Users") {
		return nil, nil
	}
	switch hook.Request.Method {
	case http.MethodPost, http.MethodPut:
		if object, ok := hook.Body.(map[string]any); ok {
			normalizeSCIMUserBooleans(object)
		}
	case http.MethodPatch:
		if object, ok := hook.Body.(map[string]any); ok {
			normalizeSCIMPatchBooleans(object)
		}
	}
	return nil, nil
}

func normalizeSCIMUserBooleans(object map[string]any) {
	if value, exists := object["active"]; exists {
		object["active"] = scimBoolean(value)
	}
	for _, attribute := range scimPrimaryAttributes {
		normalizePrimaryValues(object[attribute])
	}
}

func normalizeSCIMPatchBooleans(object map[string]any) {
	operations, _ := object["Operations"].([]any)
	if operations == nil {
		operations, _ = object["operations"].([]any)
	}
	for _, raw := range operations {
		operation, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		path, _ := operation["path"].(string)
		path = normalizeSCIMBooleanPath(path)
		if path == "" {
			if value, ok := operation["value"].(map[string]any); ok {
				normalizeSCIMUserBooleans(value)
			}
			continue
		}
		if path == "active" {
			operation["value"] = scimBoolean(operation["value"])
			continue
		}
		for _, attribute := range scimPrimaryAttributes {
			lowerAttribute := strings.ToLower(attribute)
			if path == lowerAttribute {
				normalizePrimaryValues(operation["value"])
				break
			}
			if (strings.HasPrefix(path, lowerAttribute+"[") &&
				strings.HasSuffix(path, "].primary")) || path == lowerAttribute+".primary" {
				operation["value"] = scimBoolean(operation["value"])
				break
			}
		}
	}
}

func normalizeSCIMBooleanPath(path string) string {
	path = strings.ToLower(strings.TrimSpace(path))
	prefix := strings.ToLower(SchemaUser) + ":"
	return strings.TrimPrefix(path, prefix)
}

func normalizePrimaryValues(value any) {
	switch typed := value.(type) {
	case []any:
		for _, item := range typed {
			normalizePrimaryValues(item)
		}
	case map[string]any:
		if primary, exists := typed["primary"]; exists {
			typed["primary"] = scimBoolean(primary)
		}
	}
}

func scimBoolean(value any) any {
	text, ok := value.(string)
	if !ok {
		return value
	}
	switch {
	case strings.EqualFold(text, "true"):
		return true
	case strings.EqualFold(text, "false"):
		return false
	default:
		return value
	}
}
