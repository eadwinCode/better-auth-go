package scim

import (
	"net/http"
	"strconv"
	"strings"

	betterauth "github.com/eadwinCode/better-auth-go"
)

func (instance *runtime) serviceProviderConfig(
	_ *betterauth.HookContext,
) (*betterauth.PluginResponse, error) {
	return scimJSON(http.StatusOK, map[string]any{
		"schemas":          []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
		"documentationUri": "https://datatracker.ietf.org/doc/html/rfc7644",
		"patch":            map[string]bool{"supported": true},
		"bulk":             map[string]any{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
		"filter":           map[string]any{"supported": true, "maxResults": instance.config.MaxPageSize},
		"changePassword":   map[string]bool{"supported": false},
		"sort":             map[string]bool{"supported": false},
		"etag":             map[string]bool{"supported": false},
		"authenticationSchemes": []map[string]any{{
			"type": "oauthbearertoken", "name": "Bearer Token",
			"description": "SCIM bearer token", "specUri": "https://www.rfc-editor.org/info/rfc6750",
			"primary": true,
		}},
	})
}

func (instance *runtime) schemas(
	context *betterauth.HookContext,
) (*betterauth.PluginResponse, error) {
	resource := userSchema(context.BaseURL)
	return scimJSON(http.StatusOK, listResponse([]any{resource}))
}

func (instance *runtime) getSchema(
	context *betterauth.HookContext,
) (*betterauth.PluginResponse, error) {
	if context.Params["schemaId"] != SchemaUser {
		return scimError(http.StatusNotFound, "", "Resource not found.")
	}
	return scimJSON(http.StatusOK, userSchema(context.BaseURL))
}

func (instance *runtime) resourceTypes(
	context *betterauth.HookContext,
) (*betterauth.PluginResponse, error) {
	resource := userResourceType(context.BaseURL)
	return scimJSON(http.StatusOK, listResponse([]any{resource}))
}

func (instance *runtime) resourceType(
	context *betterauth.HookContext,
) (*betterauth.PluginResponse, error) {
	if !strings.EqualFold(context.Params["resourceTypeId"], "User") {
		return scimError(http.StatusNotFound, "", "Resource not found.")
	}
	return scimJSON(http.StatusOK, userResourceType(context.BaseURL))
}

func listResponse(resources []any) map[string]any {
	return map[string]any{
		"schemas": []string{SchemaListResponse}, "totalResults": len(resources),
		"startIndex": 1, "itemsPerPage": len(resources), "Resources": resources,
	}
}

func userSchema(baseURL string) map[string]any {
	return map[string]any{
		"schemas": []string{SchemaSchema}, "id": SchemaUser, "name": "User",
		"description": "User Account",
		"attributes": []map[string]any{
			{"name": "id", "type": "string", "multiValued": false, "required": false,
				"caseExact": true, "mutability": "readOnly", "returned": "default", "uniqueness": "server"},
			{"name": "userName", "type": "string", "multiValued": false, "required": true,
				"caseExact": false, "mutability": "readWrite", "returned": "default", "uniqueness": "server"},
			{"name": "externalId", "type": "string", "multiValued": false, "required": false,
				"caseExact": true, "mutability": "readWrite", "returned": "default", "uniqueness": "none"},
			{"name": "displayName", "type": "string", "multiValued": false, "required": false,
				"caseExact": true, "mutability": "readOnly", "returned": "default", "uniqueness": "none"},
			{"name": "active", "type": "boolean", "multiValued": false, "required": false,
				"mutability": "readWrite", "returned": "default"},
			{"name": "name", "type": "complex", "multiValued": false, "required": false,
				"mutability": "readWrite", "returned": "default"},
			{"name": "emails", "type": "complex", "multiValued": true, "required": false,
				"mutability": "readWrite", "returned": "default", "uniqueness": "none"},
		},
		"meta": map[string]any{
			"resourceType": "Schema",
			"location":     strings.TrimRight(baseURL, "/") + "/scim/v2/Schemas/" + SchemaUser,
		},
	}
}

func userResourceType(baseURL string) map[string]any {
	return map[string]any{
		"schemas": []string{SchemaResourceType}, "id": "User", "name": "User",
		"endpoint": "/Users", "description": "User Account", "schema": SchemaUser,
		"meta": map[string]any{
			"resourceType": "ResourceType",
			"location":     strings.TrimRight(baseURL, "/") + "/scim/v2/ResourceTypes/User",
		},
	}
}

func scimJSON(status int, value any) (*betterauth.PluginResponse, error) {
	response, err := betterauth.JSONResponse(status, value)
	if err == nil {
		response.Headers.Set("Content-Type", "application/scim+json; charset=utf-8")
		response.Headers.Set("Cache-Control", "no-store")
	}
	return response, err
}

func scimError(status int, scimType, detail string) (*betterauth.PluginResponse, error) {
	return scimJSON(status, SCIMError{
		Schemas: []string{SchemaError}, Status: strconv.Itoa(status),
		SCIMType: scimType, Detail: detail,
	})
}
