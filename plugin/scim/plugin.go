package scim

import (
	"net/http"
	"strings"
	"time"

	betterauth "github.com/eadwinCode/better-auth-go"
)

func (instance *runtime) plugin() betterauth.Plugin {
	return betterauth.Plugin{
		ID:     "scim",
		Schema: instance.schema,
		Endpoints: []betterauth.PluginEndpoint{
			{
				Name: "getSCIMServiceProviderConfig",
				Path: "/scim/v2/ServiceProviderConfig", Method: http.MethodGet,
				AllowNonKebabPath: true, Handler: instance.serviceProviderConfig,
			},
			{
				Name: "getSCIMSchemas",
				Path: "/scim/v2/Schemas", Method: http.MethodGet,
				AllowNonKebabPath: true, Handler: instance.schemas,
			},
			{
				Name: "getSCIMSchema",
				Path: "/scim/v2/Schemas/:schemaId", Method: http.MethodGet,
				AllowNonKebabPath: true, Handler: instance.getSchema,
			},
			{
				Name: "getSCIMResourceTypes",
				Path: "/scim/v2/ResourceTypes", Method: http.MethodGet,
				AllowNonKebabPath: true, Handler: instance.resourceTypes,
			},
			{
				Name: "getSCIMResourceType",
				Path: "/scim/v2/ResourceTypes/:resourceTypeId", Method: http.MethodGet,
				AllowNonKebabPath: true, Handler: instance.resourceType,
			},
		},
		RateLimits: []betterauth.PluginRateLimitRule{{
			Matcher: func(context *betterauth.HookContext) bool {
				return strings.HasPrefix(context.Path, "/scim/")
			},
			Action: "scim.request", Window: time.Minute, Max: 600,
		}},
	}
}

func baseSchema() betterauth.Schema {
	return betterauth.Schema{
		ModelSCIMProvider: {
			Fields: map[string]betterauth.FieldSchema{
				"id": {
					Type: betterauth.FieldString, Required: true, Unique: true, Returned: true,
				},
				"providerId": {
					Type: betterauth.FieldString, Required: true, Unique: true, Returned: true,
				},
				"tokenHash": {
					Type: betterauth.FieldString, Required: true, Unique: true,
				},
				"organizationId": {
					Type: betterauth.FieldString, Index: true,
					References: "organization", Returned: true,
				},
				"userId": {
					Type: betterauth.FieldString, Index: true,
					References: betterauth.ModelUser, Returned: true,
				},
				"createdAt": {
					Type: betterauth.FieldDate, Required: true, Returned: true,
				},
				"updatedAt": {
					Type: betterauth.FieldDate, Required: true, Returned: true,
				},
				"lastUsedAt": {Type: betterauth.FieldDate, Returned: true},
				"expiresAt":  {Type: betterauth.FieldDate, Returned: true},
			},
			Indexes: []betterauth.IndexSchema{
				{
					Name:   "scim_provider_organization",
					Fields: []string{"organizationId", "providerId"}, Unique: true,
				},
				{
					Name:   "scim_provider_owner",
					Fields: []string{"userId", "providerId"}, Unique: true,
				},
			},
		},
	}
}
