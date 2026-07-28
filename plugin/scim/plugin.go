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
				Name: "generateSCIMToken",
				Path: "/scim/generate-token", Method: http.MethodPost,
				Use: []betterauth.RequestHook{
					betterauth.FreshSessionMiddleware, betterauth.CSRFMiddleware,
				},
				BodyValidator: generateTokenValidator(), Handler: instance.generateToken,
			},
			{
				Name: "listSCIMProviderConnections",
				Path: "/scim/list-provider-connections", Method: http.MethodGet,
				Use:     []betterauth.RequestHook{betterauth.SessionMiddleware},
				Handler: instance.listConnections,
			},
			{
				Name: "getSCIMProviderConnection",
				Path: "/scim/get-provider-connection", Method: http.MethodGet,
				Use:            []betterauth.RequestHook{betterauth.SessionMiddleware},
				QueryValidator: providerIDValidator(), Handler: instance.getConnection,
			},
			{
				Name: "deleteSCIMProviderConnection",
				Path: "/scim/delete-provider-connection", Method: http.MethodPost,
				Use: []betterauth.RequestHook{
					betterauth.FreshSessionMiddleware, betterauth.CSRFMiddleware,
				},
				BodyValidator: providerIDValidator(), Handler: instance.deleteConnection,
			},
			{
				Name: "createSCIMUser",
				Path: "/scim/v2/Users", Method: http.MethodPost,
				AllowNonKebabPath: true, SkipOriginCheck: true,
				Use:           []betterauth.RequestHook{instance.authenticateBearer},
				BodyValidator: userInputValidator(), Handler: instance.createUser,
			},
			{
				Name: "listSCIMUsers",
				Path: "/scim/v2/Users", Method: http.MethodGet,
				AllowNonKebabPath: true, SkipOriginCheck: true,
				Use:            []betterauth.RequestHook{instance.authenticateBearer},
				QueryValidator: listUsersValidator(instance.config), Handler: instance.listUsers,
			},
			{
				Name: "getSCIMUser",
				Path: "/scim/v2/Users/:userId", Method: http.MethodGet,
				AllowNonKebabPath: true, SkipOriginCheck: true,
				Use:     []betterauth.RequestHook{instance.authenticateBearer},
				Handler: instance.getUser,
			},
			{
				Name: "updateSCIMUser",
				Path: "/scim/v2/Users/:userId", Method: http.MethodPut,
				AllowNonKebabPath: true, SkipOriginCheck: true,
				Use:           []betterauth.RequestHook{instance.authenticateBearer},
				BodyValidator: userInputValidator(), Handler: instance.replaceUser,
			},
			{
				Name: "patchSCIMUser",
				Path: "/scim/v2/Users/:userId", Method: http.MethodPatch,
				AllowNonKebabPath: true, SkipOriginCheck: true,
				Use:           []betterauth.RequestHook{instance.authenticateBearer},
				BodyValidator: patchValidator(instance.config.MaxPatchOperations),
				Handler:       instance.patchUser,
			},
			{
				Name: "deleteSCIMUser",
				Path: "/scim/v2/Users/:userId", Method: http.MethodDelete,
				AllowNonKebabPath: true, SkipOriginCheck: true,
				Use:     []betterauth.RequestHook{instance.authenticateBearer},
				Handler: instance.deleteUser,
			},
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
		OnResponse: instance.scimResponseHook,
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
		betterauth.ModelAccount: {
			Indexes: []betterauth.IndexSchema{{
				Name: "scim_account_provider_identity", Fields: []string{"providerId", "accountId"},
				Unique: true,
			}},
		},
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
