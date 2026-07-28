package sso

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	betterauth "github.com/eadwinCode/better-auth-go"
)

func (instance *runtime) plugin() betterauth.Plugin {
	return betterauth.Plugin{
		ID:     "sso",
		Schema: instance.schema,
		Init: func(initContext betterauth.PluginInitContext) (betterauth.PluginInitResult, error) {
			if instance.config.RedirectURI != "" {
				if err := validateRedirectURI(
					instance.config.RedirectURI,
					initContext.BaseURL,
					initContext.TrustedOrigins,
				); err != nil {
					return betterauth.PluginInitResult{}, err
				}
			}
			for _, provider := range instance.defaults {
				if err := instance.validateProvider(
					context.Background(), provider,
				); err != nil {
					return betterauth.PluginInitResult{}, err
				}
			}
			return betterauth.PluginInitResult{}, nil
		},
		RateLimits: []betterauth.PluginRateLimitRule{
			{
				Matcher: func(ctx *betterauth.HookContext) bool {
					return ctx.Path == "/sign-in/sso"
				},
				Action: "sso.sign-in", Window: 10 * time.Minute, Max: 30,
			},
			{
				Matcher: func(ctx *betterauth.HookContext) bool {
					return strings.HasPrefix(ctx.Path, "/sso/callback") ||
						strings.Contains(ctx.Path, "/sso/saml2/")
				},
				Action: "sso.callback", Window: 10 * time.Minute, Max: 60,
			},
		},
		Endpoints: []betterauth.PluginEndpoint{
			{
				Name: "registerSSOProvider", Path: "/sso/register", Method: http.MethodPost,
				Use: []betterauth.RequestHook{
					betterauth.FreshSessionMiddleware, betterauth.CSRFMiddleware,
				},
				BodyValidator: registrationValidator(), Handler: instance.register,
			},
			{
				Name: "listSSOProviders", Path: "/sso/providers", Method: http.MethodGet,
				Use:     []betterauth.RequestHook{betterauth.SessionMiddleware},
				Handler: instance.listProviders,
			},
			{
				Name: "getSSOProvider", Path: "/sso/get-provider", Method: http.MethodGet,
				Use: []betterauth.RequestHook{betterauth.SessionMiddleware},
				QueryValidator: betterauth.ObjectValidator{Fields: map[string]betterauth.FieldValidation{
					"providerId": {
						Kind: betterauth.ValidationString, Required: true,
						MinLength: 1, MaxLength: 128,
					},
				}},
				Handler: instance.getProvider,
			},
			{
				Name: "updateSSOProvider", Path: "/sso/update-provider", Method: http.MethodPost,
				Use: []betterauth.RequestHook{
					betterauth.FreshSessionMiddleware, betterauth.CSRFMiddleware,
				},
				BodyValidator: updateProviderValidator(), Handler: instance.updateProvider,
			},
			{
				Name: "deleteSSOProvider", Path: "/sso/delete-provider", Method: http.MethodPost,
				Use: []betterauth.RequestHook{
					betterauth.FreshSessionMiddleware, betterauth.CSRFMiddleware,
				},
				BodyValidator: providerIDBodyValidator(), Handler: instance.deleteProvider,
			},
			{
				Name: "signInSSO", Path: "/sign-in/sso", Method: http.MethodPost,
				BodyValidator: signInValidator(), Handler: instance.signIn,
			},
			{
				Name: "callbackSSO", Path: "/sso/callback/:providerId",
				Method: http.MethodGet, SkipOriginCheck: true, Handler: instance.oidcCallback,
			},
			{
				Name: "callbackSSOPost", Path: "/sso/callback/:providerId",
				Method: http.MethodPost, SkipOriginCheck: true, Handler: instance.oidcCallback,
			},
			{
				Name: "callbackSSOShared", Path: "/sso/callback",
				Method: http.MethodGet, SkipOriginCheck: true, Handler: instance.oidcCallback,
			},
			{
				Name: "callbackSSOSharedPost", Path: "/sso/callback",
				Method: http.MethodPost, SkipOriginCheck: true, Handler: instance.oidcCallback,
			},
			{
				Name: "samlSPMetadata", Path: "/sso/saml2/sp/metadata",
				Method: http.MethodGet, SkipOriginCheck: true,
				QueryValidator: betterauth.ObjectValidator{Fields: map[string]betterauth.FieldValidation{
					"providerId": {
						Kind: betterauth.ValidationString, Required: true,
						MinLength: 1, MaxLength: 128,
					},
				}},
				Handler: instance.samlMetadata,
			},
			{
				Name: "callbackSSOSAMLGet", Path: "/sso/saml2/callback/:providerId",
				Method: http.MethodGet, SkipOriginCheck: true, Handler: instance.samlCallback,
			},
			{
				Name: "callbackSSOSAMLPost", Path: "/sso/saml2/callback/:providerId",
				Method: http.MethodPost, SkipOriginCheck: true, Handler: instance.samlCallback,
			},
			{
				Name: "samlAssertionConsumer", Path: "/sso/saml2/sp/acs/:providerId",
				Method: http.MethodPost, SkipOriginCheck: true, Handler: instance.samlCallback,
			},
			{
				Name: "samlSingleLogoutGet", Path: "/sso/saml2/sp/slo/:providerId",
				Method: http.MethodGet, SkipOriginCheck: true,
				Handler: instance.samlLogoutCallback,
			},
			{
				Name: "samlSingleLogoutPost", Path: "/sso/saml2/sp/slo/:providerId",
				Method: http.MethodPost, SkipOriginCheck: true,
				Handler: instance.samlLogoutCallback,
			},
			{
				Name: "initiateSAMLLogout", Path: "/sso/saml2/logout/:providerId",
				Method: http.MethodPost,
				Use: []betterauth.RequestHook{
					betterauth.SessionMiddleware, betterauth.CSRFMiddleware,
				},
				BodyValidator: betterauth.ObjectValidator{Fields: map[string]betterauth.FieldValidation{
					"callbackURL": {Kind: betterauth.ValidationString, MaxLength: 2048},
				}},
				Handler: instance.initiateSAMLLogout,
			},
			{
				Name: "requestSSODomainVerification",
				Path: "/sso/request-domain-verification", Method: http.MethodPost,
				Use: []betterauth.RequestHook{
					betterauth.FreshSessionMiddleware, betterauth.CSRFMiddleware,
				},
				BodyValidator: providerIDBodyValidator(),
				Handler:       instance.requestDomainVerification,
			},
			{
				Name: "verifySSODomain", Path: "/sso/verify-domain", Method: http.MethodPost,
				Use: []betterauth.RequestHook{
					betterauth.FreshSessionMiddleware, betterauth.CSRFMiddleware,
				},
				BodyValidator: providerIDBodyValidator(), Handler: instance.verifyDomain,
			},
		},
	}
}

func providerIDBodyValidator() betterauth.ObjectValidator {
	return betterauth.ObjectValidator{Fields: map[string]betterauth.FieldValidation{
		"providerId": {
			Kind: betterauth.ValidationString, Required: true,
			MinLength: 1, MaxLength: 128,
		},
	}}
}

func registrationValidator() betterauth.ObjectValidator {
	return betterauth.ObjectValidator{Fields: map[string]betterauth.FieldValidation{
		"issuer": {
			Kind: betterauth.ValidationString, Required: true,
			MinLength: 1, MaxLength: 2048,
		},
		"domain": {
			Kind: betterauth.ValidationString, Required: true,
			MinLength: 1, MaxLength: 4096,
		},
		"providerId": {
			Kind: betterauth.ValidationString, Required: true,
			MinLength: 1, MaxLength: 128,
		},
		"organizationId": {Kind: betterauth.ValidationString, MaxLength: 512},
		"oidcConfig":     {Kind: betterauth.ValidationObject},
		"samlConfig":     {Kind: betterauth.ValidationObject},
	}}
}

func updateProviderValidator() betterauth.ObjectValidator {
	return betterauth.ObjectValidator{Fields: map[string]betterauth.FieldValidation{
		"providerId": {
			Kind: betterauth.ValidationString, Required: true,
			MinLength: 1, MaxLength: 128,
		},
		"issuer":     {Kind: betterauth.ValidationString, MaxLength: 2048},
		"domain":     {Kind: betterauth.ValidationString, MaxLength: 4096},
		"oidcConfig": {Kind: betterauth.ValidationObject},
		"samlConfig": {Kind: betterauth.ValidationObject},
	}}
}

func signInValidator() betterauth.ObjectValidator {
	return betterauth.ObjectValidator{Fields: map[string]betterauth.FieldValidation{
		"email":      {Kind: betterauth.ValidationString, MaxLength: 254},
		"issuer":     {Kind: betterauth.ValidationString, MaxLength: 2048},
		"providerId": {Kind: betterauth.ValidationString, MaxLength: 128},
		"domain":     {Kind: betterauth.ValidationString, MaxLength: 253},
		"callbackURL": {
			Kind: betterauth.ValidationString, Required: true,
			MinLength: 1, MaxLength: 2048,
		},
		"errorCallbackURL":   {Kind: betterauth.ValidationString, MaxLength: 2048},
		"newUserCallbackURL": {Kind: betterauth.ValidationString, MaxLength: 2048},
		"scopes":             {Kind: betterauth.ValidationArray, MaxLength: 64},
		"loginHint":          {Kind: betterauth.ValidationString, MaxLength: 512},
		"requestSignUp":      {Kind: betterauth.ValidationBoolean},
		"providerType": {
			Kind: betterauth.ValidationString, Enum: []string{"oidc", "saml"},
		},
	}}
}

func baseSchema(domainVerification bool) betterauth.Schema {
	fields := map[string]betterauth.FieldSchema{
		"id": {
			Type: betterauth.FieldString, Required: true, Unique: true, Returned: true,
		},
		"issuer": {
			Type: betterauth.FieldString, Required: true, Returned: true,
		},
		"oidcConfig": {Type: betterauth.FieldString},
		"samlConfig": {Type: betterauth.FieldString},
		"userId": {
			Type: betterauth.FieldString, Required: true, Index: true,
			References: betterauth.ModelUser, Returned: true,
		},
		"providerId": {
			Type: betterauth.FieldString, Required: true, Unique: true, Returned: true,
		},
		"organizationId": {
			Type: betterauth.FieldString, Index: true,
			References: "organization", Returned: true,
		},
		"domain": {
			Type: betterauth.FieldString, Required: true, Index: true, Returned: true,
		},
		"createdAt": {
			Type: betterauth.FieldDate, Required: true, Returned: true,
		},
		"updatedAt": {
			Type: betterauth.FieldDate, Required: true, Returned: true,
		},
	}
	if domainVerification {
		fields["domainVerified"] = betterauth.FieldSchema{
			Type: betterauth.FieldBoolean, Returned: true,
		}
	}
	return betterauth.Schema{
		ModelSSOProvider: {
			Fields: fields,
			Indexes: []betterauth.IndexSchema{{
				Name:   "sso_provider_organization_domain",
				Fields: []string{"organizationId", "domain"},
			}},
		},
	}
}

func validateRedirectURI(value, baseURL string, trusted []string) error {
	target, err := url.Parse(value)
	if err != nil {
		return errors.New("sso: invalid shared redirect URI")
	}
	if !target.IsAbs() {
		if !strings.HasPrefix(target.Path, "/") || strings.HasPrefix(target.Path, "//") {
			return errors.New("sso: shared redirect URI must be same-origin")
		}
		return nil
	}
	if target.Scheme != "https" || target.User != nil || target.Fragment != "" {
		return errors.New("sso: shared redirect URI is not trusted")
	}
	base, err := url.Parse(baseURL)
	if err == nil && sameOrigin(target, base) {
		return nil
	}
	for _, value := range trusted {
		origin, parseErr := url.Parse(value)
		if parseErr == nil && sameOrigin(target, origin) {
			return nil
		}
	}
	return errors.New("sso: shared redirect URI is not trusted")
}

func sameOrigin(left, right *url.URL) bool {
	return left != nil && right != nil &&
		strings.EqualFold(left.Scheme, right.Scheme) &&
		strings.EqualFold(left.Host, right.Host)
}
