package sso

import (
	"errors"
	"net/url"
	"strings"

	betterauth "github.com/eadwinCode/better-auth-go"
)

func (instance *runtime) plugin() betterauth.Plugin {
	return betterauth.Plugin{
		ID:     "sso",
		Schema: instance.schema,
		Init: func(context betterauth.PluginInitContext) (betterauth.PluginInitResult, error) {
			if instance.config.RedirectURI == "" {
				return betterauth.PluginInitResult{}, nil
			}
			if err := validateRedirectURI(
				instance.config.RedirectURI, context.BaseURL, context.TrustedOrigins,
			); err != nil {
				return betterauth.PluginInitResult{}, err
			}
			return betterauth.PluginInitResult{}, nil
		},
	}
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
