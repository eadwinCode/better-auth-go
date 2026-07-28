package sso

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	betterauth "github.com/eadwinCode/better-auth-go"
	"github.com/eadwinCode/better-auth-go/social"
)

type doerTransport struct{ doer HTTPDoer }

func (transport doerTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return transport.doer.Do(request)
}

func (instance *runtime) oidcProvider(
	ctx context.Context,
	provider storedProvider,
	clock betterauth.Clock,
) (betterauth.OAuthProvider, error) {
	if provider.OIDC == nil {
		return nil, errors.New("sso: provider is not OIDC")
	}
	config := provider.OIDC
	client := &http.Client{Transport: doerTransport{doer: instance.config.HTTPClient}}
	tokenAuth := social.TokenAuthMethod(config.TokenEndpointAuthentication)
	if tokenAuth == "" {
		tokenAuth = social.TokenAuthBasic
	}
	return social.NewOIDC(ctx, provider.ProviderID, social.Options{
		Issuer: config.Issuer, ClientID: config.ClientID, ClientSecret: config.ClientSecret,
		AuthorizationURL: config.AuthorizationEndpoint,
		TokenURL:         config.TokenEndpoint,
		UserInfoURL:      config.UserInfoEndpoint,
		JWKSURL:          config.JWKSEndpoint,
		DiscoveryURL:     config.DiscoveryEndpoint,
		TokenAuth:        tokenAuth,
		Scopes:           append([]string(nil), config.Scopes...),
		ProfileMapper:    oidcProfileMapper(provider.ProviderID, config.Mapping),
		HTTPClient:       client,
		Timeout:          instance.config.DiscoveryTimeout,
		MaxResponseBytes: instance.config.DiscoveryResponseLimit,
		Clock:            clock,
		ValidateEndpoint: func(ctx context.Context, target *url.URL) error {
			return instance.config.OutboundURLPolicy(ctx, target)
		},
	})
}

func (instance *runtime) validateProvider(
	ctx context.Context,
	registration ProviderRegistration,
) error {
	if registration.OIDC != nil {
		_, err := instance.oidcProvider(ctx, instance.defaultProvider(registration), systemClock{})
		return err
	}
	for _, raw := range []string{
		registration.SAML.EntryPoint,
		registration.SAML.LogoutEndpoint,
		registration.SAML.IDPInitiatedCallbackURL,
	} {
		if raw == "" || strings.HasPrefix(raw, "/") {
			continue
		}
		target, err := url.Parse(raw)
		if err != nil {
			return errors.New("sso: invalid SAML URL")
		}
		if err = instance.config.OutboundURLPolicy(ctx, target); err != nil {
			return err
		}
	}
	sp, err := serviceProvider(
		registration.ProviderID, registration.SAML,
		"https://validation.invalid/api/auth",
	)
	if err != nil {
		return err
	}
	if instance.config.SAML.EnableSingleLogout &&
		registration.SAML.LogoutEndpoint == "" {
		return errors.New("sso: SAML single logout requires a logout endpoint")
	}
	if instance.config.SAML.WantLogoutRequestSigned && sp.Key == nil {
		return errors.New("sso: signed SAML logout requires an SP private key")
	}
	return nil
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now().UTC() }

func oidcProfileMapper(providerID string, mapping OIDCMapping) social.ProfileMapper {
	return func(claims map[string]any) (betterauth.OAuthProfile, error) {
		idField := defaultField(mapping.ID, "sub")
		emailField := defaultField(mapping.Email, "email")
		verifiedField := defaultField(mapping.EmailVerified, "email_verified")
		nameField := defaultField(mapping.Name, "name")
		imageField := defaultField(mapping.Image, "picture")
		id := claimString(claims, idField)
		email := claimString(claims, emailField)
		if id == "" || email == "" {
			return betterauth.OAuthProfile{}, errors.New("sso: OIDC profile is incomplete")
		}
		return betterauth.OAuthProfile{
			Provider: providerID, ProviderAccountID: id, Email: email,
			EmailVerified: claimBool(claims, verifiedField),
			Name:          claimString(claims, nameField),
			ImageURL:      claimString(claims, imageField),
		}, nil
	}
}

func defaultField(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return strings.TrimSpace(value)
}

func claimValue(values map[string]any, path string) any {
	var current any = values
	for _, part := range strings.Split(path, ".") {
		object, ok := current.(map[string]any)
		if !ok {
			return nil
		}
		current = object[part]
	}
	return current
}

func claimString(values map[string]any, path string) string {
	switch value := claimValue(values, path).(type) {
	case string:
		return value
	case json.Number:
		return value.String()
	case float64:
		return strconv.FormatFloat(value, 'f', -1, 64)
	default:
		return ""
	}
}

func claimBool(values map[string]any, path string) bool {
	switch value := claimValue(values, path).(type) {
	case bool:
		return value
	case string:
		result, _ := strconv.ParseBool(value)
		return result
	default:
		return false
	}
}
