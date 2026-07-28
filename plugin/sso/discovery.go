package sso

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

type DiscoveryDocument struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	UserInfoEndpoint                  string   `json:"userinfo_endpoint"`
	JWKSURI                           string   `json:"jwks_uri"`
	ScopesSupported                   []string `json:"scopes_supported"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgorithmsSupported []string `json:"id_token_signing_alg_values_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
}

// DiscoverOIDC fetches and validates an OIDC discovery document using the
// plugin's bounded client and outbound URL policy.
func DiscoverOIDC(
	ctx context.Context,
	client HTTPDoer,
	policy OutboundURLPolicy,
	issuer string,
	limit int64,
) (DiscoveryDocument, error) {
	if client == nil || policy == nil {
		return DiscoveryDocument{}, errors.New("sso: discovery client and URL policy are required")
	}
	issuer = strings.TrimRight(strings.TrimSpace(issuer), "/")
	issuerURL, err := url.Parse(issuer)
	if err != nil || issuerURL.Scheme == "" || issuerURL.Host == "" ||
		issuerURL.RawQuery != "" || issuerURL.Fragment != "" || issuerURL.User != nil {
		return DiscoveryDocument{}, errors.New("sso: invalid OIDC issuer")
	}
	if err = policy(ctx, issuerURL); err != nil {
		return DiscoveryDocument{}, fmt.Errorf("sso: untrusted OIDC issuer: %w", err)
	}
	discoveryURL := *issuerURL
	discoveryURL.Path = strings.TrimRight(discoveryURL.Path, "/") +
		"/.well-known/openid-configuration"
	if err = policy(ctx, &discoveryURL); err != nil {
		return DiscoveryDocument{}, fmt.Errorf("sso: untrusted discovery URL: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL.String(), nil)
	if err != nil {
		return DiscoveryDocument{}, fmt.Errorf("sso: build discovery request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return DiscoveryDocument{}, fmt.Errorf("sso: discovery request failed: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4<<10))
		return DiscoveryDocument{}, fmt.Errorf("sso: discovery returned status %d", response.StatusCode)
	}
	if limit <= 0 {
		limit = defaultDiscoveryLimit
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return DiscoveryDocument{}, fmt.Errorf("sso: read discovery document: %w", err)
	}
	if int64(len(body)) > limit {
		return DiscoveryDocument{}, errors.New("sso: discovery document is too large")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	var document DiscoveryDocument
	if err = decoder.Decode(&document); err != nil {
		return DiscoveryDocument{}, fmt.Errorf("sso: invalid discovery document: %w", err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return DiscoveryDocument{}, errors.New("sso: discovery document has trailing data")
	}
	if document.Issuer != issuer {
		return DiscoveryDocument{}, errors.New("sso: discovery issuer mismatch")
	}
	if document.AuthorizationEndpoint == "" || document.TokenEndpoint == "" ||
		document.JWKSURI == "" {
		return DiscoveryDocument{}, errors.New("sso: discovery document is incomplete")
	}
	for label, raw := range map[string]string{
		"authorization": document.AuthorizationEndpoint,
		"token":         document.TokenEndpoint,
		"jwks":          document.JWKSURI,
		"user-info":     document.UserInfoEndpoint,
	} {
		if raw == "" {
			continue
		}
		target, parseErr := url.Parse(raw)
		if parseErr != nil || target.Scheme == "" || target.Host == "" {
			return DiscoveryDocument{}, fmt.Errorf("sso: invalid %s endpoint", label)
		}
		if policyErr := policy(ctx, target); policyErr != nil {
			return DiscoveryDocument{}, fmt.Errorf(
				"sso: untrusted %s endpoint: %w", label, policyErr,
			)
		}
	}
	if len(document.ResponseTypesSupported) > 0 &&
		!slices.Contains(document.ResponseTypesSupported, "code") {
		return DiscoveryDocument{}, errors.New("sso: provider does not support authorization code")
	}
	if len(document.IDTokenSigningAlgorithmsSupported) > 0 &&
		!hasSafeSigningAlgorithm(document.IDTokenSigningAlgorithmsSupported) {
		return DiscoveryDocument{}, errors.New("sso: provider has no supported ID-token signing algorithm")
	}
	if len(document.TokenEndpointAuthMethodsSupported) > 0 &&
		!slices.Contains(document.TokenEndpointAuthMethodsSupported, "client_secret_basic") &&
		!slices.Contains(document.TokenEndpointAuthMethodsSupported, "client_secret_post") {
		return DiscoveryDocument{}, errors.New("sso: provider has no supported token authentication method")
	}
	return document, nil
}

func hasSafeSigningAlgorithm(values []string) bool {
	for _, value := range values {
		switch value {
		case "RS256", "RS384", "RS512", "ES256", "ES384", "ES512",
			"PS256", "PS384", "PS512", "EdDSA":
			return true
		}
	}
	return false
}
