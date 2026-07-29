// Package sso provides Better Auth-shaped OIDC, OAuth 2.0, and SAML enterprise
// single sign-on.
//
// Stability: Experimental. This package is tested but is outside the
// better-auth-go v1 compatibility guarantee pending pinned differential and
// live enterprise interoperability certification.
package sso

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	betterauth "github.com/eadwinCode/better-auth-go"
	"golang.org/x/net/publicsuffix"
)

const (
	defaultDiscoveryLimit = 256 << 10
	defaultStateTTL       = 5 * time.Minute
)

type Config struct {
	Cipher                      betterauth.TokenCipher
	HTTPClient                  HTTPDoer
	OutboundURLPolicy           OutboundURLPolicy
	OrganizationAuthorizer      OrganizationAuthorizer
	DNSResolver                 DNSResolver
	DefaultProviders            []ProviderRegistration
	ProvisionUser               ProvisionUser
	ProvisionUserOnEveryLogin   bool
	OrganizationProvisioning    OrganizationProvisioning
	DefaultOverrideUserInfo     bool
	DisableImplicitSignUp       bool
	DisableProviderRegistration bool
	ProvidersLimit              int
	RedirectURI                 string
	DomainVerification          bool
	DomainVerificationPrefix    string
	DiscoveryTimeout            time.Duration
	DiscoveryResponseLimit      int64
	StateTTL                    time.Duration
	SAML                        SAMLPolicy
	Schema                      betterauth.ModelSchema
}

type runtime struct {
	config   Config
	schema   betterauth.Schema
	defaults map[string]ProviderRegistration
}

func New(config Config) (betterauth.Plugin, error) {
	normalized, err := normalizeConfig(config)
	if err != nil {
		return betterauth.Plugin{}, err
	}
	schema, err := betterauth.MergeSchema(
		baseSchema(normalized.DomainVerification),
		betterauth.Schema{ModelSSOProvider: cloneModelSchema(normalized.Schema)},
	)
	if err != nil {
		return betterauth.Plugin{}, fmt.Errorf("sso: schema: %w", err)
	}
	defaults := make(map[string]ProviderRegistration, len(normalized.DefaultProviders))
	for _, provider := range normalized.DefaultProviders {
		defaults[provider.ProviderID] = provider
	}
	return (&runtime{config: normalized, schema: schema, defaults: defaults}).plugin(), nil
}

func normalizeConfig(config Config) (Config, error) {
	if config.Cipher == nil {
		return config, errors.New("sso: provider configuration cipher is required")
	}
	if config.DiscoveryTimeout == 0 {
		config.DiscoveryTimeout = 10 * time.Second
	}
	if config.DiscoveryTimeout < time.Second || config.DiscoveryTimeout > 30*time.Second {
		return config, errors.New("sso: discovery timeout must be between one and thirty seconds")
	}
	if config.DiscoveryResponseLimit == 0 {
		config.DiscoveryResponseLimit = defaultDiscoveryLimit
	}
	if config.DiscoveryResponseLimit < 4<<10 || config.DiscoveryResponseLimit > 1<<20 {
		return config, errors.New("sso: discovery response limit is out of bounds")
	}
	if config.StateTTL == 0 {
		config.StateTTL = defaultStateTTL
	}
	if config.StateTTL < time.Minute || config.StateTTL > 15*time.Minute {
		return config, errors.New("sso: state TTL must be between one and fifteen minutes")
	}
	if config.ProvidersLimit == 0 {
		config.ProvidersLimit = 10
	}
	if config.ProvidersLimit < 1 || config.ProvidersLimit > 1000 {
		return config, errors.New("sso: provider limit is out of bounds")
	}
	if config.DomainVerificationPrefix == "" {
		config.DomainVerificationPrefix = "better-auth-token"
	}
	config.DomainVerificationPrefix = strings.TrimPrefix(
		strings.ToLower(strings.TrimSpace(config.DomainVerificationPrefix)), "_",
	)
	if !validIdentifier(config.DomainVerificationPrefix, 63) {
		return config, errors.New("sso: invalid domain verification prefix")
	}
	if config.DomainVerification && config.DNSResolver == nil {
		return config, errors.New("sso: DNS resolver is required for domain verification")
	}
	if config.OutboundURLPolicy == nil {
		config.OutboundURLPolicy = PublicHTTPSURLPolicy
	}
	if config.HTTPClient == nil {
		config.HTTPClient = newPublicHTTPClient(config.DiscoveryTimeout)
	}
	if config.SAML.RequestTTL == 0 {
		config.SAML.RequestTTL = 5 * time.Minute
	}
	if config.SAML.ClockSkew == 0 {
		config.SAML.ClockSkew = 5 * time.Minute
	}
	if config.SAML.MaxResponseSize == 0 {
		config.SAML.MaxResponseSize = 256 << 10
	}
	if config.SAML.MaxMetadataSize == 0 {
		config.SAML.MaxMetadataSize = 100 << 10
	}
	if config.SAML.LogoutRequestTTL == 0 {
		config.SAML.LogoutRequestTTL = 5 * time.Minute
	}
	if config.SAML.DeprecatedAlgorithms == "" {
		config.SAML.DeprecatedAlgorithms = "reject"
	}
	switch config.SAML.DeprecatedAlgorithms {
	case "reject", "warn", "allow":
	default:
		return config, errors.New("sso: invalid deprecated-algorithm policy")
	}
	if config.SAML.RequestTTL < time.Minute || config.SAML.RequestTTL > 15*time.Minute ||
		config.SAML.LogoutRequestTTL < time.Minute ||
		config.SAML.LogoutRequestTTL > 15*time.Minute ||
		config.SAML.ClockSkew < 0 || config.SAML.ClockSkew > 10*time.Minute ||
		config.SAML.MaxResponseSize < 16<<10 || config.SAML.MaxResponseSize > 2<<20 ||
		config.SAML.MaxMetadataSize < 4<<10 || config.SAML.MaxMetadataSize > 1<<20 {
		return config, errors.New("sso: SAML security configuration is out of bounds")
	}
	// Correlation is enabled by default. IdP-initiated SSO remains explicit.
	config.SAML.EnableInResponseToValidation = true
	if config.RedirectURI != "" {
		parsed, err := url.Parse(config.RedirectURI)
		if err != nil || parsed.Host == "" && !strings.HasPrefix(parsed.Path, "/") ||
			parsed.Host == "" && strings.HasPrefix(parsed.Path, "//") ||
			parsed.User != nil || parsed.Fragment != "" {
			return config, errors.New("sso: invalid shared redirect URI")
		}
	}
	providers := make([]ProviderRegistration, len(config.DefaultProviders))
	seen := make(map[string]struct{}, len(providers))
	for index, provider := range config.DefaultProviders {
		normalized, err := normalizeProvider(provider)
		if err != nil {
			return config, fmt.Errorf("sso: default provider %d: %w", index, err)
		}
		if _, exists := seen[normalized.ProviderID]; exists {
			return config, errors.New("sso: duplicate default provider id")
		}
		if normalized.OrganizationID != "" && config.OrganizationAuthorizer == nil {
			return config, errors.New(
				"sso: organization authorizer is required for organization providers",
			)
		}
		seen[normalized.ProviderID] = struct{}{}
		providers[index] = normalized
	}
	config.DefaultProviders = providers
	config.Schema = cloneModelSchema(config.Schema)
	return config, nil
}

func normalizeProvider(provider ProviderRegistration) (ProviderRegistration, error) {
	provider.ProviderID = strings.ToLower(strings.TrimSpace(provider.ProviderID))
	if !validIdentifier(provider.ProviderID, 128) || reservedProviderID(provider.ProviderID) {
		return provider, errors.New("invalid or reserved provider id")
	}
	domain, err := normalizeDomains(provider.Domain)
	if err != nil {
		return provider, err
	}
	provider.Domain = domain
	provider.OrganizationID = strings.TrimSpace(provider.OrganizationID)
	if (provider.OIDC == nil) == (provider.SAML == nil) {
		return provider, errors.New("exactly one OIDC or SAML configuration is required")
	}
	if provider.OIDC != nil {
		copyConfig := *provider.OIDC
		copyConfig.Scopes = slices.Clone(copyConfig.Scopes)
		copyConfig.Mapping.ExtraFields = cloneStrings(copyConfig.Mapping.ExtraFields)
		copyConfig.Issuer = strings.TrimRight(strings.TrimSpace(copyConfig.Issuer), "/")
		if copyConfig.Issuer == "" {
			copyConfig.Issuer = strings.TrimRight(strings.TrimSpace(provider.Issuer), "/")
		}
		if copyConfig.ClientID == "" || copyConfig.ClientSecret == "" {
			return provider, errors.New("OIDC client id and secret are required")
		}
		issuer, parseErr := url.Parse(copyConfig.Issuer)
		if parseErr != nil || issuer.Scheme == "" || issuer.Host == "" ||
			issuer.User != nil || issuer.RawQuery != "" || issuer.Fragment != "" {
			return provider, errors.New("invalid OIDC issuer")
		}
		provider.Issuer = copyConfig.Issuer
		provider.OIDC = &copyConfig
	}
	if provider.SAML != nil {
		copyConfig := *provider.SAML
		copyConfig.AdditionalParams = cloneStrings(copyConfig.AdditionalParams)
		copyConfig.Mapping.ExtraFields = cloneStrings(copyConfig.Mapping.ExtraFields)
		copyConfig.Issuer = strings.TrimSpace(copyConfig.Issuer)
		if copyConfig.Issuer == "" {
			copyConfig.Issuer = strings.TrimSpace(provider.Issuer)
		}
		if copyConfig.Issuer == "" || copyConfig.EntryPoint == "" ||
			copyConfig.Certificate == "" || copyConfig.SPEntityID == "" {
			return provider, errors.New("incomplete SAML configuration")
		}
		copyConfig.WantAssertionsSigned = true
		provider.Issuer = copyConfig.Issuer
		provider.SAML = &copyConfig
	}
	return provider, nil
}

// PublicHTTPSURLPolicy rejects non-HTTPS, credential-bearing, loopback,
// unspecified, link-local, multicast, and private literal-IP destinations.
// Applications that need private IdPs must provide an explicit replacement.
func PublicHTTPSURLPolicy(_ context.Context, target *url.URL) error {
	if target == nil || target.Scheme != "https" || target.Host == "" ||
		target.User != nil || target.Fragment != "" {
		return errors.New("sso: outbound URL must be an absolute HTTPS URL")
	}
	host := strings.TrimSuffix(strings.ToLower(target.Hostname()), ".")
	if host == "" || host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return errors.New("sso: outbound URL host is not public")
	}
	if ip := net.ParseIP(host); ip != nil && !publicIP(ip) {
		return errors.New("sso: outbound URL address is not public")
	}
	return nil
}

func newPublicHTTPClient(timeout time.Duration) *http.Client {
	dialer := &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy:               nil,
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: timeout,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, fmt.Errorf("sso: invalid outbound address: %w", err)
			}
			addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, fmt.Errorf("sso: resolve outbound host: %w", err)
			}
			var lastErr error
			for _, item := range addresses {
				if !publicIP(item.IP) {
					continue
				}
				connection, dialErr := dialer.DialContext(
					ctx, network, net.JoinHostPort(item.IP.String(), port),
				)
				if dialErr == nil {
					return connection, nil
				}
				lastErr = dialErr
			}
			if lastErr != nil {
				return nil, fmt.Errorf("sso: connect to outbound host: %w", lastErr)
			}
			return nil, errors.New("sso: outbound host resolved only to non-public addresses")
		},
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func publicIP(ip net.IP) bool {
	return ip != nil && !ip.IsLoopback() && !ip.IsUnspecified() && !ip.IsPrivate() &&
		!ip.IsLinkLocalUnicast() && !ip.IsLinkLocalMulticast() && !ip.IsMulticast()
}

func normalizeDomain(value string) (string, error) {
	value = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
	if value == "" || len(value) > 253 || strings.ContainsAny(value, "/:@*") ||
		net.ParseIP(value) != nil {
		return "", errors.New("invalid provider domain")
	}
	for _, label := range strings.Split(value, ".") {
		if !validDNSLabel(label) {
			return "", errors.New("invalid provider domain")
		}
	}
	suffix, _ := publicsuffix.PublicSuffix(value)
	if suffix == value {
		return "", errors.New("provider domain cannot be a public suffix")
	}
	return value, nil
}

func validDNSLabel(value string) bool {
	if value == "" || len(value) > 63 || value[0] == '-' || value[len(value)-1] == '-' {
		return false
	}
	for _, character := range value {
		if character != '-' && (character < 'a' || character > 'z') &&
			(character < '0' || character > '9') {
			return false
		}
	}
	return true
}

func validIdentifier(value string, limit int) bool {
	if value == "" || len(value) > limit {
		return false
	}
	for _, character := range value {
		if character != '-' && character != '_' && character != '.' &&
			(character < 'a' || character > 'z') &&
			(character < '0' || character > '9') {
			return false
		}
	}
	return true
}

func reservedProviderID(value string) bool {
	switch value {
	case "credential", "email-otp", "magic-link", "phone-number", "anonymous",
		"siwe":
		return true
	default:
		return false
	}
}

func cloneStrings(values map[string]string) map[string]string {
	if values == nil {
		return nil
	}
	result := make(map[string]string, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}

func cloneModelSchema(model betterauth.ModelSchema) betterauth.ModelSchema {
	fields := make(map[string]betterauth.FieldSchema, len(model.Fields))
	for name, field := range model.Fields {
		fields[name] = field
	}
	model.Fields = fields
	indexes := make([]betterauth.IndexSchema, len(model.Indexes))
	for index, definition := range model.Indexes {
		definition.Fields = slices.Clone(definition.Fields)
		indexes[index] = definition
	}
	model.Indexes = indexes
	return model
}
