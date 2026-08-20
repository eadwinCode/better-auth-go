// Package social provides Better Auth-compatible built-in OAuth2/OIDC provider
// presets and a generic provider constructor.
package social

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	betterauth "github.com/eadwinCode/better-auth-go"
)

type TokenAuthMethod string

const (
	TokenAuthBody  TokenAuthMethod = "client_secret_post"
	TokenAuthBasic TokenAuthMethod = "client_secret_basic"
	TokenAuthNone  TokenAuthMethod = "none"
)

type ProfileMapper func(map[string]any) (betterauth.OAuthProfile, error)

// AccountSubject resolves the immutable provider-side identifier from the raw
// provider profile. It is required for custom non-OIDC providers; mutable
// local-user mappings must never choose account identity.
type AccountSubject func(map[string]any) (string, error)

// EndpointValidator is called for OIDC discovery and every discovered
// endpoint before a provider is constructed. It lets embedders apply an SSRF
// policy that is stricter than the generic public-address checks.
type EndpointValidator func(context.Context, *url.URL) error

// Options configures a built-in preset. Endpoint overrides are intended for
// self-hosted GitLab, Cognito, Microsoft tenants, Salesforce, and compatible
// private OAuth deployments.
type Options struct {
	ClientID            string
	ClientSecret        string
	ClientKey           string
	Issuer              string
	BaseURL             string
	Tenant              string
	Scopes              []string
	DisableDefaultScope bool
	AuthorizationURL    string
	TokenURL            string
	UserInfoURL         string
	JWKSURL             string
	TokenAuth           TokenAuthMethod
	ProfileMapper       ProfileMapper
	AccountSubject      AccountSubject
	// AccountIssuer overrides the synthetic local:oauth namespace for a
	// custom non-OIDC provider. It must be a stable application-owned value.
	AccountIssuer         string
	AuthorizationParams   map[string]string
	RefreshTokenParams    map[string]string
	EndSessionURL         string
	DisableProviderLogout bool
	PostLogoutRedirectURI string
	HTTPClient            *http.Client
	Timeout               time.Duration
	MaxResponseBytes      int64
	// Clock controls token-expiry and OIDC verification time in deterministic
	// tests. Nil uses the system UTC clock.
	Clock betterauth.Clock
	// DiscoveryURL overrides the standard issuer well-known location.
	DiscoveryURL string
	// ValidateEndpoint validates discovery, authorization, token, user-info,
	// and JWKS URLs before any runtime request can use them.
	ValidateEndpoint EndpointValidator
	// DisableImplicitSignUp requires callers to set requestSignUp for a new
	// account while still allowing returning users to sign in.
	DisableImplicitSignUp bool
	// DisableSignUp permanently prevents this provider from creating users.
	DisableSignUp bool

	oidcDiscovery bool
}

type preset struct {
	id                    string
	authorizationURL      string
	tokenURL              string
	userInfoURL           string
	jwksURL               string
	issuers               []string
	defaultScopes         []string
	tokenAuth             TokenAuthMethod
	pkce                  bool
	oidc                  bool
	clientIDParam         string
	userInfoMethod        string
	userInfoAuthQuery     bool
	userInfoNeedsOpenID   bool
	userInfoBody          string
	userInfoHeaders       map[string]string
	tokenMethod           string
	tokenSecretParam      string
	scopeSeparator        string
	authorizationFragment string
	authorizationExtra    map[string]string
	mapper                ProfileMapper
	claimsValidator       func(map[string]any) error
}

// Provider is immutable after construction and safe for concurrent use.
type Provider struct {
	id                    string
	clientID              string
	clientSecret          string
	authorizationURL      string
	tokenURL              string
	userInfoURL           string
	scopes                []string
	tokenAuth             TokenAuthMethod
	pkce                  bool
	oidcVerifier          *idTokenVerifier
	clientIDParam         string
	userInfoMethod        string
	userInfoAuthQuery     bool
	userInfoNeedsOpenID   bool
	userInfoBody          string
	userInfoHeaders       map[string]string
	tokenMethod           string
	tokenSecretParam      string
	scopeSeparator        string
	authorizationFragment string
	authorizationExtra    map[string]string
	refreshTokenExtra     map[string]string
	endSessionURL         string
	disableProviderLogout bool
	postLogoutRedirectURI string
	mapper                ProfileMapper
	accountSubject        AccountSubject
	accountIssuer         string
	httpClient            *http.Client
	maxResponseBytes      int64
	clock                 betterauth.Clock
	disableImplicitSignUp bool
	disableSignUp         bool
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now().UTC() }

func New(providerID string, options Options) (*Provider, error) {
	definition, err := providerPreset(strings.ToLower(strings.TrimSpace(providerID)), options)
	if err != nil {
		return nil, err
	}
	clientID := options.ClientID
	if definition.clientIDParam == "client_key" && options.ClientKey != "" {
		clientID = options.ClientKey
	}
	if clientID == "" {
		return nil, fmt.Errorf("social: %s client ID is required", definition.id)
	}
	if options.ClientSecret == "" && (definition.tokenAuth != TokenAuthNone || definition.tokenSecretParam != "") {
		return nil, fmt.Errorf("social: %s client secret is required", definition.id)
	}
	if options.AuthorizationURL != "" {
		definition.authorizationURL = options.AuthorizationURL
	}
	if options.TokenURL != "" {
		definition.tokenURL = options.TokenURL
	}
	if options.UserInfoURL != "" {
		definition.userInfoURL = options.UserInfoURL
	}
	if options.JWKSURL != "" {
		definition.jwksURL = options.JWKSURL
	}
	for name, raw := range map[string]string{
		"authorization": definition.authorizationURL,
		"token":         definition.tokenURL,
	} {
		if err := validateEndpoint(raw); err != nil {
			return nil, fmt.Errorf("social: %s %s endpoint: %w", definition.id, name, err)
		}
	}
	if definition.userInfoURL != "" {
		if err := validateEndpoint(definition.userInfoURL); err != nil {
			return nil, fmt.Errorf("social: %s user-info endpoint: %w", definition.id, err)
		}
	}
	timeout := options.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	if timeout < time.Second || timeout > time.Minute {
		return nil, errors.New("social: HTTP timeout is out of bounds")
	}
	maxResponse := options.MaxResponseBytes
	if maxResponse == 0 {
		maxResponse = 1 << 20
	}
	if maxResponse < 4096 || maxResponse > 8<<20 {
		return nil, errors.New("social: max response bytes is out of bounds")
	}
	clock := options.Clock
	if clock == nil {
		clock = systemClock{}
	}
	baseClient := options.HTTPClient
	if baseClient == nil {
		baseClient = &http.Client{}
	}
	clientCopy := *baseClient
	clientCopy.Timeout = timeout
	clientCopy.CheckRedirect = func(*http.Request, []*http.Request) error {
		return errors.New("social: provider redirects are disabled")
	}
	scopes := append([]string(nil), definition.defaultScopes...)
	if options.DisableDefaultScope {
		scopes = nil
	}
	scopes = append(scopes, options.Scopes...)
	extra := cloneMap(definition.authorizationExtra)
	for key, value := range options.AuthorizationParams {
		extra[key] = value
	}
	refreshExtra := cloneMap(options.RefreshTokenParams)
	for _, protected := range []string{
		"grant_type", "refresh_token", "client_id", "client_key", "client_secret",
	} {
		delete(refreshExtra, protected)
	}
	if options.EndSessionURL != "" {
		if err := validateEndpoint(options.EndSessionURL); err != nil {
			return nil, fmt.Errorf("social: %s end-session endpoint: %w", definition.id, err)
		}
	}
	if options.PostLogoutRedirectURI != "" {
		redirect, parseErr := url.Parse(options.PostLogoutRedirectURI)
		if parseErr != nil || redirect == nil || !redirect.IsAbs() ||
			redirect.Scheme != "https" || redirect.Host == "" || redirect.User != nil {
			return nil, fmt.Errorf("social: %s post-logout redirect URI is invalid", definition.id)
		}
		options.PostLogoutRedirectURI = redirect.String()
	}
	mapper := definition.mapper
	if options.ProfileMapper != nil {
		mapper = options.ProfileMapper
	}
	accountSubject := options.AccountSubject
	if accountSubject == nil && !definition.oidc && !isBuiltInProvider(definition.id) {
		return nil, fmt.Errorf("social: custom provider %q requires AccountSubject", definition.id)
	}
	if accountSubject == nil {
		accountSubject = func(profile map[string]any) (string, error) {
			return providerAccountSubject(definition.id, profile)
		}
	}
	accountIssuer := strings.TrimSpace(options.AccountIssuer)
	if accountIssuer == "" && !definition.oidc {
		accountIssuer, err = betterauth.OAuthAccountIssuer(definition.id)
		if err != nil {
			return nil, err
		}
	}
	var verifier *idTokenVerifier
	if definition.oidc {
		if definition.jwksURL == "" {
			return nil, fmt.Errorf("social: %s JWKS URL is required", definition.id)
		}
		if err := validateEndpoint(definition.jwksURL); err != nil {
			return nil, fmt.Errorf("social: %s JWKS endpoint: %w", definition.id, err)
		}
		verifier = &idTokenVerifier{
			client: &clientCopy, jwksURL: definition.jwksURL, issuers: definition.issuers,
			audience: clientID, maxResponseBytes: maxResponse, clock: clock,
			claimsValidator: definition.claimsValidator,
		}
	}
	return &Provider{
		id: definition.id, clientID: clientID, clientSecret: options.ClientSecret,
		authorizationURL: definition.authorizationURL, tokenURL: definition.tokenURL,
		userInfoURL: definition.userInfoURL, scopes: dedupe(scopes), tokenAuth: definition.tokenAuth,
		pkce: definition.pkce, oidcVerifier: verifier, clientIDParam: definition.clientIDParam,
		userInfoMethod: definition.userInfoMethod, userInfoAuthQuery: definition.userInfoAuthQuery,
		userInfoNeedsOpenID: definition.userInfoNeedsOpenID, userInfoBody: definition.userInfoBody,
		userInfoHeaders: cloneMap(definition.userInfoHeaders), tokenMethod: definition.tokenMethod,
		tokenSecretParam: definition.tokenSecretParam, scopeSeparator: definition.scopeSeparator,
		authorizationFragment: definition.authorizationFragment,
		authorizationExtra:    extra, refreshTokenExtra: refreshExtra,
		endSessionURL: options.EndSessionURL, disableProviderLogout: options.DisableProviderLogout,
		postLogoutRedirectURI: options.PostLogoutRedirectURI,
		mapper:                mapper, accountSubject: accountSubject,
		accountIssuer: accountIssuer, httpClient: &clientCopy, maxResponseBytes: maxResponse,
		clock: clock, disableImplicitSignUp: options.DisableImplicitSignUp,
		disableSignUp: options.DisableSignUp,
	}, nil
}

// DisableImplicitSignUp implements betterauth.OAuthProviderSignUpPolicy.
func (p *Provider) DisableImplicitSignUp() bool { return p.disableImplicitSignUp }

// DisableSignUp implements betterauth.OAuthProviderSignUpPolicy.
func (p *Provider) DisableSignUp() bool { return p.disableSignUp }

// NewOIDC discovers and validates a generic OpenID Connect provider before
// constructing an immutable OAuth provider. Issuer is required; explicit
// endpoint options override discovered values only after the discovered
// configuration itself has passed validation.
func NewOIDC(ctx context.Context, providerID string, options Options) (*Provider, error) {
	issuer, err := canonicalIssuer(options.Issuer)
	if err != nil {
		return nil, fmt.Errorf("social: OIDC issuer: %w", err)
	}
	timeout := options.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	if timeout < time.Second || timeout > time.Minute {
		return nil, errors.New("social: HTTP timeout is out of bounds")
	}
	maxResponse := options.MaxResponseBytes
	if maxResponse == 0 {
		maxResponse = 1 << 20
	}
	if maxResponse < 4096 || maxResponse > 8<<20 {
		return nil, errors.New("social: max response bytes is out of bounds")
	}
	baseClient := options.HTTPClient
	if baseClient == nil {
		baseClient = &http.Client{}
	}
	client := *baseClient
	client.Timeout = timeout
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return errors.New("social: provider redirects are disabled")
	}
	var discovery struct {
		Issuer                            string   `json:"issuer"`
		AuthorizationEndpoint             string   `json:"authorization_endpoint"`
		TokenEndpoint                     string   `json:"token_endpoint"`
		UserInfoEndpoint                  string   `json:"userinfo_endpoint"`
		JWKSURI                           string   `json:"jwks_uri"`
		ResponseTypesSupported            []string `json:"response_types_supported"`
		IDTokenSigningAlgorithmsSupported []string `json:"id_token_signing_alg_values_supported"`
		TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
		EndSessionEndpoint                string   `json:"end_session_endpoint"`
	}
	discoveryURL := issuer + "/.well-known/openid-configuration"
	if options.DiscoveryURL != "" {
		discoveryURL = options.DiscoveryURL
	}
	if err := validateOIDCEndpoint(ctx, discoveryURL, issuer, options.ValidateEndpoint); err != nil {
		return nil, fmt.Errorf("social: OIDC discovery endpoint: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/json")
	if err := boundedJSON(&client, request, maxResponse, &discovery); err != nil {
		return nil, fmt.Errorf("social: OIDC discovery: %w", err)
	}
	discoveredIssuer, err := canonicalIssuer(discovery.Issuer)
	if err != nil || discoveredIssuer != issuer {
		return nil, errors.New("social: OIDC discovery issuer mismatch")
	}
	if len(discovery.ResponseTypesSupported) > 0 &&
		!contains(discovery.ResponseTypesSupported, "code") {
		return nil, errors.New("social: OIDC provider does not support authorization code")
	}
	if len(discovery.IDTokenSigningAlgorithmsSupported) > 0 &&
		!contains(discovery.IDTokenSigningAlgorithmsSupported, "RS256") {
		return nil, errors.New("social: OIDC provider does not support RS256")
	}
	for name, endpoint := range map[string]string{
		"authorization": discovery.AuthorizationEndpoint,
		"token":         discovery.TokenEndpoint,
		"JWKS":          discovery.JWKSURI,
	} {
		if err := validateOIDCEndpoint(ctx, endpoint, issuer, options.ValidateEndpoint); err != nil {
			return nil, fmt.Errorf("social: OIDC %s endpoint: %w", name, err)
		}
	}
	if discovery.UserInfoEndpoint != "" {
		if err := validateOIDCEndpoint(
			ctx, discovery.UserInfoEndpoint, issuer, options.ValidateEndpoint,
		); err != nil {
			return nil, fmt.Errorf("social: OIDC user-info endpoint: %w", err)
		}
	}
	if options.AuthorizationURL == "" {
		options.AuthorizationURL = discovery.AuthorizationEndpoint
	}
	if options.TokenURL == "" {
		options.TokenURL = discovery.TokenEndpoint
	}
	if options.UserInfoURL == "" {
		options.UserInfoURL = discovery.UserInfoEndpoint
	}
	if options.JWKSURL == "" {
		options.JWKSURL = discovery.JWKSURI
	}
	if options.EndSessionURL == "" {
		options.EndSessionURL = discovery.EndSessionEndpoint
	}
	if options.TokenAuth == "" {
		switch {
		case contains(discovery.TokenEndpointAuthMethodsSupported, string(TokenAuthBasic)):
			options.TokenAuth = TokenAuthBasic
		case contains(discovery.TokenEndpointAuthMethodsSupported, string(TokenAuthBody)):
			options.TokenAuth = TokenAuthBody
		case contains(discovery.TokenEndpointAuthMethodsSupported, string(TokenAuthNone)):
			options.TokenAuth = TokenAuthNone
		}
	}
	if !options.DisableDefaultScope {
		options.Scopes = append([]string{"openid", "profile", "email"}, options.Scopes...)
	}
	for name, endpoint := range map[string]string{
		"authorization": options.AuthorizationURL,
		"token":         options.TokenURL,
		"JWKS":          options.JWKSURL,
		"user-info":     options.UserInfoURL,
	} {
		if endpoint == "" {
			continue
		}
		if err := validateOIDCEndpoint(
			ctx, endpoint, issuer, options.ValidateEndpoint,
		); err != nil {
			return nil, fmt.Errorf("social: OIDC %s override: %w", name, err)
		}
	}
	options.Issuer = issuer
	options.HTTPClient = &client
	options.oidcDiscovery = true
	return New(providerID, options)
}

func (p *Provider) AuthorizationURL(state, challenge, nonce, redirectURI string) (string, error) {
	destination, err := url.Parse(p.authorizationURL)
	if err != nil {
		return "", err
	}
	query := destination.Query()
	query.Set(p.clientIDParameter(), p.clientID)
	query.Set("redirect_uri", redirectURI)
	query.Set("response_type", "code")
	query.Set("state", state)
	if len(p.scopes) > 0 {
		separator := p.scopeSeparator
		if separator == "" {
			separator = " "
		}
		query.Set("scope", strings.Join(p.scopes, separator))
	}
	if p.pkce {
		query.Set("code_challenge", challenge)
		query.Set("code_challenge_method", "S256")
	}
	if p.oidcVerifier != nil {
		query.Set("nonce", nonce)
	}
	for key, value := range p.authorizationExtra {
		query.Set(key, value)
	}
	destination.RawQuery = query.Encode()
	if p.authorizationFragment != "" {
		destination.Fragment = p.authorizationFragment
	}
	return destination.String(), nil
}

func (p *Provider) Exchange(
	ctx context.Context,
	code string,
	verifier string,
	nonce string,
	redirectURI string,
) (betterauth.OAuthResult, error) {
	token, err := p.exchangeToken(ctx, code, verifier, redirectURI)
	if err != nil {
		return betterauth.OAuthResult{}, err
	}
	var profileData map[string]any
	var verifiedClaims map[string]any
	if p.oidcVerifier != nil && token.IDToken == "" {
		return betterauth.OAuthResult{}, errors.New("social: OIDC provider returned no ID token")
	}
	if p.userInfoURL != "" {
		profileData, err = p.userInfo(ctx, token)
		if err != nil {
			return betterauth.OAuthResult{}, err
		}
	} else if token.IDToken != "" && p.oidcVerifier != nil {
		profileData, err = p.oidcVerifier.Verify(ctx, token.IDToken, nonce)
		if err != nil {
			return betterauth.OAuthResult{}, err
		}
		verifiedClaims = profileData
	} else {
		return betterauth.OAuthResult{}, errors.New("social: provider returned no verifiable profile")
	}
	if p.oidcVerifier != nil {
		claims, verifyErr := p.oidcVerifier.Verify(ctx, token.IDToken, nonce)
		if verifyErr != nil {
			return betterauth.OAuthResult{}, verifyErr
		}
		verifiedClaims = claims
		for key, value := range claims {
			if _, exists := profileData[key]; !exists {
				profileData[key] = value
			}
		}
	}
	profile, err := p.mapper(profileData)
	if err != nil {
		return betterauth.OAuthResult{}, err
	}
	profile.Provider = p.id
	if verifiedClaims != nil {
		profile.Issuer = stringValue(verifiedClaims["iss"])
		if p.id == "microsoft" {
			profile.ProviderAccountID = stringValue(verifiedClaims["oid"])
		} else {
			profile.ProviderAccountID = stringValue(verifiedClaims["sub"])
		}
	} else {
		profile.Issuer = p.accountIssuer
		profile.ProviderAccountID, err = p.accountSubject(profileData)
		if err != nil {
			return betterauth.OAuthResult{}, err
		}
	}
	if strings.TrimSpace(profile.Issuer) == "" || strings.TrimSpace(profile.ProviderAccountID) == "" {
		return betterauth.OAuthResult{}, errors.New("social: provider returned no stable account identity")
	}
	tokens := betterauth.ProviderTokens{
		AccessToken: token.AccessToken, RefreshToken: token.RefreshToken,
		IDToken: token.IDToken, Scope: token.Scope,
	}
	if token.ExpiresIn > 0 {
		tokens.AccessTokenExpiresAt = p.clock.Now().UTC().Add(time.Duration(token.ExpiresIn) * time.Second)
	}
	return betterauth.OAuthResult{Profile: profile, Tokens: tokens}, nil
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	Scope        string `json:"scope"`
	OpenID       string `json:"openid"`
}

func (p *Provider) exchangeToken(ctx context.Context, code, verifier, redirectURI string) (tokenResponse, error) {
	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {redirectURI},
	}
	form.Set(p.clientIDParameter(), p.clientID)
	if p.pkce {
		form.Set("code_verifier", verifier)
	}
	if p.tokenAuth == TokenAuthBody || p.tokenSecretParam != "" {
		secretParam := p.tokenSecretParam
		if secretParam == "" {
			secretParam = "client_secret"
		}
		form.Set(secretParam, p.clientSecret)
	}
	return p.requestToken(ctx, form)
}

// Refresh exchanges a refresh token using the provider's configured token
// endpoint and client authentication method.
func (p *Provider) Refresh(ctx context.Context, refreshToken string) (betterauth.ProviderTokens, error) {
	if strings.TrimSpace(refreshToken) == "" {
		return betterauth.ProviderTokens{}, errors.New("social: refresh token is required")
	}
	form := make(url.Values, len(p.refreshTokenExtra)+3)
	for key, value := range p.refreshTokenExtra {
		form.Set(key, value)
	}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	form.Set(p.clientIDParameter(), p.clientID)
	if p.tokenAuth == TokenAuthBody || p.tokenSecretParam != "" {
		secretParam := p.tokenSecretParam
		if secretParam == "" {
			secretParam = "client_secret"
		}
		form.Set(secretParam, p.clientSecret)
	}
	token, err := p.requestToken(ctx, form)
	if err != nil {
		return betterauth.ProviderTokens{}, err
	}
	result := betterauth.ProviderTokens{
		AccessToken: token.AccessToken, RefreshToken: token.RefreshToken,
		IDToken: token.IDToken, Scope: token.Scope,
	}
	if token.ExpiresIn > 0 {
		result.AccessTokenExpiresAt = p.clock.Now().UTC().Add(time.Duration(token.ExpiresIn) * time.Second)
	}
	return result, nil
}

// EndSessionURL builds a validated OIDC RP-initiated logout URL.
func (p *Provider) EndSessionURL(request betterauth.OAuthEndSessionRequest) (string, error) {
	if p.disableProviderLogout || p.endSessionURL == "" {
		return "", nil
	}
	destination, err := url.Parse(p.endSessionURL)
	if err != nil || destination == nil || !destination.IsAbs() ||
		destination.Scheme != "https" || destination.Host == "" || destination.User != nil {
		return "", errors.New("social: invalid end-session endpoint")
	}
	query := destination.Query()
	if request.IDToken != "" {
		query.Set("id_token_hint", request.IDToken)
	}
	redirectURI := request.PostLogoutRedirectURI
	if redirectURI == "" {
		redirectURI = p.postLogoutRedirectURI
	}
	if redirectURI != "" {
		query.Set("post_logout_redirect_uri", redirectURI)
		query.Set("client_id", p.clientID)
		if request.State != "" {
			query.Set("state", request.State)
		}
	}
	destination.RawQuery = query.Encode()
	return destination.String(), nil
}

func (p *Provider) requestToken(ctx context.Context, form url.Values) (tokenResponse, error) {
	method := p.tokenMethod
	if method == "" {
		method = http.MethodPost
	}
	endpoint := p.tokenURL
	var body io.Reader = strings.NewReader(form.Encode())
	if method == http.MethodGet {
		parsed, parseErr := url.Parse(endpoint)
		if parseErr != nil {
			return tokenResponse{}, parseErr
		}
		parsed.RawQuery = form.Encode()
		endpoint = parsed.String()
		body = nil
	}
	request, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return tokenResponse{}, err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	if p.tokenAuth == TokenAuthBasic {
		request.SetBasicAuth(p.clientID, p.clientSecret)
	}
	var token tokenResponse
	if err := p.doJSON(request, &token); err != nil {
		return tokenResponse{}, fmt.Errorf("social: token exchange: %w", err)
	}
	if token.AccessToken == "" && token.IDToken == "" {
		return tokenResponse{}, errors.New("social: token response contained no token")
	}
	return token, nil
}

func (p *Provider) userInfo(ctx context.Context, token tokenResponse) (map[string]any, error) {
	method := p.userInfoMethod
	if method == "" {
		method = http.MethodGet
	}
	endpoint := p.userInfoURL
	if p.userInfoAuthQuery {
		parsed, err := url.Parse(endpoint)
		if err != nil {
			return nil, err
		}
		query := parsed.Query()
		query.Set("access_token", token.AccessToken)
		if p.userInfoNeedsOpenID {
			query.Set("openid", token.OpenID)
			query.Set("lang", "zh_CN")
		}
		parsed.RawQuery = query.Encode()
		endpoint = parsed.String()
	}
	var body io.Reader
	if p.userInfoBody != "" {
		body = strings.NewReader(p.userInfoBody)
	}
	request, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "better-auth-go/"+betterauth.Version)
	if !p.userInfoAuthQuery {
		request.Header.Set("Authorization", "Bearer "+token.AccessToken)
	}
	for key, value := range p.userInfoHeaders {
		request.Header.Set(key, value)
	}
	var profile map[string]any
	if err := p.doJSON(request, &profile); err != nil {
		return nil, fmt.Errorf("social: user info: %w", err)
	}
	if p.id == "github" && stringValue(profile["email"]) == "" {
		email, verified, emailErr := p.githubEmail(ctx, token.AccessToken)
		if emailErr != nil {
			return nil, emailErr
		}
		profile["email"] = email
		profile["email_verified"] = verified
	}
	return profile, nil
}

func (p *Provider) githubEmail(ctx context.Context, accessToken string) (string, bool, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user/emails", nil)
	if err != nil {
		return "", false, err
	}
	request.Header.Set("Authorization", "Bearer "+accessToken)
	request.Header.Set("Accept", "application/vnd.github+json")
	var values []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := p.doJSON(request, &values); err != nil {
		return "", false, err
	}
	for _, value := range values {
		if value.Primary && value.Verified {
			return value.Email, true, nil
		}
	}
	return "", false, errors.New("social: GitHub returned no primary verified email")
}

func (p *Provider) doJSON(request *http.Request, destination any) error {
	response, err := p.httpClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return fmt.Errorf("provider returned HTTP %d", response.StatusCode)
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, p.maxResponseBytes+1))
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("provider returned trailing JSON")
	}
	return nil
}

func (p *Provider) clientIDParameter() string {
	if p.clientIDParam != "" {
		return p.clientIDParam
	}
	return "client_id"
}

func defaultMapper(data map[string]any) (betterauth.OAuthProfile, error) {
	data = unwrapProfile(data)
	id := firstString(data, "sub", "id", "user_id", "account_id", "open_id", "openid")
	email := firstString(data, "email", "email_address")
	if id == "" {
		return betterauth.OAuthProfile{}, errors.New("social: profile has no stable account ID")
	}
	return betterauth.OAuthProfile{
		ProviderAccountID: id,
		Email:             email,
		EmailVerified:     firstBool(data, "email_verified", "verified_email", "verified"),
		Name:              firstString(data, "name", "display_name", "displayName", "username", "login", "full_name"),
		ImageURL:          firstString(data, "picture", "avatar_url", "avatar", "profile_image_url", "image"),
	}, nil
}

func providerMapper(providerID string) ProfileMapper {
	return func(data map[string]any) (betterauth.OAuthProfile, error) {
		original := data
		profileData := unwrapProfile(data)
		profile, err := defaultMapper(original)
		if err != nil {
			profile = betterauth.OAuthProfile{}
		}
		switch providerID {
		case "atlassian":
			profile.EmailVerified = false
		case "discord":
			profile.Name = firstString(profileData, "global_name", "username")
			profile.ImageURL = firstString(profileData, "image_url")
		case "dropbox":
			if name := nestedMap(profileData, "name"); name != nil {
				profile.Name = firstString(name, "display_name")
			}
			profile.ImageURL = firstString(profileData, "profile_photo_url")
		case "facebook":
			if picture := nestedMap(profileData, "picture", "data"); picture != nil {
				profile.ImageURL = firstString(picture, "url")
			}
		case "figma":
			profile.Name = firstString(profileData, "handle")
			profile.ImageURL = firstString(profileData, "img_url")
			profile.EmailVerified = false
		case "kick":
			profile.ImageURL = firstString(profileData, "profile_picture")
			profile.EmailVerified = false
		case "line":
			profile.ProviderAccountID = firstString(profileData, "sub", "userId")
			profile.Name = firstString(profileData, "name", "displayName")
			profile.ImageURL = firstString(profileData, "picture", "pictureUrl")
			profile.EmailVerified = false
		case "linear":
			profile.ImageURL = firstString(profileData, "avatarUrl")
			profile.EmailVerified = false
		case "naver":
			profile.Name = firstString(profileData, "name", "nickname")
			profile.ImageURL = firstString(profileData, "profile_image")
			profile.EmailVerified = false
		case "notion":
			if person := nestedMap(profileData, "person"); person != nil {
				profile.Email = firstString(person, "email")
			}
			profile.ImageURL = firstString(profileData, "avatar_url")
			profile.EmailVerified = false
		case "polar":
			profile.Name = firstString(profileData, "public_name", "username")
			profile.ImageURL = firstString(profileData, "avatar_url")
		case "railway":
			profile.EmailVerified = false
		case "reddit":
			profile.Name = firstString(profileData, "name")
			profile.Email = profile.ProviderAccountID + "@reddit.invalid"
			profile.EmailVerified = false
			profile.ImageURL = strings.Split(firstString(profileData, "icon_img"), "?")[0]
		case "roblox":
			profile.Name = firstString(profileData, "nickname", "preferred_username")
			profile.Email = firstString(profileData, "preferred_username")
			profile.EmailVerified = false
		case "salesforce":
			if photos := nestedMap(profileData, "photos"); photos != nil {
				profile.ImageURL = firstString(photos, "picture", "thumbnail")
			}
		case "slack":
			profile.ProviderAccountID = firstString(profileData, "https://slack.com/user_id")
			profile.Name = firstString(profileData, "name")
			profile.Email = firstString(profileData, "email")
			profile.EmailVerified = firstBool(profileData, "email_verified")
			profile.ImageURL = firstString(profileData, "picture", "https://slack.com/user_image_512")
		case "spotify":
			profile.Name = firstString(profileData, "display_name")
			profile.ImageURL = firstArrayString(profileData, "images", "url")
			profile.EmailVerified = false
		case "tiktok":
			profile.ProviderAccountID = firstString(profileData, "open_id", "id")
			profile.Name = firstString(profileData, "display_name", "username")
			if profile.Email == "" {
				profile.Email = firstString(profileData, "username")
			}
			profile.ImageURL = firstString(profileData, "avatar_large_url", "avatar_url")
			profile.EmailVerified = false
		case "twitter":
			profile.Name = firstString(profileData, "name")
			if confirmedEmail := firstString(profileData, "confirmed_email"); confirmedEmail != "" {
				profile.Email = confirmedEmail
				profile.EmailVerified = true
			} else {
				profile.Email = firstString(profileData, "username")
				profile.EmailVerified = false
			}
			profile.ImageURL = firstString(profileData, "profile_image_url")
		case "vk":
			profile.Name = strings.TrimSpace(
				firstString(profileData, "first_name") + " " + firstString(profileData, "last_name"),
			)
			profile.EmailVerified = false
		case "wechat":
			profile.ProviderAccountID = firstString(profileData, "unionid", "openid")
			profile.Name = firstString(profileData, "nickname")
			if profile.Email == "" {
				profile.Email = profile.ProviderAccountID + "@wechat.invalid"
			}
			profile.ImageURL = firstString(profileData, "headimgurl")
			profile.EmailVerified = false
		case "zoom":
			profile.Name = firstString(profileData, "display_name")
			profile.ImageURL = firstString(profileData, "pic_url")
		}
		if profile.ProviderAccountID == "" {
			return betterauth.OAuthProfile{}, errors.New("social: profile has no stable account ID")
		}
		return profile, nil
	}
}

func nestedMap(data map[string]any, keys ...string) map[string]any {
	current := data
	for _, key := range keys {
		value, ok := current[key].(map[string]any)
		if !ok {
			return nil
		}
		current = value
	}
	return current
}

func firstArrayString(data map[string]any, arrayKey, valueKey string) string {
	values, _ := data[arrayKey].([]any)
	if len(values) == 0 {
		return ""
	}
	value, _ := values[0].(map[string]any)
	return firstString(value, valueKey)
}

func unwrapProfile(data map[string]any) map[string]any {
	for _, key := range []string{"user", "response", "data"} {
		switch nested := data[key].(type) {
		case map[string]any:
			if key == "data" {
				if user, ok := nested["user"].(map[string]any); ok {
					return user
				}
				if viewer, ok := nested["viewer"].(map[string]any); ok {
					return viewer
				}
			}
			return nested
		case []any:
			if len(nested) > 0 {
				if first, ok := nested[0].(map[string]any); ok {
					return first
				}
			}
		}
	}
	if bot, ok := data["bot"].(map[string]any); ok {
		if owner, ok := bot["owner"].(map[string]any); ok {
			if user, ok := owner["user"].(map[string]any); ok {
				if person, ok := user["person"].(map[string]any); ok {
					user["email"] = person["email"]
				}
				return user
			}
		}
	}
	if account, ok := data["kakao_account"].(map[string]any); ok {
		account["id"] = data["id"]
		if profile, ok := account["profile"].(map[string]any); ok {
			account["name"] = firstString(profile, "nickname")
			account["picture"] = firstString(profile, "profile_image_url", "thumbnail_image_url")
		}
		account["email_verified"] = firstBool(account, "is_email_verified") && firstBool(account, "is_email_valid")
		return account
	}
	return data
}

func firstString(data map[string]any, keys ...string) string {
	for _, key := range keys {
		if value := stringValue(data[key]); value != "" {
			return value
		}
	}
	return ""
}

func stringValue(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case json.Number:
		return typed.String()
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	default:
		return ""
	}
}

func firstBool(data map[string]any, keys ...string) bool {
	for _, key := range keys {
		switch value := data[key].(type) {
		case bool:
			return value
		case string:
			parsed, _ := strconv.ParseBool(value)
			return parsed
		}
	}
	return false
}

func validateEndpoint(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed == nil || !parsed.IsAbs() || parsed.Host == "" {
		return errors.New("must be an absolute URL")
	}
	if parsed.Scheme != "https" {
		isLoopback := parsed.Scheme == "http" &&
			(parsed.Hostname() == "localhost" || parsed.Hostname() == "127.0.0.1" || parsed.Hostname() == "::1")
		if !isLoopback {
			return errors.New("must use HTTPS")
		}
	}
	if parsed.User != nil || parsed.Fragment != "" {
		return errors.New("credentials and fragments are not allowed")
	}
	return nil
}

func canonicalIssuer(raw string) (string, error) {
	if err := validateEndpoint(raw); err != nil {
		return "", err
	}
	parsed, _ := url.Parse(raw)
	if parsed.RawQuery != "" {
		return "", errors.New("query parameters are not allowed")
	}
	return strings.TrimSuffix(parsed.String(), "/"), nil
}

func validateDiscoveredEndpoint(raw, issuer string) error {
	if err := validateEndpoint(raw); err != nil {
		return err
	}
	endpoint, _ := url.Parse(raw)
	issuerURL, _ := url.Parse(issuer)
	endpointIP := net.ParseIP(endpoint.Hostname())
	issuerIP := net.ParseIP(issuerURL.Hostname())
	issuerIsLoopback := issuerIP != nil && issuerIP.IsLoopback()
	if endpointIP != nil && !issuerIsLoopback &&
		(endpointIP.IsLoopback() || endpointIP.IsPrivate() || endpointIP.IsLinkLocalUnicast() ||
			endpointIP.IsLinkLocalMulticast() || endpointIP.IsUnspecified()) {
		return errors.New("private network addresses are not allowed")
	}
	return nil
}

func validateOIDCEndpoint(
	ctx context.Context,
	raw string,
	issuer string,
	validator EndpointValidator,
) error {
	if err := validateDiscoveredEndpoint(raw, issuer); err != nil {
		return err
	}
	if validator == nil {
		return nil
	}
	parsed, _ := url.Parse(raw)
	if err := validator(ctx, parsed); err != nil {
		return err
	}
	return nil
}

func boundedJSON(client *http.Client, request *http.Request, maxResponse int64, destination any) error {
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return fmt.Errorf("provider returned HTTP %d", response.StatusCode)
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, maxResponse+1))
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("provider returned trailing JSON")
	}
	return nil
}

func dedupe(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func cloneMap(input map[string]string) map[string]string {
	result := make(map[string]string, len(input))
	for key, value := range input {
		result[key] = value
	}
	return result
}
