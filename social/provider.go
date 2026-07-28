// Package social provides Better Auth-compatible built-in OAuth2/OIDC provider
// presets and a generic provider constructor.
package social

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	AuthorizationParams map[string]string
	HTTPClient          *http.Client
	Timeout             time.Duration
	MaxResponseBytes    int64
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
	mapper                ProfileMapper
	httpClient            *http.Client
	maxResponseBytes      int64
}

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
	mapper := definition.mapper
	if options.ProfileMapper != nil {
		mapper = options.ProfileMapper
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
			audience: clientID, maxResponseBytes: maxResponse,
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
		authorizationExtra:    extra, mapper: mapper, httpClient: &clientCopy, maxResponseBytes: maxResponse,
	}, nil
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
	} else {
		return betterauth.OAuthResult{}, errors.New("social: provider returned no verifiable profile")
	}
	if token.IDToken != "" && p.oidcVerifier != nil {
		claims, verifyErr := p.oidcVerifier.Verify(ctx, token.IDToken, nonce)
		if verifyErr != nil {
			return betterauth.OAuthResult{}, verifyErr
		}
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
	tokens := betterauth.ProviderTokens{
		AccessToken: token.AccessToken, RefreshToken: token.RefreshToken,
		IDToken: token.IDToken, Scope: token.Scope,
	}
	if token.ExpiresIn > 0 {
		tokens.AccessTokenExpiresAt = time.Now().UTC().Add(time.Duration(token.ExpiresIn) * time.Second)
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
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	}
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
		result.AccessTokenExpiresAt = time.Now().UTC().Add(time.Duration(token.ExpiresIn) * time.Second)
	}
	return result, nil
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
