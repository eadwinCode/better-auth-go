package social

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	betterauth "github.com/eadwinCode/better-auth-go"
)

const fixtureRedirectURI = "https://app.example.com/api/auth/callback/provider"

type capturedRequest struct {
	method string
	path   string
	header http.Header
	form   url.Values
}

// tokenFixture is a provider double that records every token and user-info
// request. userInfo returns the user-info status and JSON body.
type tokenFixture struct {
	server   *httptest.Server
	mu       sync.Mutex
	requests []capturedRequest
}

func newTokenFixture(t *testing.T, userInfo func() (int, any)) *tokenFixture {
	t.Helper()
	fixture := &tokenFixture{}
	fixture.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		form, err := url.ParseQuery(string(body))
		if err != nil {
			t.Error(err)
		}
		if r.Method == http.MethodGet {
			form = r.URL.Query()
		}
		fixture.mu.Lock()
		fixture.requests = append(fixture.requests, capturedRequest{
			method: r.Method, path: r.URL.Path, header: r.Header.Clone(), form: form,
		})
		fixture.mu.Unlock()
		switch r.URL.Path {
		case "/token":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "access-token", "refresh_token": "refresh-token",
				"expires_in": 3600, "token_type": "Bearer",
			})
		case "/userinfo":
			status, payload := http.StatusOK, any(map[string]any{})
			if userInfo != nil {
				status, payload = userInfo()
			}
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(payload)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(fixture.server.Close)
	return fixture
}

func (fixture *tokenFixture) options(options Options) Options {
	options.TokenURL = fixture.server.URL + "/token"
	options.UserInfoURL = fixture.server.URL + "/userinfo"
	options.HTTPClient = fixture.server.Client()
	return options
}

func (fixture *tokenFixture) last(t *testing.T, path string) capturedRequest {
	t.Helper()
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	for index := len(fixture.requests) - 1; index >= 0; index-- {
		if fixture.requests[index].path == path {
			return fixture.requests[index]
		}
	}
	t.Fatalf("no request to %s", path)
	return capturedRequest{}
}

func assertForm(t *testing.T, got url.Values, want map[string]string) {
	t.Helper()
	flat := make(map[string]string, len(got))
	for key, values := range got {
		if len(values) != 1 {
			t.Fatalf("form key %q has %d values: %v", key, len(values), got)
		}
		flat[key] = values[0]
	}
	if !maps.Equal(flat, want) {
		t.Fatalf("token form:\nwant %v\ngot  %v", want, flat)
	}
}

func basicHeader(clientID, clientSecret string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(clientID+":"+clientSecret))
}

func newFixtureProvider(t *testing.T, fixture *tokenFixture, id string, options Options) *Provider {
	t.Helper()
	provider, err := New(id, fixture.options(options))
	if err != nil {
		t.Fatal(err)
	}
	return provider
}

func TestEncodeBasicCredentialsFormEncodesEachValue(t *testing.T) {
	t.Parallel()
	// Vector from upstream basic-credentials.test.ts.
	if got, want := encodeBasicCredentials("alice!*'", "p@ss word (1)"),
		basicHeader("alice%21*%27", "p%40ss+word+%281%29"); got != want {
		t.Fatalf("encodeBasicCredentials = %q, want %q", got, want)
	}
	if got, want := encodeBasicCredentials("id~1", "abc:def/é"),
		basicHeader("id%7E1", "abc%3Adef%2F%C3%A9"); got != want {
		t.Fatalf("encodeBasicCredentials = %q, want %q", got, want)
	}
}

func TestCloudflarePresetTokenAuthAndProfile(t *testing.T) {
	t.Parallel()
	profile := func(fields map[string]any) func() (int, any) {
		return func() (int, any) {
			return http.StatusOK, map[string]any{"success": true, "errors": []any{}, "result": fields}
		}
	}
	user := map[string]any{
		"id": "cloudflare-user-1", "email": "user@example.com",
		"first_name": "Cloudflare", "last_name": "User",
	}

	t.Run("client secret uses basic auth", func(t *testing.T) {
		t.Parallel()
		fixture := newTokenFixture(t, profile(user))
		provider := newFixtureProvider(t, fixture, "cloudflare", Options{
			ClientID: "cloudflare-client", ClientSecret: "cloudflare-secret",
		})
		authorization, err := provider.AuthorizationURL("state", "challenge", "", fixtureRedirectURI)
		if err != nil {
			t.Fatal(err)
		}
		destination := mustURL(t, authorization)
		query := destination.Query()
		if destination.Host != "dash.cloudflare.com" || destination.Path != "/oauth2/auth" ||
			query.Get("scope") != "user-details.read" || query.Get("code_challenge") != "challenge" ||
			query.Get("code_challenge_method") != "S256" || query.Get("client_id") != "cloudflare-client" {
			t.Fatalf("Cloudflare authorization URL: %s", authorization)
		}
		result, err := provider.Exchange(context.Background(), "authorization-code", "code-verifier", "", fixtureRedirectURI)
		if err != nil {
			t.Fatal(err)
		}
		token := fixture.last(t, "/token")
		if token.header.Get("Authorization") != basicHeader("cloudflare-client", "cloudflare-secret") {
			t.Fatalf("Cloudflare token auth header: %q", token.header.Get("Authorization"))
		}
		assertForm(t, token.form, map[string]string{
			"code": "authorization-code", "code_verifier": "code-verifier",
			"grant_type": "authorization_code", "redirect_uri": fixtureRedirectURI,
		})
		if got := fixture.last(t, "/userinfo").header.Get("Authorization"); got != "Bearer access-token" {
			t.Fatalf("Cloudflare user-info auth: %q", got)
		}
		got := result.Profile
		if got.ProviderAccountID != "cloudflare-user-1" || got.Email != "user@example.com" ||
			got.Name != "Cloudflare User" || got.EmailVerified || got.ImageURL != "" {
			t.Fatalf("Cloudflare profile: %#v", got)
		}
		if _, err := provider.Refresh(context.Background(), "refresh-token"); err != nil {
			t.Fatal(err)
		}
		refresh := fixture.last(t, "/token")
		if refresh.header.Get("Authorization") != basicHeader("cloudflare-client", "cloudflare-secret") {
			t.Fatalf("Cloudflare refresh auth header: %q", refresh.header.Get("Authorization"))
		}
		assertForm(t, refresh.form, map[string]string{"grant_type": "refresh_token", "refresh_token": "refresh-token"})
	})

	t.Run("public client sends no secret", func(t *testing.T) {
		t.Parallel()
		fixture := newTokenFixture(t, profile(user))
		provider := newFixtureProvider(t, fixture, "cloudflare", Options{ClientID: "cloudflare-client"})
		if _, err := provider.Exchange(context.Background(), "authorization-code", "code-verifier", "", fixtureRedirectURI); err != nil {
			t.Fatal(err)
		}
		token := fixture.last(t, "/token")
		if token.header.Get("Authorization") != "" {
			t.Fatalf("public Cloudflare client sent Authorization: %q", token.header.Get("Authorization"))
		}
		assertForm(t, token.form, map[string]string{
			"client_id": "cloudflare-client", "code": "authorization-code", "code_verifier": "code-verifier",
			"grant_type": "authorization_code", "redirect_uri": fixtureRedirectURI,
		})
		if _, err := provider.Refresh(context.Background(), "refresh-token"); err != nil {
			t.Fatal(err)
		}
		assertForm(t, fixture.last(t, "/token").form, map[string]string{
			"client_id": "cloudflare-client", "grant_type": "refresh_token", "refresh_token": "refresh-token",
		})
	})

	t.Run("client_secret_post is selectable", func(t *testing.T) {
		t.Parallel()
		fixture := newTokenFixture(t, profile(user))
		provider := newFixtureProvider(t, fixture, "cloudflare", Options{
			ClientID: "cloudflare-client", ClientSecret: "cloudflare-secret", TokenAuth: TokenAuthBody,
		})
		if _, err := provider.Exchange(context.Background(), "authorization-code", "code-verifier", "", fixtureRedirectURI); err != nil {
			t.Fatal(err)
		}
		token := fixture.last(t, "/token")
		if token.header.Get("Authorization") != "" {
			t.Fatalf("client_secret_post sent Authorization: %q", token.header.Get("Authorization"))
		}
		assertForm(t, token.form, map[string]string{
			"client_id": "cloudflare-client", "client_secret": "cloudflare-secret",
			"code": "authorization-code", "code_verifier": "code-verifier",
			"grant_type": "authorization_code", "redirect_uri": fixtureRedirectURI,
		})
	})

	t.Run("mismatched client authentication is rejected", func(t *testing.T) {
		t.Parallel()
		for _, options := range []Options{
			{ClientID: "cloudflare-client", TokenAuth: TokenAuthBasic},
			{ClientID: "cloudflare-client", TokenAuth: TokenAuthBody},
			{ClientID: "cloudflare-client", ClientSecret: "cloudflare-secret", TokenAuth: TokenAuthNone},
		} {
			if _, err := New("cloudflare", options); err == nil {
				t.Fatalf("Cloudflare accepted %q with secret=%t", options.TokenAuth, options.ClientSecret != "")
			}
		}
	})

	t.Run("name falls back to email", func(t *testing.T) {
		t.Parallel()
		fixture := newTokenFixture(t, profile(map[string]any{"id": "cloudflare-user-2", "email": "nameless@example.com"}))
		provider := newFixtureProvider(t, fixture, "cloudflare", Options{ClientID: "cloudflare-client"})
		result, err := provider.Exchange(context.Background(), "authorization-code", "code-verifier", "", fixtureRedirectURI)
		if err != nil {
			t.Fatal(err)
		}
		if result.Profile.Name != "nameless@example.com" {
			t.Fatalf("Cloudflare name fallback: %q", result.Profile.Name)
		}
	})

	for name, response := range map[string]func() (int, any){
		"the request fails": func() (int, any) {
			return http.StatusInternalServerError, map[string]any{"success": false}
		},
		"Cloudflare reports an error": func() (int, any) {
			return http.StatusOK, map[string]any{
				"success": false, "errors": []any{map[string]any{"code": 1000, "message": "Unable to fetch user"}},
				"result": nil,
			}
		},
		"Cloudflare omits the profile": func() (int, any) {
			return http.StatusOK, map[string]any{"success": true, "errors": []any{}, "result": nil}
		},
	} {
		t.Run("rejects when "+name, func(t *testing.T) {
			t.Parallel()
			fixture := newTokenFixture(t, response)
			provider := newFixtureProvider(t, fixture, "cloudflare", Options{ClientID: "cloudflare-client"})
			if _, err := provider.Exchange(
				context.Background(), "authorization-code", "code-verifier", "", fixtureRedirectURI,
			); err == nil {
				t.Fatal("Cloudflare user-info failure was accepted")
			}
		})
	}
}

// TestPayPalTokenRequests mirrors upstream paypal.test.ts.
func TestPayPalTokenRequests(t *testing.T) {
	t.Parallel()
	fixture := newTokenFixture(t, nil)
	provider := newFixtureProvider(t, fixture, "paypal", Options{
		ClientID: "paypal-client-id", ClientSecret: "paypal-client-secret",
	})
	authorization, err := provider.AuthorizationURL("state", "challenge", "", fixtureRedirectURI)
	if err != nil {
		t.Fatal(err)
	}
	if query := mustURL(t, authorization).Query(); query.Get("code_challenge") != "challenge" ||
		query.Get("code_challenge_method") != "S256" {
		t.Fatalf("PayPal authorization URL has no PKCE challenge: %s", authorization)
	}
	if _, err := provider.exchangeToken(context.Background(), "authorization-code", "code-verifier", fixtureRedirectURI); err != nil {
		t.Fatal(err)
	}
	token := fixture.last(t, "/token")
	if token.header.Get("Accept") != "application/json" ||
		token.header.Get("Authorization") != basicHeader("paypal-client-id", "paypal-client-secret") ||
		token.header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		t.Fatalf("PayPal token headers: %v", token.header)
	}
	assertForm(t, token.form, map[string]string{
		"code": "authorization-code", "code_verifier": "code-verifier",
		"grant_type": "authorization_code", "redirect_uri": fixtureRedirectURI,
	})
	if _, err := provider.Refresh(context.Background(), "refresh-token"); err != nil {
		t.Fatal(err)
	}
	refresh := fixture.last(t, "/token")
	if refresh.header.Get("Accept") != "application/json" ||
		refresh.header.Get("Authorization") != basicHeader("paypal-client-id", "paypal-client-secret") {
		t.Fatalf("PayPal refresh headers: %v", refresh.header)
	}
	assertForm(t, refresh.form, map[string]string{"grant_type": "refresh_token", "refresh_token": "refresh-token"})
}

// TestRedditTokenRequests mirrors upstream reddit.test.ts.
func TestRedditTokenRequests(t *testing.T) {
	t.Parallel()
	fixture := newTokenFixture(t, func() (int, any) {
		return http.StatusOK, map[string]any{
			"id": "reddit-user-1", "name": "reddit_user", "icon_img": "https://example.com/a.png?x=1",
			"has_verified_email": true, "oauth_client_id": "shared-app-client-id", "verified": true,
		}
	})
	provider := newFixtureProvider(t, fixture, "reddit", Options{ClientID: "reddit-app", ClientSecret: "reddit-secret"})
	result, err := provider.Exchange(context.Background(), "authorization-code", "code-verifier", "", fixtureRedirectURI)
	if err != nil {
		t.Fatal(err)
	}
	token := fixture.last(t, "/token")
	if token.header.Get("Accept") != "text/plain" || token.header.Get("User-Agent") != "better-auth" ||
		token.header.Get("Authorization") != basicHeader("reddit-app", "reddit-secret") ||
		token.header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		t.Fatalf("Reddit token headers: %v", token.header)
	}
	assertForm(t, token.form, map[string]string{
		"code": "authorization-code", "grant_type": "authorization_code", "redirect_uri": fixtureRedirectURI,
	})
	if result.Profile.Email != "reddit-user-1@reddit.placeholder.invalid" || result.Profile.EmailVerified {
		t.Fatalf("Reddit placeholder profile: %#v", result.Profile)
	}
	if _, err := provider.Refresh(context.Background(), "refresh-token"); err != nil {
		t.Fatal(err)
	}
	refresh := fixture.last(t, "/token")
	if refresh.header.Get("Accept") != "application/json" ||
		refresh.header.Get("Authorization") != basicHeader("reddit-app", "reddit-secret") {
		t.Fatalf("Reddit refresh headers: %v", refresh.header)
	}
	assertForm(t, refresh.form, map[string]string{"grant_type": "refresh_token", "refresh_token": "refresh-token"})
}

// TestTikTokTokenRequests mirrors upstream tiktok.test.ts.
func TestTikTokTokenRequests(t *testing.T) {
	t.Parallel()
	fixture := newTokenFixture(t, nil)
	provider := newFixtureProvider(t, fixture, "tiktok", Options{
		ClientKey: "tiktok-client-key", ClientSecret: "tiktok-client-secret",
	})
	if _, err := provider.exchangeToken(context.Background(), "authorization-code", "code-verifier", fixtureRedirectURI); err != nil {
		t.Fatal(err)
	}
	token := fixture.last(t, "/token")
	if token.header.Get("Authorization") != "" {
		t.Fatalf("TikTok token request sent Authorization: %q", token.header.Get("Authorization"))
	}
	assertForm(t, token.form, map[string]string{
		"client_key": "tiktok-client-key", "client_secret": "tiktok-client-secret",
		"code": "authorization-code", "code_verifier": "code-verifier",
		"grant_type": "authorization_code", "redirect_uri": fixtureRedirectURI,
	})
	if _, err := provider.Refresh(context.Background(), "refresh-token"); err != nil {
		t.Fatal(err)
	}
	assertForm(t, fixture.last(t, "/token").form, map[string]string{
		"client_key": "tiktok-client-key", "client_secret": "tiktok-client-secret",
		"grant_type": "refresh_token", "refresh_token": "refresh-token",
	})
}

// TestPresetTokenAuthMatchesUpstream checks each preset's client
// authentication on both grants against its upstream provider file.
func TestPresetTokenAuthMatchesUpstream(t *testing.T) {
	t.Parallel()
	for _, contract := range []struct {
		id      string
		code    TokenAuthMethod
		refresh TokenAuthMethod
		pkce    bool
	}{
		{"figma", TokenAuthBasic, TokenAuthBasic, true},
		{"notion", TokenAuthBasic, TokenAuthBody, false},
		{"paypal", TokenAuthBasic, TokenAuthBasic, true},
		{"railway", TokenAuthBasic, TokenAuthBasic, true},
		{"reddit", TokenAuthBasic, TokenAuthBasic, false},
		{"twitter", TokenAuthBasic, TokenAuthBasic, true},
		{"spotify", TokenAuthBody, TokenAuthBody, true},
		{"zoom", TokenAuthBody, TokenAuthBody, true},
		{"roblox", TokenAuthBody, TokenAuthBody, true},
		{"github", TokenAuthBody, TokenAuthBody, true},
	} {
		contract := contract
		t.Run(contract.id, func(t *testing.T) {
			t.Parallel()
			fixture := newTokenFixture(t, nil)
			provider := newFixtureProvider(t, fixture, contract.id, Options{
				ClientID: "client id", ClientSecret: "secret~*",
			})
			check := func(method TokenAuthMethod, request capturedRequest, standard map[string]string) {
				t.Helper()
				want := maps.Clone(standard)
				switch method {
				case TokenAuthBasic:
					if got := request.header.Get("Authorization"); got != basicHeader("client+id", "secret%7E*") {
						t.Fatalf("Basic header: %q", got)
					}
				case TokenAuthBody:
					if got := request.header.Get("Authorization"); got != "" {
						t.Fatalf("client_secret_post sent Authorization: %q", got)
					}
					want["client_id"] = "client id"
					want["client_secret"] = "secret~*"
				}
				assertForm(t, request.form, want)
			}
			if _, err := provider.exchangeToken(context.Background(), "code", "verifier", fixtureRedirectURI); err != nil {
				t.Fatal(err)
			}
			standard := map[string]string{"code": "code", "grant_type": "authorization_code", "redirect_uri": fixtureRedirectURI}
			if contract.pkce {
				standard["code_verifier"] = "verifier"
			}
			check(contract.code, fixture.last(t, "/token"), standard)
			if _, err := provider.Refresh(context.Background(), "refresh-token"); err != nil {
				t.Fatal(err)
			}
			check(contract.refresh, fixture.last(t, "/token"), map[string]string{
				"grant_type": "refresh_token", "refresh_token": "refresh-token",
			})
		})
	}
}

func TestCustomTokenRequestAuthentication(t *testing.T) {
	t.Parallel()
	custom := func(fixture *tokenFixture, hook TokenRequestHook) Options {
		return fixture.options(Options{
			ClientID: "client-id", TokenAuth: TokenAuthCustom, CustomizeTokenRequest: hook,
			AuthorizationURL: "https://idp.example.com/authorize", AccountSubject: testAccountSubject,
		})
	}

	t.Run("hook sets provider credentials", func(t *testing.T) {
		t.Parallel()
		fixture := newTokenFixture(t, nil)
		var grants []string
		provider, err := New("custom-auth", custom(fixture, func(_ context.Context, request *TokenRequest) error {
			if request.TokenEndpoint != fixture.server.URL+"/token" || request.ClientID != "client-id" {
				return errors.New("unexpected token request context")
			}
			grants = append(grants, request.GrantType)
			request.Body.Set("client_key", "provider-client-key")
			request.Body.Set("client_secret", "provider-client-secret")
			request.Header.Set("X-Provider", "custom")
			return nil
		}))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := provider.exchangeToken(context.Background(), "auth-code", "verifier", fixtureRedirectURI); err != nil {
			t.Fatal(err)
		}
		token := fixture.last(t, "/token")
		if token.header.Get("X-Provider") != "custom" || token.header.Get("Authorization") != "" {
			t.Fatalf("custom token headers: %v", token.header)
		}
		assertForm(t, token.form, map[string]string{
			"client_key": "provider-client-key", "client_secret": "provider-client-secret",
			"code": "auth-code", "code_verifier": "verifier",
			"grant_type": "authorization_code", "redirect_uri": fixtureRedirectURI,
		})
		if _, err := provider.Refresh(context.Background(), "refresh-token"); err != nil {
			t.Fatal(err)
		}
		assertForm(t, fixture.last(t, "/token").form, map[string]string{
			"client_key": "provider-client-key", "client_secret": "provider-client-secret",
			"grant_type": "refresh_token", "refresh_token": "refresh-token",
		})
		if strings.Join(grants, ",") != "authorization_code,refresh_token" {
			t.Fatalf("custom hook grant types: %v", grants)
		}
	})

	for _, parameter := range []string{"client_assertion", "client_assertion_type"} {
		parameter := parameter
		t.Run("rejects only "+parameter, func(t *testing.T) {
			t.Parallel()
			fixture := newTokenFixture(t, nil)
			provider, err := New("custom-auth", custom(fixture, func(_ context.Context, request *TokenRequest) error {
				request.Body.Set(parameter, "value")
				return nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			_, err = provider.exchangeToken(context.Background(), "auth-code", "verifier", fixtureRedirectURI)
			if err == nil || !strings.Contains(err.Error(), "client_assertion and client_assertion_type must both be provided") {
				t.Fatalf("partial client assertion accepted: %v", err)
			}
		})
	}

	t.Run("hook error stops the request", func(t *testing.T) {
		t.Parallel()
		fixture := newTokenFixture(t, nil)
		provider, err := New("custom-auth", custom(fixture, func(context.Context, *TokenRequest) error {
			return errors.New("signing failed")
		}))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := provider.exchangeToken(context.Background(), "auth-code", "verifier", fixtureRedirectURI); err == nil ||
			!strings.Contains(err.Error(), "signing failed") {
			t.Fatalf("hook error was ignored: %v", err)
		}
		fixture.mu.Lock()
		defer fixture.mu.Unlock()
		if len(fixture.requests) != 0 {
			t.Fatal("token request was sent after the hook failed")
		}
	})

	t.Run("configuration is validated", func(t *testing.T) {
		t.Parallel()
		fixture := newTokenFixture(t, nil)
		withoutHook := custom(fixture, nil)
		if _, err := New("custom-auth", withoutHook); err == nil {
			t.Fatal("custom token auth without a hook was accepted")
		}
		hookOnly := custom(fixture, func(context.Context, *TokenRequest) error { return nil })
		hookOnly.TokenAuth = TokenAuthBody
		hookOnly.ClientSecret = "secret"
		if _, err := New("custom-auth", hookOnly); err == nil {
			t.Fatal("token request hook without custom token auth was accepted")
		}
		unknown := fixture.options(Options{
			ClientID: "client-id", ClientSecret: "secret", TokenAuth: "private_key_jwt",
			AuthorizationURL: "https://idp.example.com/authorize", AccountSubject: testAccountSubject,
		})
		if _, err := New("custom-auth", unknown); err == nil {
			t.Fatal("unsupported token auth method was accepted")
		}
	})
}

func TestProviderPlaceholderEmails(t *testing.T) {
	t.Parallel()
	for _, contract := range []struct {
		name     string
		id       string
		data     map[string]any
		email    string
		verified bool
	}{
		{"reddit without email", "reddit", map[string]any{"id": "reddit-user-1", "name": "r", "oauth_client_id": "shared-app-client-id"}, "reddit-user-1@reddit.placeholder.invalid", false},
		{"reddit ignores profile email", "reddit", map[string]any{"id": "reddit-user-2", "email": "user@example.com"}, "reddit-user-2@reddit.placeholder.invalid", false},
		{"roblox without email", "roblox", map[string]any{"sub": "roblox-user-1", "preferred_username": "roblox_name"}, "roblox-user-1@roblox.placeholder.invalid", false},
		{"roblox ignores profile email", "roblox", map[string]any{"sub": "roblox-user-2", "email": "user@example.com"}, "roblox-user-2@roblox.placeholder.invalid", false},
		{"tiktok without email", "tiktok", map[string]any{"data": map[string]any{"user": map[string]any{"open_id": "tiktok-user-1", "username": "tiktok-user"}}}, "tiktok-user-1@tiktok.placeholder.invalid", false},
		{"tiktok with email", "tiktok", map[string]any{"data": map[string]any{"user": map[string]any{"open_id": "tiktok-user-2", "email": "tiktok@example.com"}}}, "tiktok@example.com", false},
		{"twitter without email", "twitter", map[string]any{"data": map[string]any{"id": "twitter-user-1", "username": "twitter_user", "verified": true}}, "twitter-user-1@twitter.placeholder.invalid", false},
		{"twitter with confirmed email", "twitter", map[string]any{"data": map[string]any{"id": "twitter-user-2", "confirmed_email": "twitter@example.com"}}, "twitter@example.com", true},
		{"twitter with unconfirmed email", "twitter", map[string]any{"data": map[string]any{"id": "twitter-user-3", "email": "other@example.com"}}, "other@example.com", false},
		{"wechat union id", "wechat", map[string]any{"openid": "open-123", "unionid": "union-abc"}, "union-abc@wechat.placeholder.invalid", false},
		{"wechat open id", "wechat", map[string]any{"openid": "open-456"}, "open-456@wechat.placeholder.invalid", false},
		{"wechat with email", "wechat", map[string]any{"openid": "open-789", "email": "wechat@example.com"}, "wechat@example.com", false},
	} {
		contract := contract
		t.Run(contract.name, func(t *testing.T) {
			t.Parallel()
			profile, err := providerMapper(contract.id)(contract.data)
			if err != nil {
				t.Fatal(err)
			}
			if profile.Email != contract.email || profile.EmailVerified != contract.verified {
				t.Fatalf("%s email = %q verified=%t, want %q verified=%t",
					contract.id, profile.Email, profile.EmailVerified, contract.email, contract.verified)
			}
		})
	}

	t.Run("invalid identifier is rejected", func(t *testing.T) {
		t.Parallel()
		_, err := providerMapper("reddit")(map[string]any{"id": "bad id"})
		if !errors.Is(err, betterauth.ErrInvalidPlaceholderEmail) {
			t.Fatalf("invalid placeholder identifier: %v", err)
		}
	})
}

func TestTransportErrorsDropTheURLQuery(t *testing.T) {
	failing := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("network down")
	})}
	request, err := http.NewRequest(http.MethodGet,
		"https://api.weixin.qq.com/sns/oauth2/access_token?appid=app&secret=top-secret&code=c", nil)
	if err != nil {
		t.Fatal(err)
	}
	err = boundedJSON(failing, request, 1024, &struct{}{})
	if err == nil || strings.Contains(err.Error(), "top-secret") || strings.Contains(err.Error(), "code=c") {
		t.Fatalf("error leaked the query: %v", err)
	}
	if !strings.Contains(err.Error(), "https://api.weixin.qq.com/sns/oauth2/access_token") {
		t.Fatalf("error lost the endpoint: %v", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }
