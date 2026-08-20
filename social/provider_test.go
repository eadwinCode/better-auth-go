package social

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	betterauth "github.com/eadwinCode/better-auth-go"
)

func TestSupportedProviderCatalog(t *testing.T) {
	t.Parallel()
	expected := []string{
		"apple", "atlassian", "cognito", "discord", "dropbox", "facebook", "figma",
		"github", "gitlab", "google", "huggingface", "kakao", "kick", "line",
		"linear", "linkedin", "microsoft", "naver", "notion", "paybin", "paypal",
		"polar", "railway", "reddit", "roblox", "salesforce", "slack", "spotify",
		"tiktok", "twitch", "twitter", "vercel", "vk", "wechat", "zoom",
	}
	if !slices.Equal(SupportedProviders, expected) {
		t.Fatalf("provider catalog drifted:\nwant %#v\ngot  %#v", expected, SupportedProviders)
	}
	seen := map[string]bool{}
	for _, id := range SupportedProviders {
		if seen[id] {
			t.Fatalf("duplicate provider %q", id)
		}
		seen[id] = true
		options := Options{ClientID: "client-id", ClientSecret: "client-secret"}
		switch id {
		case "cognito":
			options.Issuer = "https://tenant.auth.example"
		case "microsoft":
			options.Tenant = "00000000-0000-0000-0000-000000000000"
		case "tiktok":
			options.ClientKey = "client-key"
		}
		provider, err := New(id, options)
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		destination, err := provider.AuthorizationURL(
			"state-value", "challenge-value", "nonce-value", "https://auth.example/callback/"+id,
		)
		if err != nil {
			t.Fatalf("%s authorization URL: %v", id, err)
		}
		parsed, err := url.Parse(destination)
		if err != nil {
			t.Fatalf("%s URL parse: %v", id, err)
		}
		if parsed.Scheme != "https" || parsed.Query().Get("state") != "state-value" ||
			parsed.Query().Get("redirect_uri") == "" {
			t.Fatalf("%s unsafe/incomplete authorization URL: %s", id, destination)
		}
	}
}

func TestGenericOAuthExchange(t *testing.T) {
	t.Parallel()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			if err := r.ParseForm(); err != nil {
				t.Error(err)
			}
			if r.Form.Get("code") != "authorization-code" ||
				r.Form.Get("code_verifier") != "verifier-value" ||
				r.Form.Get("client_secret") != "client-secret" {
				t.Errorf("unexpected token form: %v", r.Form)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "access-token", "token_type": "Bearer", "expires_in": 300,
			})
		case "/userinfo":
			if r.Header.Get("Authorization") != "Bearer access-token" {
				t.Errorf("unexpected authorization header: %q", r.Header.Get("Authorization"))
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"sub": "provider-user", "email": "user@example.com", "email_verified": true,
				"name": "Provider User", "picture": "https://images.example/user.png",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	provider, err := New("custom-provider", Options{
		ClientID: "client-id", ClientSecret: "client-secret",
		AuthorizationURL: server.URL + "/authorize", TokenURL: server.URL + "/token",
		UserInfoURL: server.URL + "/userinfo", HTTPClient: server.Client(),
		AccountSubject: testAccountSubject,
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := provider.Exchange(
		context.Background(), "authorization-code", "verifier-value", "nonce-value",
		"https://auth.example/callback/custom-provider",
	)
	if err != nil {
		t.Fatal(err)
	}
	profile := result.Profile
	if profile.ProviderAccountID != "provider-user" || profile.Email != "user@example.com" ||
		!profile.EmailVerified || profile.Name != "Provider User" {
		t.Fatalf("unexpected profile: %#v", profile)
	}
	if result.Tokens.AccessToken != "access-token" {
		t.Fatalf("unexpected tokens: %#v", result.Tokens)
	}
}

func TestProviderRejectsRedirectingTokenEndpoint(t *testing.T) {
	t.Parallel()
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "stolen"})
	}))
	defer target.Close()
	redirector := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer redirector.Close()

	provider, err := New("redirect-test", Options{
		ClientID: "client", ClientSecret: "secret",
		AuthorizationURL: redirector.URL + "/authorize", TokenURL: redirector.URL,
		UserInfoURL: redirector.URL + "/userinfo", HTTPClient: redirector.Client(),
		AccountSubject: testAccountSubject,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = provider.Exchange(context.Background(), "code", "verifier", "", "https://auth.example/callback")
	if err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("expected redirect rejection, got %v", err)
	}
}

func testAccountSubject(profile map[string]any) (string, error) {
	if value := stringValue(profile["sub"]); value != "" {
		return value, nil
	}
	return stringValue(profile["id"]), nil
}

func TestProviderEndSessionURLIsBoundedAndDiscriminated(t *testing.T) {
	provider, err := New("logout-provider", Options{
		ClientID: "client-id", ClientSecret: "client-secret",
		AuthorizationURL: "https://idp.example.com/authorize",
		TokenURL:         "https://idp.example.com/token",
		UserInfoURL:      "https://idp.example.com/userinfo",
		EndSessionURL:    "https://idp.example.com/logout",
		AccountSubject:   testAccountSubject,
	})
	if err != nil {
		t.Fatal(err)
	}
	destination, err := provider.EndSessionURL(betterauth.OAuthEndSessionRequest{
		IDToken: "id-token", PostLogoutRedirectURI: "https://app.example.com/signed-out",
		State: "opaque-state",
	})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(destination)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	if parsed.Scheme != "https" || parsed.Host != "idp.example.com" ||
		query.Get("id_token_hint") != "id-token" || query.Get("client_id") != "client-id" ||
		query.Get("post_logout_redirect_uri") != "https://app.example.com/signed-out" ||
		query.Get("state") != "opaque-state" {
		t.Fatalf("unexpected end-session URL: %s", destination)
	}
}
