package social

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	betterauth "github.com/eadwinCode/better-auth-go"
)

type presetContract struct {
	id        string
	authHost  string
	authPath  string
	scopes    []string
	pkce      bool
	tokenAuth TokenAuthMethod
}

func TestBetterAuthV1625PresetContracts(t *testing.T) {
	t.Parallel()
	contracts := []presetContract{
		{"apple", "appleid.apple.com", "/auth/authorize", []string{"email", "name"}, true, TokenAuthBody},
		{"atlassian", "auth.atlassian.com", "/authorize", []string{"read:jira-user", "offline_access"}, true, TokenAuthBody},
		{"cognito", "tenant.auth.example", "/oauth2/authorize", []string{"openid", "profile", "email"}, true, TokenAuthBody},
		{"discord", "discord.com", "/api/oauth2/authorize", []string{"identify", "email"}, false, TokenAuthBody},
		{"dropbox", "www.dropbox.com", "/oauth2/authorize", []string{"account_info.read"}, true, TokenAuthBody},
		{"facebook", "www.facebook.com", "/v24.0/dialog/oauth", []string{"email", "public_profile"}, false, TokenAuthBody},
		{"figma", "www.figma.com", "/oauth", []string{"current_user:read"}, true, TokenAuthBody},
		{"github", "github.com", "/login/oauth/authorize", []string{"read:user", "user:email"}, true, TokenAuthBody},
		{"gitlab", "gitlab.com", "/oauth/authorize", []string{"read_user"}, true, TokenAuthBody},
		{"google", "accounts.google.com", "/o/oauth2/v2/auth", []string{"email", "profile", "openid"}, true, TokenAuthBody},
		{"huggingface", "huggingface.co", "/oauth/authorize", []string{"openid", "profile", "email"}, true, TokenAuthBody},
		{"kakao", "kauth.kakao.com", "/oauth/authorize", []string{"account_email", "profile_image", "profile_nickname"}, false, TokenAuthBody},
		{"kick", "id.kick.com", "/oauth/authorize", []string{"user:read"}, true, TokenAuthBody},
		{"line", "access.line.me", "/oauth2/v2.1/authorize", []string{"openid", "profile", "email"}, true, TokenAuthBody},
		{"linear", "linear.app", "/oauth/authorize", []string{"read"}, false, TokenAuthBody},
		{"linkedin", "www.linkedin.com", "/oauth/v2/authorization", []string{"profile", "email", "openid"}, false, TokenAuthBody},
		{"microsoft", "login.microsoftonline.com", "/tenant-id/oauth2/v2.0/authorize", []string{"openid", "profile", "email", "User.Read", "offline_access"}, true, TokenAuthBody},
		{"naver", "nid.naver.com", "/oauth2.0/authorize", []string{"profile", "email"}, false, TokenAuthBody},
		{"notion", "api.notion.com", "/v1/oauth/authorize", nil, false, TokenAuthBasic},
		{"paybin", "idp.paybin.io", "/oauth2/authorize", []string{"openid", "email", "profile"}, true, TokenAuthBody},
		{"paypal", "www.paypal.com", "/signin/authorize", nil, false, TokenAuthBasic},
		{"polar", "polar.sh", "/oauth2/authorize", []string{"openid", "profile", "email"}, true, TokenAuthBody},
		{"railway", "backboard.railway.com", "/oauth/auth", []string{"openid", "email", "profile"}, true, TokenAuthBody},
		{"reddit", "www.reddit.com", "/api/v1/authorize", []string{"identity"}, false, TokenAuthBasic},
		{"roblox", "apis.roblox.com", "/oauth/v1/authorize", []string{"openid", "profile"}, true, TokenAuthBody},
		{"salesforce", "login.salesforce.com", "/services/oauth2/authorize", []string{"openid", "email", "profile"}, true, TokenAuthBody},
		{"slack", "slack.com", "/openid/connect/authorize", []string{"openid", "profile", "email"}, false, TokenAuthBody},
		{"spotify", "accounts.spotify.com", "/authorize", []string{"user-read-email"}, true, TokenAuthBasic},
		{"tiktok", "www.tiktok.com", "/v2/auth/authorize", []string{"user.info.profile"}, false, TokenAuthBody},
		{"twitch", "id.twitch.tv", "/oauth2/authorize", []string{"user:read:email", "openid"}, false, TokenAuthBody},
		{"twitter", "x.com", "/i/oauth2/authorize", []string{"users.read", "tweet.read", "offline.access", "users.email"}, true, TokenAuthBasic},
		{"vercel", "vercel.com", "/oauth/authorize", nil, true, TokenAuthBody},
		{"vk", "id.vk.com", "/authorize", []string{"email", "phone"}, true, TokenAuthBody},
		{"wechat", "open.weixin.qq.com", "/connect/qrconnect", []string{"snsapi_login"}, false, TokenAuthNone},
		{"zoom", "zoom.us", "/oauth/authorize", nil, false, TokenAuthBasic},
	}
	if len(contracts) != 35 {
		t.Fatalf("certification matrix has %d providers", len(contracts))
	}
	for index, contract := range contracts {
		if contract.id != SupportedProviders[index] {
			t.Fatalf("certification matrix[%d] = %q, want %q", index, contract.id, SupportedProviders[index])
		}
	}
	for _, contract := range contracts {
		contract := contract
		t.Run(contract.id, func(t *testing.T) {
			t.Parallel()
			options := Options{ClientID: "client-id", ClientSecret: "client-secret"}
			switch contract.id {
			case "cognito":
				options.Issuer = "https://tenant.auth.example"
			case "microsoft":
				options.Tenant = "tenant-id"
			case "tiktok":
				options.ClientKey = "client-key"
			}
			definition, err := providerPreset(contract.id, options)
			if err != nil {
				t.Fatal(err)
			}
			if definition.pkce != contract.pkce || definition.tokenAuth != contract.tokenAuth ||
				!slices.Equal(definition.defaultScopes, contract.scopes) {
				t.Fatalf("contract drift: pkce=%v auth=%q scopes=%v", definition.pkce, definition.tokenAuth, definition.defaultScopes)
			}
			provider, err := New(contract.id, options)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := provider.AuthorizationURL(
				"state", "challenge", "nonce", "https://auth.example/callback/"+contract.id,
			)
			if err != nil {
				t.Fatal(err)
			}
			destination, err := url.Parse(raw)
			if err != nil {
				t.Fatal(err)
			}
			query := destination.Query()
			if destination.Hostname() != contract.authHost || destination.Path != contract.authPath ||
				query.Get("state") != "state" || query.Get("response_type") != "code" {
				t.Fatalf("authorization contract drift: %s", raw)
			}
			if contract.pkce != (query.Get("code_challenge_method") == "S256") {
				t.Fatalf("PKCE contract drift: %s", raw)
			}
			if contract.id == "tiktok" && query.Get("client_key") != "client-key" {
				t.Fatalf("TikTok client_key missing: %s", raw)
			}
			if contract.id == "wechat" && (destination.Fragment != "wechat_redirect" || query.Get("appid") == "") {
				t.Fatalf("WeChat authorization contract drift: %s", raw)
			}
		})
	}
}

type profileContract struct {
	id       string
	data     map[string]any
	account  string
	email    string
	verified bool
	name     string
	image    string
}

func TestBetterAuthV1625PresetProfileMappings(t *testing.T) {
	t.Parallel()
	standard := func(id string) map[string]any {
		return map[string]any{
			"sub": id + "-account", "email": id + "@example.com", "email_verified": true,
			"name": id + " user", "picture": "https://images.example/" + id,
		}
	}
	contracts := []profileContract{
		{"apple", standard("apple"), "apple-account", "apple@example.com", true, "apple user", "https://images.example/apple"},
		{"atlassian", map[string]any{"account_id": "atl", "email": "atl@example.com", "name": "Atlassian", "picture": "atl.png"}, "atl", "atl@example.com", false, "Atlassian", "atl.png"},
		{"cognito", standard("cognito"), "cognito-account", "cognito@example.com", true, "cognito user", "https://images.example/cognito"},
		{"discord", map[string]any{"id": "discord", "global_name": "Discord", "email": "discord@example.com", "verified": true, "image_url": "discord.png"}, "discord", "discord@example.com", true, "Discord", "discord.png"},
		{"dropbox", map[string]any{"account_id": "dropbox", "name": map[string]any{"display_name": "Dropbox"}, "email": "dropbox@example.com", "email_verified": true, "profile_photo_url": "dropbox.png"}, "dropbox", "dropbox@example.com", true, "Dropbox", "dropbox.png"},
		{"facebook", map[string]any{"id": "facebook", "name": "Facebook", "email": "facebook@example.com", "email_verified": true, "picture": map[string]any{"data": map[string]any{"url": "facebook.png"}}}, "facebook", "facebook@example.com", true, "Facebook", "facebook.png"},
		{"figma", map[string]any{"id": "figma", "handle": "Figma", "email": "figma@example.com", "img_url": "figma.png"}, "figma", "figma@example.com", false, "Figma", "figma.png"},
		{"github", map[string]any{"id": "github", "name": "GitHub", "email": "github@example.com", "email_verified": true, "avatar_url": "github.png"}, "github", "github@example.com", true, "GitHub", "github.png"},
		{"gitlab", map[string]any{"id": "gitlab", "username": "GitLab", "email": "gitlab@example.com", "email_verified": true, "avatar_url": "gitlab.png"}, "gitlab", "gitlab@example.com", true, "GitLab", "gitlab.png"},
		{"google", standard("google"), "google-account", "google@example.com", true, "google user", "https://images.example/google"},
		{"huggingface", standard("huggingface"), "huggingface-account", "huggingface@example.com", true, "huggingface user", "https://images.example/huggingface"},
		{"kakao", map[string]any{"id": "kakao", "kakao_account": map[string]any{"email": "kakao@example.com", "is_email_valid": true, "is_email_verified": true, "profile": map[string]any{"nickname": "Kakao", "profile_image_url": "kakao.png"}}}, "kakao", "kakao@example.com", true, "Kakao", "kakao.png"},
		{"kick", map[string]any{"data": []any{map[string]any{"user_id": "kick", "name": "Kick", "email": "kick@example.com", "profile_picture": "kick.png"}}}, "kick", "kick@example.com", false, "Kick", "kick.png"},
		{"line", map[string]any{"sub": "line", "name": "Line", "email": "line@example.com", "pictureUrl": "line.png"}, "line", "line@example.com", false, "Line", "line.png"},
		{"linear", map[string]any{"data": map[string]any{"viewer": map[string]any{"id": "linear", "name": "Linear", "email": "linear@example.com", "avatarUrl": "linear.png"}}}, "linear", "linear@example.com", false, "Linear", "linear.png"},
		{"linkedin", standard("linkedin"), "linkedin-account", "linkedin@example.com", true, "linkedin user", "https://images.example/linkedin"},
		{"microsoft", standard("microsoft"), "microsoft-account", "microsoft@example.com", true, "microsoft user", "https://images.example/microsoft"},
		{"naver", map[string]any{"response": map[string]any{"id": "naver", "nickname": "Naver", "email": "naver@example.com", "profile_image": "naver.png"}}, "naver", "naver@example.com", false, "Naver", "naver.png"},
		{"notion", map[string]any{"id": "notion", "name": "Notion", "person": map[string]any{"email": "notion@example.com"}, "avatar_url": "notion.png"}, "notion", "notion@example.com", false, "Notion", "notion.png"},
		{"paybin", standard("paybin"), "paybin-account", "paybin@example.com", true, "paybin user", "https://images.example/paybin"},
		{"paypal", map[string]any{"user_id": "paypal", "name": "PayPal", "email": "paypal@example.com", "email_verified": true, "picture": "paypal.png"}, "paypal", "paypal@example.com", true, "PayPal", "paypal.png"},
		{"polar", map[string]any{"id": "polar", "public_name": "Polar", "email": "polar@example.com", "email_verified": true, "avatar_url": "polar.png"}, "polar", "polar@example.com", true, "Polar", "polar.png"},
		{"railway", standard("railway"), "railway-account", "railway@example.com", false, "railway user", "https://images.example/railway"},
		{"reddit", map[string]any{"id": "reddit", "name": "Reddit", "icon_img": "reddit.png?size=64"}, "reddit", "reddit@reddit.invalid", false, "Reddit", "reddit.png"},
		{"roblox", map[string]any{"sub": "roblox", "nickname": "Roblox", "preferred_username": "roblox-user", "picture": "roblox.png"}, "roblox", "roblox-user", false, "Roblox", "roblox.png"},
		{"salesforce", map[string]any{"user_id": "salesforce", "name": "Salesforce", "email": "salesforce@example.com", "email_verified": true, "photos": map[string]any{"picture": "salesforce.png"}}, "salesforce", "salesforce@example.com", true, "Salesforce", "salesforce.png"},
		{"slack", map[string]any{"https://slack.com/user_id": "slack", "name": "Slack", "email": "slack@example.com", "email_verified": true, "https://slack.com/user_image_512": "slack.png"}, "slack", "slack@example.com", true, "Slack", "slack.png"},
		{"spotify", map[string]any{"id": "spotify", "display_name": "Spotify", "email": "spotify@example.com", "images": []any{map[string]any{"url": "spotify.png"}}}, "spotify", "spotify@example.com", false, "Spotify", "spotify.png"},
		{"tiktok", map[string]any{"data": map[string]any{"user": map[string]any{"open_id": "tiktok", "display_name": "TikTok", "username": "tiktok-user", "avatar_large_url": "tiktok.png"}}}, "tiktok", "tiktok-user", false, "TikTok", "tiktok.png"},
		{"twitch", standard("twitch"), "twitch-account", "twitch@example.com", true, "twitch user", "https://images.example/twitch"},
		{"twitter", map[string]any{"data": map[string]any{"id": "twitter", "name": "Twitter", "username": "twitter-user", "confirmed_email": "twitter@example.com", "profile_image_url": "twitter.png"}}, "twitter", "twitter@example.com", true, "Twitter", "twitter.png"},
		{"vercel", standard("vercel"), "vercel-account", "vercel@example.com", true, "vercel user", "https://images.example/vercel"},
		{"vk", map[string]any{"user": map[string]any{"user_id": "vk", "first_name": "V K", "last_name": "User", "email": "vk@example.com", "avatar": "vk.png"}}, "vk", "vk@example.com", false, "V K User", "vk.png"},
		{"wechat", map[string]any{"unionid": "wechat", "nickname": "WeChat", "headimgurl": "wechat.png"}, "wechat", "wechat@wechat.invalid", false, "WeChat", "wechat.png"},
		{"zoom", map[string]any{"id": "zoom", "display_name": "Zoom", "email": "zoom@example.com", "verified": true, "pic_url": "zoom.png"}, "zoom", "zoom@example.com", true, "Zoom", "zoom.png"},
	}
	if len(contracts) != len(SupportedProviders) {
		t.Fatalf("profile matrix has %d providers, catalog has %d", len(contracts), len(SupportedProviders))
	}
	for index, contract := range contracts {
		if contract.id != SupportedProviders[index] {
			t.Fatalf("profile matrix[%d] = %q, want %q", index, contract.id, SupportedProviders[index])
		}
	}
	for _, contract := range contracts {
		contract := contract
		t.Run(contract.id, func(t *testing.T) {
			t.Parallel()
			profile, err := providerMapper(contract.id)(contract.data)
			if err != nil {
				t.Fatal(err)
			}
			if profile.ProviderAccountID != contract.account || profile.Email != contract.email ||
				profile.EmailVerified != contract.verified || profile.Name != contract.name ||
				profile.ImageURL != contract.image {
				t.Fatalf("profile mapping drift:\nwant %#v\ngot  %#v", contract, profile)
			}
		})
	}
}

type certificationClock struct{ now time.Time }

func (clock certificationClock) Now() time.Time { return clock.now }

func TestGenericOIDCDiscoveryAndIDTokenVerification(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rotatedKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	activeKey := key
	activeKeyID := "key-1"
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer": server.URL, "authorization_endpoint": server.URL + "/authorize",
				"token_endpoint": server.URL + "/token", "jwks_uri": server.URL + "/jwks",
				"response_types_supported":              []string{"code"},
				"id_token_signing_alg_values_supported": []string{"RS256"},
				"token_endpoint_auth_methods_supported": []string{"client_secret_basic"},
			})
		case "/token":
			clientID, secret, ok := r.BasicAuth()
			if !ok || clientID != "client-id" || secret != "client-secret" {
				t.Errorf("unexpected token authentication")
			}
			_ = r.ParseForm()
			if r.Form.Get("code_verifier") != "verifier" {
				t.Errorf("PKCE verifier missing: %v", r.Form)
			}
			if r.Form.Get("code") == "missing-id-token" {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"access_token": "access-token", "expires_in": 300,
				})
				return
			}
			signingKey := activeKey
			keyID := activeKeyID
			audience := "client-id"
			expiry := now.Add(time.Hour)
			algorithm := "RS256"
			switch r.Form.Get("code") {
			case "rotate":
				activeKey = rotatedKey
				activeKeyID = "key-2"
				signingKey = activeKey
				keyID = activeKeyID
			case "bad-audience":
				audience = "other-client"
			case "expired":
				expiry = now.Add(-time.Hour)
			case "bad-algorithm":
				algorithm = "HS256"
			}
			raw := signIDTokenWithAlgorithm(t, signingKey, keyID, algorithm, map[string]any{
				"iss": server.URL, "aud": "client-id", "sub": "oidc-user",
				"email": "oidc@example.com", "email_verified": true, "name": "OIDC User",
				"nonce": "nonce", "exp": expiry.Unix(),
			})
			if audience != "client-id" {
				raw = signIDToken(t, signingKey, keyID, map[string]any{
					"iss": server.URL, "aud": audience, "sub": "oidc-user",
					"email": "oidc@example.com", "email_verified": true, "name": "OIDC User",
					"nonce": "nonce", "exp": expiry.Unix(),
				})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "access-token", "id_token": raw, "expires_in": 300,
			})
		case "/jwks":
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{
				"kty": "RSA", "kid": activeKeyID, "alg": "RS256", "use": "sig",
				"n": base64.RawURLEncoding.EncodeToString(activeKey.PublicKey.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(activeKey.PublicKey.E)).Bytes()),
			}}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	provider, err := NewOIDC(context.Background(), "enterprise-oidc", Options{
		ClientID: "client-id", ClientSecret: "client-secret", Issuer: server.URL,
		HTTPClient: server.Client(), Clock: certificationClock{now: now},
	})
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := provider.AuthorizationURL(
		"state", "challenge", "nonce", "https://auth.example/callback",
	)
	if err != nil {
		t.Fatal(err)
	}
	query := mustURL(t, authorization).Query()
	if query.Get("nonce") != "nonce" || query.Get("code_challenge") != "challenge" ||
		query.Get("scope") != "openid profile email" {
		t.Fatalf("generic OIDC authorization contract: %s", authorization)
	}
	result, err := provider.Exchange(
		context.Background(), "code", "verifier", "nonce", "https://auth.example/callback",
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.Profile.Provider != "enterprise-oidc" ||
		result.Profile.ProviderAccountID != "oidc-user" || !result.Profile.EmailVerified {
		t.Fatalf("generic OIDC profile: %#v", result.Profile)
	}
	_, err = provider.Exchange(
		context.Background(), "missing-id-token", "verifier", "nonce",
		"https://auth.example/callback",
	)
	if err == nil || !strings.Contains(err.Error(), "no ID token") {
		t.Fatalf("OIDC response without a verified subject was accepted: %v", err)
	}
	if want := now.Add(5 * time.Minute); !result.Tokens.AccessTokenExpiresAt.Equal(want) {
		t.Fatalf("deterministic token expiry = %v, want %v", result.Tokens.AccessTokenExpiresAt, want)
	}
	_, err = provider.Exchange(
		context.Background(), "code", "verifier", "wrong-nonce", "https://auth.example/callback",
	)
	if err == nil || !strings.Contains(err.Error(), "nonce") {
		t.Fatalf("invalid nonce accepted: %v", err)
	}
	rotated, err := provider.Exchange(
		context.Background(), "rotate", "verifier", "nonce", "https://auth.example/callback",
	)
	if err != nil || rotated.Profile.ProviderAccountID != "oidc-user" {
		t.Fatalf("JWKS key rotation failed: %#v, %v", rotated, err)
	}
	for _, failure := range []struct {
		code string
		want string
	}{
		{"bad-audience", "audience"},
		{"expired", "expired"},
		{"bad-algorithm", "unsupported"},
	} {
		_, err := provider.Exchange(
			context.Background(), failure.code, "verifier", "nonce", "https://auth.example/callback",
		)
		if err == nil || !strings.Contains(err.Error(), failure.want) {
			t.Fatalf("%s ID token accepted: %v", failure.code, err)
		}
	}
}

func TestGenericOIDCRejectsDiscoveryRedirectAndIssuerMismatch(t *testing.T) {
	t.Parallel()
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": "https://attacker.example"})
	}))
	defer target.Close()
	redirector := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer redirector.Close()
	_, err := NewOIDC(context.Background(), "redirected", Options{
		ClientID: "client", ClientSecret: "secret", Issuer: redirector.URL,
		HTTPClient: redirector.Client(),
	})
	if err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("discovery redirect accepted: %v", err)
	}

	var mismatch *httptest.Server
	mismatch = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 "https://different.example",
			"authorization_endpoint": mismatch.URL + "/authorize",
			"token_endpoint":         mismatch.URL + "/token",
			"jwks_uri":               mismatch.URL + "/jwks",
		})
	}))
	defer mismatch.Close()
	_, err = NewOIDC(context.Background(), "mismatch", Options{
		ClientID: "client", ClientSecret: "secret", Issuer: mismatch.URL,
		HTTPClient: mismatch.Client(),
	})
	if err == nil || !strings.Contains(err.Error(), "issuer mismatch") {
		t.Fatalf("issuer mismatch accepted: %v", err)
	}
	if err := validateDiscoveredEndpoint(
		"https://127.0.0.2/token", "https://issuer.example",
	); err == nil || !strings.Contains(err.Error(), "private") {
		t.Fatalf("private discovered endpoint accepted: %v", err)
	}
}

func TestGenericOAuthAuthenticationRefreshMapperAndErrorBounds(t *testing.T) {
	t.Parallel()
	for _, method := range []TokenAuthMethod{TokenAuthBody, TokenAuthBasic, TokenAuthNone} {
		method := method
		t.Run(string(method), func(t *testing.T) {
			t.Parallel()
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/token":
					if err := r.ParseForm(); err != nil {
						t.Error(err)
					}
					clientID, secret, basic := r.BasicAuth()
					switch method {
					case TokenAuthBody:
						if basic || r.Form.Get("client_secret") != "client-secret" {
							t.Errorf("client_secret_post contract: basic=%v form=%v", basic, r.Form)
						}
					case TokenAuthBasic:
						if !basic || clientID != "client-id" || secret != "client-secret" ||
							r.Form.Get("client_secret") != "" {
							t.Errorf("client_secret_basic contract: basic=%v id=%q form=%v", basic, clientID, r.Form)
						}
					case TokenAuthNone:
						if basic || r.Form.Get("client_secret") != "" {
							t.Errorf("public-client contract: basic=%v form=%v", basic, r.Form)
						}
					}
					if r.Form.Get("grant_type") == "refresh_token" {
						if r.Form.Get("resource") != "https://api.example.com" ||
							r.Form.Get("refresh_token") != "refresh" {
							t.Errorf("refresh token params contract: %v", r.Form)
						}
						_ = json.NewEncoder(w).Encode(map[string]any{
							"access_token": "refreshed", "refresh_token": "next-refresh",
							"scope": "openid", "expires_in": 60,
						})
						return
					}
					_ = json.NewEncoder(w).Encode(map[string]any{
						"access_token": "access", "refresh_token": "refresh",
					})
				case "/userinfo":
					_ = json.NewEncoder(w).Encode(map[string]any{
						"id": "raw-id", "email": "raw@example.com",
					})
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			secret := "client-secret"
			if method == TokenAuthNone {
				secret = ""
			}
			provider, err := New("generic-"+string(method), Options{
				ClientID: "client-id", ClientSecret: secret, TokenAuth: method,
				AuthorizationURL: server.URL + "/authorize", TokenURL: server.URL + "/token",
				UserInfoURL: server.URL + "/userinfo", HTTPClient: server.Client(),
				Scopes:              []string{"profile", "email", "profile"},
				AuthorizationParams: map[string]string{"prompt": "consent"},
				RefreshTokenParams: map[string]string{
					"resource": "https://api.example.com", "refresh_token": "attacker-value",
				},
				AccountSubject: testAccountSubject,
				ProfileMapper: func(raw map[string]any) (betterauth.OAuthProfile, error) {
					return betterauth.OAuthProfile{
						ProviderAccountID: "mapped-" + stringValue(raw["id"]),
						Email:             stringValue(raw["email"]),
						EmailVerified:     true,
						Name:              "Mapped",
					}, nil
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			authorization, err := provider.AuthorizationURL(
				"state", "challenge", "", "https://auth.example/callback",
			)
			if err != nil {
				t.Fatal(err)
			}
			query := mustURL(t, authorization).Query()
			if query.Get("scope") != "profile email" || query.Get("prompt") != "consent" ||
				query.Get("code_challenge_method") != "S256" {
				t.Fatalf("generic authorization options: %s", authorization)
			}
			result, err := provider.Exchange(
				context.Background(), "code", "verifier", "", "https://auth.example/callback",
			)
			if err != nil {
				t.Fatal(err)
			}
			if result.Profile.ProviderAccountID != "raw-id" ||
				result.Profile.Provider != "generic-"+string(method) || !result.Profile.EmailVerified {
				t.Fatalf("custom mapper result: %#v", result.Profile)
			}
			refreshed, err := provider.Refresh(context.Background(), "refresh")
			if err != nil {
				t.Fatal(err)
			}
			if refreshed.AccessToken != "refreshed" || refreshed.RefreshToken != "next-refresh" {
				t.Fatalf("refresh result: %#v", refreshed)
			}
		})
	}

	t.Run("provider error is sanitized", func(t *testing.T) {
		t.Parallel()
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, `{"error":"invalid_client","client_secret":"must-not-leak"}`, http.StatusBadRequest)
		}))
		defer server.Close()
		provider, err := New("sanitized-error", Options{
			ClientID: "client", ClientSecret: "secret",
			AuthorizationURL: server.URL + "/authorize", TokenURL: server.URL,
			UserInfoURL: server.URL + "/userinfo", HTTPClient: server.Client(),
			AccountSubject: testAccountSubject,
		})
		if err != nil {
			t.Fatal(err)
		}
		_, err = provider.Exchange(context.Background(), "code", "verifier", "", "https://auth.example/callback")
		if err == nil || !strings.Contains(err.Error(), "HTTP 400") ||
			strings.Contains(err.Error(), "must-not-leak") {
			t.Fatalf("unsafe provider error: %v", err)
		}
	})

	t.Run("oversized response is rejected", func(t *testing.T) {
		t.Parallel()
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"padding":"` + strings.Repeat("x", 5000) + `"}`))
		}))
		defer server.Close()
		provider, err := New("bounded-response", Options{
			ClientID: "client", ClientSecret: "secret",
			AuthorizationURL: server.URL + "/authorize", TokenURL: server.URL,
			UserInfoURL: server.URL + "/userinfo", HTTPClient: server.Client(),
			MaxResponseBytes: 4096,
			AccountSubject:   testAccountSubject,
		})
		if err != nil {
			t.Fatal(err)
		}
		_, err = provider.Exchange(context.Background(), "code", "verifier", "", "https://auth.example/callback")
		if err == nil {
			t.Fatal("oversized provider response was accepted")
		}
	})
}

func signIDToken(t *testing.T, key *rsa.PrivateKey, keyID string, claims map[string]any) string {
	return signIDTokenWithAlgorithm(t, key, keyID, "RS256", claims)
}

func signIDTokenWithAlgorithm(
	t *testing.T,
	key *rsa.PrivateKey,
	keyID string,
	algorithm string,
	claims map[string]any,
) string {
	t.Helper()
	header, err := json.Marshal(map[string]string{"alg": algorithm, "kid": keyID, "typ": "JWT"})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." +
		base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

var _ betterauth.Clock = certificationClock{}
