package betterauth_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	betterauth "github.com/eadwinCode/better-auth-go"
	"github.com/eadwinCode/better-auth-go/adapter/memory"
)

type fakeOAuthProvider struct {
	mu                    sync.Mutex
	challenges            map[string]string
	profile               betterauth.OAuthProfile
	tokens                betterauth.ProviderTokens
	disableImplicitSignUp bool
	disableSignUp         bool
}

func (provider *fakeOAuthProvider) DisableImplicitSignUp() bool {
	return provider.disableImplicitSignUp
}

func (provider *fakeOAuthProvider) DisableSignUp() bool { return provider.disableSignUp }

func (provider *fakeOAuthProvider) AuthorizationURL(state, challenge, nonce, redirectURI string) (string, error) {
	provider.mu.Lock()
	if provider.challenges == nil {
		provider.challenges = map[string]string{}
	}
	provider.challenges[nonce] = challenge
	provider.mu.Unlock()
	destination := &url.URL{Scheme: "https", Host: "provider.example", Path: "/authorize"}
	query := destination.Query()
	query.Set("state", state)
	query.Set("redirect_uri", redirectURI)
	query.Set("code_challenge", challenge)
	query.Set("nonce", nonce)
	destination.RawQuery = query.Encode()
	return destination.String(), nil
}

func (provider *fakeOAuthProvider) Exchange(
	_ context.Context,
	code string,
	verifier string,
	nonce string,
	redirectURI string,
) (betterauth.OAuthResult, error) {
	provider.mu.Lock()
	challenge := provider.challenges[nonce]
	profile := provider.profile
	tokens := provider.tokens
	provider.mu.Unlock()
	sum := sha256.Sum256([]byte(verifier))
	if code != "valid-code" || challenge != base64.RawURLEncoding.EncodeToString(sum[:]) || verifier == "" || nonce == "" ||
		redirectURI != "https://auth.example.com/api/auth/callback/test" {
		return betterauth.OAuthResult{}, betterauth.ErrReplay
	}
	if profile.ProviderAccountID == "" {
		profile = betterauth.OAuthProfile{
			ProviderAccountID: "provider-user-1", Email: "oauth@example.com",
			EmailVerified: true, Name: "OAuth User",
		}
	}
	if tokens.AccessToken == "" {
		tokens = betterauth.ProviderTokens{
			AccessToken: "plain-access-token", RefreshToken: "plain-refresh-token",
			IDToken: "plain-id-token", Scope: "openid profile",
			AccessTokenExpiresAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
		}
	}
	return betterauth.OAuthResult{
		Profile: profile,
		Tokens:  tokens,
	}, nil
}

func (provider *fakeOAuthProvider) setTokens(tokens betterauth.ProviderTokens) {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	provider.tokens = tokens
}

func (provider *fakeOAuthProvider) Refresh(
	_ context.Context,
	refreshToken string,
) (betterauth.ProviderTokens, error) {
	if refreshToken != "plain-refresh-token" {
		return betterauth.ProviderTokens{}, betterauth.ErrReplay
	}
	return betterauth.ProviderTokens{
		AccessToken: "refreshed-access-token", RefreshToken: refreshToken,
		IDToken: "refreshed-id-token", Scope: "openid profile",
		AccessTokenExpiresAt: time.Date(2030, 1, 1, 1, 0, 0, 0, time.UTC),
	}, nil
}

func TestOAuthStatePKCERedirectAndEncryptedTokens(t *testing.T) {
	t.Parallel()
	database := memory.New()
	provider := &fakeOAuthProvider{}
	cipher, err := betterauth.NewAESGCMTokenCipher([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	server, err := betterauth.New(betterauth.Config{
		PublicURL: "https://auth.example.com", TrustedOrigins: []string{"https://app.example.com"},
		AllowedRedirectURLs: []string{"https://app.example.com/dashboard"},
		Database:            database, Mailer: discardMailer{}, ImpersonationAuthorizer: denyImpersonation{},
		Tokens: &sequenceTokens{}, ProviderTokenCipher: cipher,
		SocialProviders: map[string]betterauth.OAuthProvider{"test": provider},
	})
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"provider":"test","callbackURL":"https://app.example.com/dashboard","disableRedirect":true}`)
	request := httptest.NewRequest(http.MethodPost, "https://auth.example.com/api/auth/sign-in/social", bytes.NewReader(body))
	request.Header.Set("Origin", "https://app.example.com")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("authorize response %d: %s", recorder.Code, recorder.Body.String())
	}
	var authorization struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &authorization); err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(authorization.URL)
	if err != nil {
		t.Fatal(err)
	}
	state := parsed.Query().Get("state")
	if state == "" || parsed.Query().Get("code_challenge") == "" || parsed.Query().Get("nonce") == "" {
		t.Fatalf("incomplete authorization URL: %s", authorization.URL)
	}

	callback := httptest.NewRequest(
		http.MethodGet,
		"https://auth.example.com/api/auth/callback/test?state="+url.QueryEscape(state)+"&code=valid-code",
		nil,
	)
	callbackRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(callbackRecorder, callback)
	if callbackRecorder.Code != http.StatusFound ||
		callbackRecorder.Header().Get("Location") != "https://app.example.com/dashboard" {
		t.Fatalf("callback response %d location=%q body=%s", callbackRecorder.Code, callbackRecorder.Header().Get("Location"), callbackRecorder.Body.String())
	}
	account, err := database.FindOne(context.Background(), betterauth.FindOneQuery{
		Model: betterauth.ModelAccount, Where: []betterauth.Where{
			betterauth.Eq("providerId", "test"), betterauth.Eq("accountId", "provider-user-1"),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	encrypted, _ := account["accessToken"].(string)
	if encrypted == "" || encrypted == "plain-access-token" {
		t.Fatalf("provider token was not encrypted: %#v", account)
	}
	plaintext, err := cipher.Open(context.Background(), encrypted)
	if err != nil || plaintext != "plain-access-token" {
		t.Fatalf("encrypted token did not round trip: %q, %v", plaintext, err)
	}

	replay := httptest.NewRecorder()
	server.Handler().ServeHTTP(replay, callback.Clone(context.Background()))
	if replay.Code != http.StatusBadRequest {
		t.Fatalf("state replay was not rejected: %d %s", replay.Code, replay.Body.String())
	}

	client := &testClient{handler: server.Handler(), database: database}
	for _, cookie := range callbackRecorder.Result().Cookies() {
		switch cookie.Name {
		case "__Host-better_auth_session":
			client.session = cookie
		case "__Host-better_auth_csrf":
			client.csrf = cookie
		}
	}
	access := client.request(t, http.MethodPost, "/get-access-token", map[string]any{
		"providerId": "test",
	}, true)
	if access.Code != http.StatusOK ||
		!bytes.Contains(access.Body.Bytes(), []byte(`"accessToken":"plain-access-token"`)) ||
		bytes.Contains(access.Body.Bytes(), []byte("plain-refresh-token")) {
		t.Fatalf("get-access-token: %d %s", access.Code, access.Body.String())
	}
	refreshed := client.request(t, http.MethodPost, "/refresh-token", map[string]any{
		"providerId": "test",
	}, true)
	if refreshed.Code != http.StatusOK ||
		!bytes.Contains(refreshed.Body.Bytes(), []byte(`"accessToken":"refreshed-access-token"`)) {
		t.Fatalf("refresh-token: %d %s", refreshed.Code, refreshed.Body.String())
	}
}

func TestOAuthAccountLinkingRequiresMatchingAuthenticatedUser(t *testing.T) {
	t.Parallel()
	database := memory.New()
	provider := &fakeOAuthProvider{}
	cipher, err := betterauth.NewAESGCMTokenCipher([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	passwords, err := betterauth.NewArgon2idVerifier(betterauth.Argon2Params{
		Memory: 19 * 1024, Iterations: 2, Parallelism: 1, SaltLength: 16, KeyLength: 32,
	}, 1024)
	if err != nil {
		t.Fatal(err)
	}
	server, err := betterauth.New(betterauth.Config{
		PublicURL: "https://auth.example.com", TrustedOrigins: []string{"https://app.example.com"},
		AllowedRedirectURLs: []string{"https://app.example.com/dashboard"},
		Database:            database, Mailer: discardMailer{}, ImpersonationAuthorizer: denyImpersonation{},
		Tokens: &sequenceTokens{}, Passwords: passwords, ProviderTokenCipher: cipher,
		SocialProviders: map[string]betterauth.OAuthProvider{"test": provider},
	})
	if err != nil {
		t.Fatal(err)
	}
	client := &testClient{handler: server.Handler(), database: database}
	signup := client.request(t, http.MethodPost, "/sign-up/email", map[string]any{
		"email": "oauth@example.com", "password": "correct horse battery staple", "name": "OAuth User",
	}, false)
	if signup.Code != http.StatusOK {
		t.Fatal(signup.Body.String())
	}
	start := client.request(t, http.MethodPost, "/link-social", map[string]any{
		"provider": "test", "callbackURL": "https://app.example.com/dashboard", "disableRedirect": true,
	}, true)
	if start.Code != http.StatusOK {
		t.Fatalf("link-social: %d %s", start.Code, start.Body.String())
	}
	var authorization struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(start.Body.Bytes(), &authorization); err != nil {
		t.Fatal(err)
	}
	destination, err := url.Parse(authorization.URL)
	if err != nil {
		t.Fatal(err)
	}
	callback := client.request(
		t, http.MethodGet,
		"/callback/test?state="+url.QueryEscape(destination.Query().Get("state"))+"&code=valid-code",
		nil, false,
	)
	if callback.Code != http.StatusFound {
		t.Fatalf("link callback: %d %s", callback.Code, callback.Body.String())
	}
	accounts := client.request(t, http.MethodGet, "/list-accounts", nil, false)
	var linked []betterauth.OAuthAccount
	if err := json.Unmarshal(accounts.Body.Bytes(), &linked); err != nil {
		t.Fatal(err)
	}
	if len(linked) != 2 {
		t.Fatalf("expected credential and linked account: %s", accounts.Body.String())
	}
}
