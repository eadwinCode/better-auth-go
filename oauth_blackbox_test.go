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

	betterauth "github.com/eadwinCode/better-auth-go"
	"github.com/eadwinCode/better-auth-go/adapter/memory"
)

type fakeOAuthProvider struct {
	mu        sync.Mutex
	challenge string
	nonce     string
}

func (provider *fakeOAuthProvider) AuthorizationURL(state, challenge, nonce, redirectURI string) (string, error) {
	provider.mu.Lock()
	provider.challenge = challenge
	provider.nonce = nonce
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
	challenge := provider.challenge
	expectedNonce := provider.nonce
	provider.mu.Unlock()
	sum := sha256.Sum256([]byte(verifier))
	if code != "valid-code" || challenge != base64.RawURLEncoding.EncodeToString(sum[:]) || verifier == "" || nonce != expectedNonce ||
		redirectURI != "https://auth.example.com/api/auth/callback/test" {
		return betterauth.OAuthResult{}, betterauth.ErrReplay
	}
	return betterauth.OAuthResult{
		Profile: betterauth.OAuthProfile{
			ProviderAccountID: "provider-user-1", Email: "oauth@example.com",
			EmailVerified: true, Name: "OAuth User",
		},
		Tokens: betterauth.ProviderTokens{
			AccessToken: "plain-access-token", RefreshToken: "plain-refresh-token",
		},
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
}
