package betterauth_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	betterauth "github.com/eadwinCode/better-auth-go"
)

func TestConcurrentSessionRefreshHasOneWinner(t *testing.T) {
	t.Parallel()
	client, _ := newBlackBoxServer(t)
	if response := client.request(t, http.MethodPost, "/sign-up/email", map[string]any{
		"email":    "refresh-race@example.com",
		"password": "correct horse battery staple",
		"name":     "Refresh Race",
	}, false); response.Code != http.StatusOK {
		t.Fatal(response.Body.String())
	}
	oldSession := *client.session
	csrf := *client.csrf
	start := make(chan struct{})
	results := make(chan *httptest.ResponseRecorder, 2)
	var wait sync.WaitGroup
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			request := httptest.NewRequest(
				http.MethodPost,
				"https://auth.example.com/api/auth/refresh-session",
				bytes.NewBufferString(`{}`),
			)
			request.Header.Set("Origin", "https://app.example.com")
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("X-CSRF-Token", csrf.Value)
			request.AddCookie(&oldSession)
			request.AddCookie(&csrf)
			recorder := httptest.NewRecorder()
			client.handler.ServeHTTP(recorder, request)
			results <- recorder
		}()
	}
	close(start)
	wait.Wait()
	close(results)

	statuses := map[int]int{}
	var replacement *http.Cookie
	for result := range results {
		statuses[result.Code]++
		if result.Code == http.StatusOK {
			for _, cookie := range result.Result().Cookies() {
				if cookie.Name == oldSession.Name {
					copied := *cookie
					replacement = &copied
				}
			}
		}
	}
	if statuses[http.StatusOK] != 1 || statuses[http.StatusUnauthorized] != 1 ||
		replacement == nil || replacement.Value == oldSession.Value {
		t.Fatalf("session refresh race was not one-winner: statuses=%v replacement=%#v", statuses, replacement)
	}
	oldClient := &testClient{
		handler: client.handler, database: client.database, session: &oldSession, csrf: &csrf,
	}
	if response := oldClient.request(t, http.MethodGet, "/get-session", nil, false); response.Code != http.StatusOK || strings.TrimSpace(response.Body.String()) != "null" {
		t.Fatalf("rotated session remained valid: %d %s", response.Code, response.Body)
	}
	newClient := &testClient{
		handler: client.handler, database: client.database, session: replacement, csrf: &csrf,
	}
	if response := newClient.request(t, http.MethodGet, "/get-session", nil, false); response.Code != http.StatusOK || strings.TrimSpace(response.Body.String()) == "null" {
		t.Fatalf("winning replacement is invalid: %d %s", response.Code, response.Body)
	}
}

type providerWithoutRefresh struct {
	inner *fakeOAuthProvider
}

func (provider providerWithoutRefresh) AuthorizationURL(
	state string,
	challenge string,
	nonce string,
	redirectURI string,
) (string, error) {
	return provider.inner.AuthorizationURL(state, challenge, nonce, redirectURI)
}

func (provider providerWithoutRefresh) Exchange(
	ctx context.Context,
	code string,
	verifier string,
	nonce string,
	redirectURI string,
) (betterauth.OAuthResult, error) {
	return provider.inner.Exchange(ctx, code, verifier, nonce, redirectURI)
}

type controlledRefreshProvider struct {
	inner   *fakeOAuthProvider
	refresh func(context.Context, string) (betterauth.ProviderTokens, error)
	calls   atomic.Int64
}

func (provider *controlledRefreshProvider) AuthorizationURL(
	state string,
	challenge string,
	nonce string,
	redirectURI string,
) (string, error) {
	return provider.inner.AuthorizationURL(state, challenge, nonce, redirectURI)
}

func (provider *controlledRefreshProvider) Exchange(
	ctx context.Context,
	code string,
	verifier string,
	nonce string,
	redirectURI string,
) (betterauth.OAuthResult, error) {
	return provider.inner.Exchange(ctx, code, verifier, nonce, redirectURI)
}

func (provider *controlledRefreshProvider) Refresh(
	ctx context.Context,
	refreshToken string,
) (betterauth.ProviderTokens, error) {
	provider.calls.Add(1)
	return provider.refresh(ctx, refreshToken)
}

func newProviderCertificationClient(
	t *testing.T,
	provider betterauth.OAuthProvider,
) *testClient {
	t.Helper()
	cipher, err := betterauth.NewAESGCMTokenCipher(
		[]byte("0123456789abcdef0123456789abcdef"),
	)
	if err != nil {
		t.Fatal(err)
	}
	client, _ := newBlackBoxServerConfig(t, func(config *betterauth.Config) {
		config.AllowedRedirectURLs = []string{
			"https://app.example.com/success",
			"https://app.example.com/error",
			"https://app.example.com/new-user",
		}
		config.SocialProviders = map[string]betterauth.OAuthProvider{"test": provider}
		config.ProviderTokenCipher = cipher
	})
	authorization := startGoOAuth(t, client, "/sign-in/social", oauthPolicyInput(), false)
	destination := callbackGoOAuth(t, client, authorization, "code=valid-code")
	if destination.String() != "https://app.example.com/new-user" {
		t.Fatalf("provider fixture sign-in destination=%s", destination)
	}
	return client
}

func TestProviderTokenRefreshFailureAndPreservationMatrix(t *testing.T) {
	t.Run("unsupported provider", func(t *testing.T) {
		inner := &fakeOAuthProvider{}
		inner.setTokens(providerCertificationTokens("plain-refresh-token"))
		client := newProviderCertificationClient(t, providerWithoutRefresh{inner: inner})
		assertProviderTokenCode(t, client, "TOKEN_REFRESH_NOT_SUPPORTED")
	})

	t.Run("missing refresh token", func(t *testing.T) {
		inner := &fakeOAuthProvider{}
		tokens := providerCertificationTokens("")
		inner.setTokens(tokens)
		client := newProviderCertificationClient(t, inner)
		assertProviderTokenCode(t, client, "REFRESH_TOKEN_NOT_FOUND")
	})

	t.Run("expired refresh token", func(t *testing.T) {
		inner := &fakeOAuthProvider{}
		tokens := providerCertificationTokens("plain-refresh-token")
		tokens.RefreshTokenExpiresAt = time.Date(2026, 7, 28, 11, 59, 0, 0, time.UTC)
		inner.setTokens(tokens)
		client := newProviderCertificationClient(t, inner)
		assertProviderTokenCode(t, client, "REFRESH_TOKEN_NOT_FOUND")
	})

	t.Run("provider failure", func(t *testing.T) {
		inner := &fakeOAuthProvider{}
		inner.setTokens(providerCertificationTokens("plain-refresh-token"))
		provider := &controlledRefreshProvider{
			inner: inner,
			refresh: func(context.Context, string) (betterauth.ProviderTokens, error) {
				return betterauth.ProviderTokens{}, errors.New("provider-secret")
			},
		}
		client := newProviderCertificationClient(t, provider)
		response := client.request(t, http.MethodPost, "/refresh-token", map[string]any{
			"providerId": "test",
		}, true)
		if response.Code != http.StatusBadRequest ||
			!bytes.Contains(response.Body.Bytes(), []byte(`"code":"FAILED_TO_REFRESH_ACCESS_TOKEN"`)) ||
			bytes.Contains(response.Body.Bytes(), []byte("provider-secret")) {
			t.Fatalf("provider failure response=%d %s", response.Code, response.Body)
		}
	})

	t.Run("replacement fields are preserved and encrypted", func(t *testing.T) {
		inner := &fakeOAuthProvider{}
		inner.setTokens(providerCertificationTokens("single-use-refresh-token"))
		provider := &controlledRefreshProvider{
			inner: inner,
			refresh: func(_ context.Context, token string) (betterauth.ProviderTokens, error) {
				if token != "single-use-refresh-token" {
					return betterauth.ProviderTokens{}, errors.New("unexpected refresh token")
				}
				return betterauth.ProviderTokens{
					AccessToken:          "replacement-access-token",
					AccessTokenExpiresAt: time.Date(2030, 1, 1, 1, 0, 0, 0, time.UTC),
				}, nil
			},
		}
		client := newProviderCertificationClient(t, provider)
		response := client.request(t, http.MethodPost, "/refresh-token", map[string]any{
			"providerId": "test",
		}, true)
		if response.Code != http.StatusOK {
			t.Fatalf("refresh status=%d body=%s", response.Code, response.Body)
		}
		body := decodeBlackboxObject(t, response.Body.Bytes())
		if body["accessToken"] != "replacement-access-token" ||
			body["idToken"] != "fixture-id-token" ||
			body["scope"] != "openid profile" {
			t.Fatalf("preserved refresh response mismatch: %#v", body)
		}
		if _, exposed := body["refreshToken"]; exposed {
			t.Fatalf("provider refresh token leaked: %#v", body)
		}
		account, err := client.database.FindOne(context.Background(), betterauth.FindOneQuery{
			Model: betterauth.ModelAccount,
			Where: []betterauth.Where{
				betterauth.Eq("providerId", "test"),
				betterauth.Eq("accountId", "provider-user-1"),
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		plaintext := map[string]string{
			"accessToken":  "replacement-access-token",
			"refreshToken": "single-use-refresh-token",
			"idToken":      "fixture-id-token",
		}
		for field, exposed := range plaintext {
			value, _ := account[field].(string)
			if value == "" || value == exposed {
				t.Fatalf("provider credential %s is not encrypted: %#v", field, account)
			}
		}
	})
}

func TestProviderAccessTokenAutoRefreshPersistsOnce(t *testing.T) {
	t.Parallel()
	inner := &fakeOAuthProvider{}
	tokens := providerCertificationTokens("auto-refresh-token")
	tokens.AccessTokenExpiresAt = time.Date(2026, 7, 28, 12, 0, 4, 0, time.UTC)
	inner.setTokens(tokens)
	provider := &controlledRefreshProvider{
		inner: inner,
		refresh: func(_ context.Context, token string) (betterauth.ProviderTokens, error) {
			if token != "auto-refresh-token" {
				return betterauth.ProviderTokens{}, errors.New("unexpected refresh token")
			}
			return betterauth.ProviderTokens{
				AccessToken:          "auto-refreshed-access-token",
				RefreshToken:         token,
				IDToken:              "auto-refreshed-id-token",
				Scope:                "openid profile",
				AccessTokenExpiresAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
			}, nil
		},
	}
	client := newProviderCertificationClient(t, provider)
	for range 2 {
		response := client.request(t, http.MethodPost, "/get-access-token", map[string]any{
			"providerId": "test",
		}, true)
		if response.Code != http.StatusOK {
			t.Fatalf("get-access-token status=%d body=%s", response.Code, response.Body)
		}
		body := decodeBlackboxObject(t, response.Body.Bytes())
		if body["accessToken"] != "auto-refreshed-access-token" {
			t.Fatalf("automatic refresh response mismatch: %#v", body)
		}
		if _, exposed := body["refreshToken"]; exposed {
			t.Fatalf("automatic refresh leaked refresh token: %#v", body)
		}
	}
	if provider.calls.Load() != 1 {
		t.Fatalf("persisted automatic refresh was repeated: calls=%d", provider.calls.Load())
	}
}

func TestConcurrentSingleUseProviderRefreshHasOneWinner(t *testing.T) {
	t.Parallel()
	inner := &fakeOAuthProvider{}
	inner.setTokens(providerCertificationTokens("single-use-refresh-token"))
	var consumed atomic.Bool
	provider := &controlledRefreshProvider{
		inner: inner,
		refresh: func(_ context.Context, token string) (betterauth.ProviderTokens, error) {
			if token != "single-use-refresh-token" || !consumed.CompareAndSwap(false, true) {
				return betterauth.ProviderTokens{}, errors.New("refresh token already consumed")
			}
			return betterauth.ProviderTokens{
				AccessToken:           "concurrent-winner-access-token",
				RefreshToken:          "rotated-refresh-token",
				IDToken:               "concurrent-winner-id-token",
				Scope:                 "openid profile",
				AccessTokenExpiresAt:  time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
				RefreshTokenExpiresAt: time.Date(2030, 1, 2, 0, 0, 0, 0, time.UTC),
			}, nil
		},
	}
	client := newProviderCertificationClient(t, provider)
	body := []byte(`{"providerId":"test"}`)
	start := make(chan struct{})
	results := make(chan *httptest.ResponseRecorder, 2)
	var wait sync.WaitGroup
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			request := httptest.NewRequest(
				http.MethodPost,
				"https://auth.example.com/api/auth/refresh-token",
				bytes.NewReader(body),
			)
			request.Header.Set("Origin", "https://app.example.com")
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("X-CSRF-Token", client.csrf.Value)
			request.AddCookie(client.session)
			request.AddCookie(client.csrf)
			recorder := httptest.NewRecorder()
			client.handler.ServeHTTP(recorder, request)
			results <- recorder
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	statuses := map[int]int{}
	for result := range results {
		statuses[result.Code]++
		if bytes.Contains(result.Body.Bytes(), []byte("already consumed")) {
			t.Fatalf("provider failure detail leaked: %s", result.Body)
		}
	}
	if statuses[http.StatusOK] != 1 || statuses[http.StatusBadRequest] != 1 {
		t.Fatalf("provider refresh race was not one-winner: %#v", statuses)
	}
	response := client.request(t, http.MethodPost, "/get-access-token", map[string]any{
		"providerId": "test",
	}, true)
	if response.Code != http.StatusOK {
		t.Fatalf("persisted winner token is unreadable: %d %s", response.Code, response.Body)
	}
	responseBody := decodeBlackboxObject(t, response.Body.Bytes())
	if responseBody["accessToken"] != "concurrent-winner-access-token" {
		t.Fatalf("wrong persisted winner token: %#v", responseBody)
	}
}

func providerCertificationTokens(refreshToken string) betterauth.ProviderTokens {
	return betterauth.ProviderTokens{
		AccessToken:           "fixture-access-token",
		RefreshToken:          refreshToken,
		IDToken:               "fixture-id-token",
		Scope:                 "openid profile",
		AccessTokenExpiresAt:  time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
		RefreshTokenExpiresAt: time.Date(2030, 1, 2, 0, 0, 0, 0, time.UTC),
	}
}

func assertProviderTokenCode(t *testing.T, client *testClient, code string) {
	t.Helper()
	response := client.request(t, http.MethodPost, "/refresh-token", map[string]any{
		"providerId": "test",
	}, true)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("provider token status=%d body=%s", response.Code, response.Body)
	}
	body := decodeBlackboxObject(t, response.Body.Bytes())
	if body["code"] != code {
		t.Fatalf("provider token code=%v, want %s: %#v", body["code"], code, body)
	}
}

func decodeBlackboxObject(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("decode response %q: %v", body, err)
	}
	return result
}
