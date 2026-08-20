package betterauth_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	betterauth "github.com/eadwinCode/better-auth-go"
	"github.com/eadwinCode/better-auth-go/adapter/memory"
)

type fixedClock struct{ now time.Time }

func (clock fixedClock) Now() time.Time { return clock.now }

type sequenceTokens struct {
	mu      sync.Mutex
	counter uint64
}

func (source *sequenceTokens) Token(byteLength int) (string, error) {
	source.mu.Lock()
	defer source.mu.Unlock()
	source.counter++
	return fmt.Sprintf("test-token-%03d-%0*d", source.counter, byteLength, source.counter), nil
}

type captureMailer struct {
	mu    sync.Mutex
	mails []betterauth.Mail
}

func (mailer *captureMailer) Send(_ context.Context, message betterauth.Mail) error {
	mailer.mu.Lock()
	defer mailer.mu.Unlock()
	mailer.mails = append(mailer.mails, message)
	return nil
}

func (mailer *captureMailer) last() betterauth.Mail {
	mailer.mu.Lock()
	defer mailer.mu.Unlock()
	return mailer.mails[len(mailer.mails)-1]
}

func (mailer *captureMailer) count() int {
	mailer.mu.Lock()
	defer mailer.mu.Unlock()
	return len(mailer.mails)
}

type allowImpersonation struct{}

func (allowImpersonation) CanImpersonate(
	context.Context,
	betterauth.User,
	betterauth.User,
) error {
	return nil
}

type testClient struct {
	handler  http.Handler
	database *memory.Adapter
	session  *http.Cookie
	csrf     *http.Cookie
}

func newBlackBoxServer(t *testing.T) (*testClient, *captureMailer) {
	return newBlackBoxServerConfig(t, nil)
}

func newBlackBoxServerConfig(
	t *testing.T,
	configure func(*betterauth.Config),
) (*testClient, *captureMailer) {
	t.Helper()
	mailer := &captureMailer{}
	passwords, err := betterauth.NewArgon2idVerifier(betterauth.Argon2Params{
		Memory:      19 * 1024,
		Iterations:  2,
		Parallelism: 1,
		SaltLength:  16,
		KeyLength:   32,
	}, 1024)
	if err != nil {
		t.Fatal(err)
	}
	database := memory.New()
	config := betterauth.Config{
		PublicURL:               "https://auth.example.com",
		TrustedOrigins:          []string{"https://app.example.com"},
		Database:                database,
		Mailer:                  mailer,
		ImpersonationAuthorizer: allowImpersonation{},
		Clock: fixedClock{
			now: time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC),
		},
		Tokens:    &sequenceTokens{},
		Passwords: passwords,
	}
	if configure != nil {
		configure(&config)
	}
	server, err := betterauth.New(config)
	if err != nil {
		t.Fatal(err)
	}
	return &testClient{handler: server.Handler(), database: database}, mailer
}

func (client *testClient) request(
	t *testing.T,
	method string,
	path string,
	body any,
	csrf bool,
) *httptest.ResponseRecorder {
	t.Helper()
	var payload []byte
	if body != nil {
		var err error
		payload, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	request := httptest.NewRequest(
		method,
		"https://auth.example.com/api/auth"+path,
		bytes.NewReader(payload),
	)
	request.Header.Set("Origin", "https://app.example.com")
	request.Header.Set("Content-Type", "application/json")
	if client.session != nil {
		request.AddCookie(client.session)
	}
	if client.csrf != nil {
		request.AddCookie(client.csrf)
		if csrf {
			request.Header.Set("X-CSRF-Token", client.csrf.Value)
		}
	}
	recorder := httptest.NewRecorder()
	client.handler.ServeHTTP(recorder, request)
	for _, cookie := range recorder.Result().Cookies() {
		switch cookie.Name {
		case "__Host-better_auth_session":
			client.session = cookie
		case "__Host-better_auth_csrf":
			client.csrf = cookie
		}
	}
	return recorder
}

type fakeOAuthProvider struct {
	mu         sync.Mutex
	challenges map[string]string
	profile    betterauth.OAuthProfile
	tokens     betterauth.ProviderTokens
}

func (provider *fakeOAuthProvider) AuthorizationURL(
	state string,
	challenge string,
	nonce string,
	redirectURI string,
) (string, error) {
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
	if code != "valid-code" ||
		challenge != base64.RawURLEncoding.EncodeToString(sum[:]) ||
		verifier == "" ||
		nonce == "" ||
		redirectURI != "https://auth.example.com/api/auth/callback/test" {
		return betterauth.OAuthResult{}, betterauth.ErrReplay
	}
	if profile.ProviderAccountID == "" {
		profile = betterauth.OAuthProfile{
			Issuer:            "local:oauth:test",
			ProviderAccountID: "provider-user-1",
			Email:             "oauth@example.com",
			EmailVerified:     true,
			Name:              "OAuth User",
		}
	}
	if tokens.AccessToken == "" {
		tokens = betterauth.ProviderTokens{
			AccessToken:          "plain-access-token",
			RefreshToken:         "plain-refresh-token",
			IDToken:              "plain-id-token",
			Scope:                "openid profile",
			AccessTokenExpiresAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
		}
	}
	return betterauth.OAuthResult{Profile: profile, Tokens: tokens}, nil
}

func (provider *fakeOAuthProvider) Refresh(
	_ context.Context,
	refreshToken string,
) (betterauth.ProviderTokens, error) {
	if refreshToken != "plain-refresh-token" {
		return betterauth.ProviderTokens{}, betterauth.ErrReplay
	}
	return betterauth.ProviderTokens{
		AccessToken:          "refreshed-access-token",
		RefreshToken:         refreshToken,
		IDToken:              "refreshed-id-token",
		Scope:                "openid profile",
		AccessTokenExpiresAt: time.Date(2030, 1, 1, 1, 0, 0, 0, time.UTC),
	}, nil
}
