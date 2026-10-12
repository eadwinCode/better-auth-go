package sso

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"testing"
	"time"

	betterauth "github.com/eadwinCode/better-auth-go"
	"github.com/eadwinCode/better-auth-go/adapter/memory"
)

type unusedSocialProvider struct{}

func (unusedSocialProvider) AuthorizationURL(string, string, string, string) (string, error) {
	return "https://social.example.com/authorize", nil
}

func (unusedSocialProvider) Exchange(context.Context, string, string, string, string) (betterauth.OAuthResult, error) {
	return betterauth.OAuthResult{}, errors.New("not used")
}

// Accounts are keyed by (providerId, accountId). An SSO provider that reuses a
// social provider's ID must not be able to sign in as that provider's users,
// even when it was configured or stored before the registration check existed.
func TestSSOProviderCannotReuseSocialProviderID(t *testing.T) {
	t.Parallel()
	clock := runtimeClock{now: time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)}
	fixture := newOIDCFixture(t, clock)
	cipher, err := betterauth.NewAESGCMTokenCipher([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	plugin, err := New(Config{
		Cipher: cipher, HTTPClient: fixture,
		OutboundURLPolicy: func(context.Context, *url.URL) error { return nil },
		DefaultProviders: []ProviderRegistration{{
			Issuer: "https://idp.example.com", Domain: "example.com",
			ProviderID: "acme-social", OIDC: &OIDCConfig{
				Issuer: "https://idp.example.com", ClientID: "sso-client",
				ClientSecret: "sso-secret",
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	database := memory.New()
	server, err := betterauth.New(betterauth.Config{
		PublicURL:      "https://auth.example.com",
		TrustedOrigins: []string{"https://app.example.com"},
		Database:       database, Clock: clock, Mailer: runtimeMailer{},
		ImpersonationAuthorizer: runtimeImpersonation{},
		ProviderTokenCipher:     cipher, Plugins: []betterauth.Plugin{plugin},
		SocialProviders:         map[string]betterauth.OAuthProvider{"acme-social": unusedSocialProvider{}},
		AllowedRedirectURLs:     []string{"https://app.example.com/dashboard"},
	})
	if err != nil {
		t.Fatal(err)
	}
	now := clock.now
	for _, record := range []struct {
		model string
		data  betterauth.Record
	}{
		{betterauth.ModelUser, betterauth.Record{
			"id": "victim", "email": "victim@example.net", "name": "Victim",
			"emailVerified": true, "createdAt": now, "updatedAt": now,
		}},
		{betterauth.ModelAccount, betterauth.Record{
			"id": "victim-acme", "userId": "victim", "providerId": "acme-social",
			"accountId": "enterprise-user-1", "createdAt": now, "updatedAt": now,
		}},
	} {
		if _, err := database.Create(context.Background(), betterauth.CreateQuery{
			Model: record.model, Data: record.data, ForceAllowID: true,
		}); err != nil {
			t.Fatal(err)
		}
	}

	signIn := ssoRequest(t, server.Handler(), http.MethodPost, "/sign-in/sso", map[string]any{
		"providerId": "acme-social", "callbackURL": "https://app.example.com/dashboard",
	}, nil)
	if signIn.Code != http.StatusOK {
		t.Fatalf("sign in start: %d %s", signIn.Code, signIn.Body.String())
	}
	var authorization struct {
		URL string `json:"url"`
	}
	if err = json.Unmarshal(signIn.Body.Bytes(), &authorization); err != nil {
		t.Fatal(err)
	}
	destination, err := url.Parse(authorization.URL)
	if err != nil {
		t.Fatal(err)
	}
	fixture.mu.Lock()
	fixture.nonce = destination.Query().Get("nonce")
	fixture.mu.Unlock()
	callback := ssoRequest(t, server.Handler(), http.MethodGet,
		"/sso/callback/acme-social?code=valid-code&state="+url.QueryEscape(destination.Query().Get("state")),
		nil, nil)
	t.Logf("DEBUG callback %d %s %s", callback.Code, callback.Header().Get("Location"), callback.Body.String())
	if findCookie(callback.Result().Cookies(), "__Host-better_auth_session") != nil ||
		callback.Header().Get("Location") == "https://app.example.com/dashboard" {
		t.Fatalf("SSO provider named like a social provider signed in: %d %s %s",
			callback.Code, callback.Header().Get("Location"), callback.Body.String())
	}
}

func TestSSORegistrationRejectsAccountProviderIDs(t *testing.T) {
	t.Parallel()
	instance := &runtime{defaults: map[string]ProviderRegistration{"default-sso": {}}}
	ctx := &betterauth.HookContext{
		AccountProviderInUse: func(id string) (bool, error) {
			return id == "github" || id == "trusted-idp", nil
		},
	}
	for id, reserved := range map[string]bool{
		"github": true, "trusted-idp": true, "default-sso": true, "enterprise": false,
	} {
		err := instance.rejectAccountProviderID(ctx, id)
		var authErr *betterauth.Error
		if reserved != (err != nil) {
			t.Fatalf("%s: err=%v", id, err)
		}
		if reserved && (!errors.As(err, &authErr) || authErr.Status != http.StatusUnprocessableEntity ||
			authErr.Message != "This providerId is reserved and cannot be used for an SSO provider") {
			t.Fatalf("%s: err=%#v", id, err)
		}
	}
	if err := instance.rejectAccountProviderID(&betterauth.HookContext{}, "enterprise"); err == nil {
		t.Fatal("missing kernel check was treated as unreserved")
	}
}
