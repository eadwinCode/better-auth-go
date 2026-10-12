package betterauth_test

import (
	"net/http"
	"testing"

	betterauth "github.com/eadwinCode/better-auth-go"
)

// Providers such as Reddit and Roblox return no email, so the presets use an
// unverified `{id}@{provider}.placeholder.invalid` address. Go keeps its
// documented verified-email gate for these profiles: an untrusted provider is
// refused, and a provider the application lists in TrustedProviders is
// accepted as verified evidence.
func TestOAuthPlaceholderEmailFollowsVerifiedEmailGate(t *testing.T) {
	t.Parallel()
	placeholder, err := betterauth.CreatePlaceholderEmail(betterauth.PlaceholderEmailOptions{
		Identifier: "reddit-user-1", Namespace: "reddit",
	})
	if err != nil {
		t.Fatal(err)
	}
	profile := betterauth.OAuthProfile{
		ProviderAccountID: "reddit-user-1", Email: placeholder, EmailVerified: false, Name: "Reddit User",
	}

	t.Run("untrusted provider is refused", func(t *testing.T) {
		t.Parallel()
		client := newOAuthPolicyClient(t, &fakeOAuthProvider{profile: profile}, nil)
		authorization := startGoOAuth(t, client, "/sign-in/social", oauthPolicyInput(), false)
		destination := callbackGoOAuth(t, client, authorization, "code=valid-code")
		if destination.Query().Get("error") != "unable_to_get_user_info" {
			t.Fatalf("unverified placeholder identity was accepted: %s", destination)
		}
	})

	t.Run("trusted provider signs up with the placeholder", func(t *testing.T) {
		t.Parallel()
		client := newOAuthPolicyClient(t, &fakeOAuthProvider{profile: profile}, func(config *betterauth.Config) {
			config.Account.TrustedProviders = []string{"test"}
		})
		authorization := startGoOAuth(t, client, "/sign-in/social", oauthPolicyInput(), false)
		destination := callbackGoOAuth(t, client, authorization, "code=valid-code")
		if destination.String() != "https://app.example.com/new-user" {
			t.Fatalf("trusted placeholder identity was refused: %s", destination)
		}
		session := client.request(t, http.MethodGet, "/get-session", nil, false)
		if session.Code != http.StatusOK ||
			!containsAny(session.Body.String(), `"email":"reddit-user-1@reddit.placeholder.invalid"`) ||
			!containsAny(session.Body.String(), `"emailVerified":true`) {
			t.Fatalf("trusted placeholder session: %s", session.Body.String())
		}
	})
}
