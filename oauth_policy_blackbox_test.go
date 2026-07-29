package betterauth_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	betterauth "github.com/eadwinCode/better-auth-go"
)

func newOAuthPolicyClient(
	t *testing.T,
	provider *fakeOAuthProvider,
	configure func(*betterauth.Config),
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
		if configure != nil {
			configure(config)
		}
	})
	return client
}

func startGoOAuth(
	t *testing.T,
	client *testClient,
	path string,
	body map[string]any,
	csrf bool,
) *url.URL {
	t.Helper()
	response := client.request(t, http.MethodPost, path, body, csrf)
	if response.Code != http.StatusOK {
		t.Fatalf("OAuth start status=%d body=%s", response.Code, response.Body.String())
	}
	var output struct {
		URL      string `json:"url"`
		Redirect bool   `json:"redirect"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &output); err != nil {
		t.Fatal(err)
	}
	if output.URL == "" || output.Redirect {
		t.Fatalf("unexpected disableRedirect response: %s", response.Body.String())
	}
	authorization, err := url.Parse(output.URL)
	if err != nil {
		t.Fatal(err)
	}
	return authorization
}

func callbackGoOAuth(
	t *testing.T,
	client *testClient,
	authorization *url.URL,
	query string,
) *url.URL {
	t.Helper()
	response := client.request(
		t, http.MethodGet,
		"/callback/test?state="+url.QueryEscape(authorization.Query().Get("state"))+"&"+query,
		nil, false,
	)
	if response.Code != http.StatusFound {
		t.Fatalf("OAuth callback status=%d body=%s", response.Code, response.Body.String())
	}
	destination, err := url.Parse(response.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return destination
}

func oauthPolicyInput() map[string]any {
	return map[string]any{
		"provider": "test", "callbackURL": "https://app.example.com/success",
		"errorCallbackURL":   "https://app.example.com/error",
		"newUserCallbackURL": "https://app.example.com/new-user", "disableRedirect": true,
	}
}

func TestOAuthProviderErrorsAreStateBoundSingleUseAndSanitized(t *testing.T) {
	t.Parallel()
	client := newOAuthPolicyClient(t, &fakeOAuthProvider{}, nil)
	authorization := startGoOAuth(t, client, "/sign-in/social", oauthPolicyInput(), false)
	destination := callbackGoOAuth(
		t, client, authorization,
		"error="+url.QueryEscape("unknown<script>")+"&error_description="+url.QueryEscape("secret-description"),
	)
	if destination.Scheme+"://"+destination.Host+destination.Path != "https://app.example.com/error" ||
		destination.Query().Get("error") != "provider_error" ||
		containsAny(destination.String(), "script", "secret-description") {
		t.Fatalf("provider error was not sanitized: %s", destination)
	}
	replay := client.request(
		t, http.MethodGet,
		"/callback/test?state="+url.QueryEscape(authorization.Query().Get("state"))+"&error=access_denied",
		nil, false,
	)
	if replay.Code != http.StatusBadRequest || replay.Header().Get("Location") != "" {
		t.Fatalf("provider-error state replay was not rejected: %d %s", replay.Code, replay.Body.String())
	}

	mismatched := startGoOAuth(t, client, "/sign-in/social", oauthPolicyInput(), false)
	state := url.QueryEscape(mismatched.Query().Get("state"))
	wrongProvider := client.request(
		t, http.MethodGet, "/callback/missing?state="+state+"&error=access_denied", nil, false,
	)
	if wrongProvider.Code != http.StatusBadRequest || wrongProvider.Header().Get("Location") != "" {
		t.Fatalf("mismatched provider callback was not rejected: %d %s", wrongProvider.Code, wrongProvider.Body.String())
	}
	originalProvider := client.request(
		t, http.MethodGet, "/callback/test?state="+state+"&code=valid-code", nil, false,
	)
	if originalProvider.Code != http.StatusBadRequest {
		t.Fatalf("mismatched provider callback did not consume state: %d %s", originalProvider.Code, originalProvider.Body.String())
	}
}

func TestOAuthImplicitLinkingRequiresVerifiedLocalEmail(t *testing.T) {
	t.Parallel()
	client := newOAuthPolicyClient(t, &fakeOAuthProvider{}, nil)
	signup := client.request(t, http.MethodPost, "/sign-up/email", map[string]any{
		"email": "oauth@example.com", "password": "correct horse battery staple", "name": "Local User",
	}, false)
	if signup.Code != http.StatusOK {
		t.Fatal(signup.Body.String())
	}
	authorization := startGoOAuth(t, client, "/sign-in/social", oauthPolicyInput(), false)
	destination := callbackGoOAuth(t, client, authorization, "code=valid-code")
	if destination.Query().Get("error") != "account_not_linked" {
		t.Fatalf("unverified local identity was implicitly linked: %s", destination)
	}

	var signupBody map[string]any
	if err := json.Unmarshal(signup.Body.Bytes(), &signupBody); err != nil {
		t.Fatal(err)
	}
	userID := signupBody["user"].(map[string]any)["id"].(string)
	if _, err := client.database.Update(context.Background(), betterauth.UpdateQuery{
		Model: betterauth.ModelUser, Where: []betterauth.Where{betterauth.Eq("id", userID)},
		Update: betterauth.Record{"emailVerified": true},
	}); err != nil {
		t.Fatal(err)
	}
	authorization = startGoOAuth(t, client, "/sign-in/social", oauthPolicyInput(), false)
	destination = callbackGoOAuth(t, client, authorization, "code=valid-code")
	if destination.String() != "https://app.example.com/success" {
		t.Fatalf("verified local identity was not linked: %s", destination)
	}
}

func TestOAuthLocalVerificationRequirementCanBeDisabled(t *testing.T) {
	t.Parallel()
	required := false
	client := newOAuthPolicyClient(t, &fakeOAuthProvider{}, func(config *betterauth.Config) {
		config.Account.RequireLocalEmailVerified = &required
	})
	signup := client.request(t, http.MethodPost, "/sign-up/email", map[string]any{
		"email": "oauth@example.com", "password": "correct horse battery staple", "name": "Migrating User",
	}, false)
	if signup.Code != http.StatusOK {
		t.Fatal(signup.Body.String())
	}
	authorization := startGoOAuth(t, client, "/sign-in/social", oauthPolicyInput(), false)
	destination := callbackGoOAuth(t, client, authorization, "code=valid-code")
	if destination.String() != "https://app.example.com/success" {
		t.Fatalf("local-verification opt-out did not link: %s", destination)
	}
	session := client.request(t, http.MethodGet, "/get-session", nil, false)
	if session.Code != http.StatusOK || !containsAny(session.Body.String(), `"emailVerified":true`) {
		t.Fatalf("verified provider evidence did not promote the matching local email: %s", session.Body.String())
	}
}

func TestOAuthDisableImplicitLinkingStillAllowsNewUsers(t *testing.T) {
	t.Parallel()
	t.Run("existing same-email user", func(t *testing.T) {
		client := newOAuthPolicyClient(t, &fakeOAuthProvider{}, func(config *betterauth.Config) {
			config.Account.DisableImplicitLinking = true
		})
		signup := goResponse(client.request(t, http.MethodPost, "/sign-up/email", map[string]any{
			"email": "oauth@example.com", "password": "correct horse battery staple", "name": "Existing User",
		}, false))
		if signup.status != http.StatusOK {
			t.Fatal(string(signup.body))
		}
		userID := responseUser(t, signup)["id"].(string)
		if _, err := client.database.Update(context.Background(), betterauth.UpdateQuery{
			Model: betterauth.ModelUser, Where: []betterauth.Where{betterauth.Eq("id", userID)},
			Update: betterauth.Record{"emailVerified": true},
		}); err != nil {
			t.Fatal(err)
		}
		authorization := startGoOAuth(t, client, "/sign-in/social", oauthPolicyInput(), false)
		destination := callbackGoOAuth(t, client, authorization, "code=valid-code")
		if destination.Query().Get("error") != "account_not_linked" {
			t.Fatalf("disableImplicitLinking was ignored: %s", destination)
		}
	})

	t.Run("genuinely new user", func(t *testing.T) {
		client := newOAuthPolicyClient(t, &fakeOAuthProvider{}, func(config *betterauth.Config) {
			config.Account.DisableImplicitLinking = true
		})
		authorization := startGoOAuth(t, client, "/sign-in/social", oauthPolicyInput(), false)
		destination := callbackGoOAuth(t, client, authorization, "code=valid-code")
		if destination.String() != "https://app.example.com/new-user" {
			t.Fatalf("disableImplicitLinking blocked new-user signup: %s", destination)
		}
	})
}

func TestOAuthUpdateAccountOnSignInOption(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name       string
		disable    bool
		wantAccess string
	}{
		{name: "default updates", wantAccess: "second-access"},
		{name: "disabled preserves", disable: true, wantAccess: "first-access"},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			provider := &fakeOAuthProvider{tokens: betterauth.ProviderTokens{
				AccessToken: "first-access", RefreshToken: "plain-refresh-token",
				IDToken: "first-id", Scope: "openid profile",
				AccessTokenExpiresAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
			}}
			client := newOAuthPolicyClient(t, provider, func(config *betterauth.Config) {
				if test.disable {
					update := false
					config.Account.UpdateAccountOnSignIn = &update
				}
			})
			first := startGoOAuth(t, client, "/sign-in/social", oauthPolicyInput(), false)
			callbackGoOAuth(t, client, first, "code=valid-code")
			provider.setTokens(betterauth.ProviderTokens{
				AccessToken: "second-access", RefreshToken: "plain-refresh-token",
				IDToken: "second-id", Scope: "openid profile",
				AccessTokenExpiresAt: time.Date(2030, 1, 1, 1, 0, 0, 0, time.UTC),
			})
			second := startGoOAuth(t, client, "/sign-in/social", oauthPolicyInput(), false)
			callbackGoOAuth(t, client, second, "code=valid-code")
			access := goResponse(client.request(t, http.MethodPost, "/get-access-token", map[string]any{
				"providerId": "test",
			}, true))
			if access.status != http.StatusOK || decodeObject(t, access.body)["accessToken"] != test.wantAccess {
				t.Fatalf("updateAccountOnSignIn mismatch: status=%d body=%s", access.status, access.body)
			}
		})
	}
}

func TestOAuthLinkingAndSignupOptions(t *testing.T) {
	t.Run("linking disabled", func(t *testing.T) {
		enabled := false
		client := newOAuthPolicyClient(t, &fakeOAuthProvider{}, func(config *betterauth.Config) {
			config.Account.LinkingEnabled = &enabled
		})
		signup := client.request(t, http.MethodPost, "/sign-up/email", map[string]any{
			"email": "disabled@example.com", "password": "correct horse battery staple", "name": "Disabled",
		}, false)
		if signup.Code != http.StatusOK {
			t.Fatal(signup.Body.String())
		}
		response := client.request(t, http.MethodPost, "/link-social", oauthPolicyInput(), true)
		if response.Code != http.StatusUnauthorized || !containsAny(response.Body.String(), "LINKING_NOT_ALLOWED") {
			t.Fatalf("disabled linking response=%d %s", response.Code, response.Body.String())
		}
	})

	t.Run("request sign up", func(t *testing.T) {
		client := newOAuthPolicyClient(t, &fakeOAuthProvider{disableImplicitSignUp: true}, nil)
		input := oauthPolicyInput()
		authorization := startGoOAuth(t, client, "/sign-in/social", input, false)
		destination := callbackGoOAuth(t, client, authorization, "code=valid-code")
		if destination.Query().Get("error") != "signup_disabled" {
			t.Fatalf("implicit signup was not disabled: %s", destination)
		}
		input["requestSignUp"] = true
		authorization = startGoOAuth(t, client, "/sign-in/social", input, false)
		destination = callbackGoOAuth(t, client, authorization, "code=valid-code")
		if destination.String() != "https://app.example.com/new-user" {
			t.Fatalf("explicit requestSignUp did not create a user: %s", destination)
		}
	})

	t.Run("trusted provider evidence", func(t *testing.T) {
		provider := &fakeOAuthProvider{profile: betterauth.OAuthProfile{
			ProviderAccountID: "trusted-user", Email: "trusted@example.com",
			EmailVerified: false, Name: "Trusted User",
		}}
		client := newOAuthPolicyClient(t, provider, func(config *betterauth.Config) {
			config.Account.TrustedProviders = []string{"test"}
		})
		authorization := startGoOAuth(t, client, "/sign-in/social", oauthPolicyInput(), false)
		destination := callbackGoOAuth(t, client, authorization, "code=valid-code")
		if destination.String() != "https://app.example.com/new-user" {
			t.Fatalf("trusted provider was not accepted: %s", destination)
		}
		session := client.request(t, http.MethodGet, "/get-session", nil, false)
		if session.Code != http.StatusOK || !containsAny(session.Body.String(), `"emailVerified":true`) {
			t.Fatalf("trusted provider identity was not promoted to verified: %s", session.Body.String())
		}
	})

	t.Run("request-resolved trusted provider evidence", func(t *testing.T) {
		provider := &fakeOAuthProvider{profile: betterauth.OAuthProfile{
			ProviderAccountID: "resolved-trusted-user", Email: "resolved-trusted@example.com",
			EmailVerified: false, Name: "Resolved Trusted User",
		}}
		client := newOAuthPolicyClient(t, provider, func(config *betterauth.Config) {
			config.Account.TrustedProviderResolver = betterauth.TrustedProviderResolverFunc(
				func(_ context.Context, request *http.Request) ([]string, error) {
					if request.URL.Path != "/api/auth/callback/test" {
						return nil, errors.New("unexpected callback path")
					}
					return []string{"test"}, nil
				},
			)
		})
		authorization := startGoOAuth(t, client, "/sign-in/social", oauthPolicyInput(), false)
		destination := callbackGoOAuth(t, client, authorization, "code=valid-code")
		if destination.String() != "https://app.example.com/new-user" {
			t.Fatalf("request-resolved trusted provider was not accepted: %s", destination)
		}
	})

	t.Run("profile update protects identity", func(t *testing.T) {
		client := newOAuthPolicyClient(t, &fakeOAuthProvider{}, func(config *betterauth.Config) {
			config.Account.AllowLinkingDifferentEmails = true
			config.Account.UpdateUserInfoOnLink = true
		})
		signup := client.request(t, http.MethodPost, "/sign-up/email", map[string]any{
			"email": "profile-local@example.com", "password": "correct horse battery staple", "name": "Old Name",
		}, false)
		if signup.Code != http.StatusOK {
			t.Fatal(signup.Body.String())
		}
		authorization := startGoOAuth(t, client, "/link-social", oauthPolicyInput(), true)
		destination := callbackGoOAuth(t, client, authorization, "code=valid-code")
		if destination.String() != "https://app.example.com/success" {
			t.Fatalf("explicit link failed: %s", destination)
		}
		session := client.request(t, http.MethodGet, "/get-session", nil, false)
		body := goResponse(session)
		user := responseUser(t, body)
		if user["name"] != "OAuth User" || user["email"] != "profile-local@example.com" {
			t.Fatalf("profile update changed identity or missed profile fields: %s", session.Body.String())
		}
	})
}

func TestConcurrentOAuthAccountCollisionHasOneOwner(t *testing.T) {
	t.Parallel()
	provider := &fakeOAuthProvider{}
	clientA := newOAuthPolicyClient(t, provider, func(config *betterauth.Config) {
		config.Account.AllowLinkingDifferentEmails = true
	})
	clientB := &testClient{handler: clientA.handler, database: clientA.database}
	signupAdminOptionUser(t, clientA, "concurrent-a@example.com", "Concurrent A")
	signupAdminOptionUser(t, clientB, "concurrent-b@example.com", "Concurrent B")
	authorizationA := startGoOAuth(t, clientA, "/link-social", oauthPolicyInput(), true)
	authorizationB := startGoOAuth(t, clientB, "/link-social", oauthPolicyInput(), true)

	clients := []*testClient{clientA, clientB}
	authorizations := []*url.URL{authorizationA, authorizationB}
	locations := make([]string, len(clients))
	statuses := make([]int, len(clients))
	var wait sync.WaitGroup
	for index := range clients {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			request := httptest.NewRequest(
				http.MethodGet,
				"https://auth.example.com/api/auth/callback/test?state="+
					url.QueryEscape(authorizations[index].Query().Get("state"))+"&code=valid-code",
				nil,
			)
			request.AddCookie(clients[index].session)
			request.AddCookie(clients[index].csrf)
			recorder := httptest.NewRecorder()
			clients[index].handler.ServeHTTP(recorder, request)
			statuses[index] = recorder.Code
			locations[index] = recorder.Header().Get("Location")
		}(index)
	}
	wait.Wait()

	successes := 0
	collisions := 0
	for index := range statuses {
		if statuses[index] != http.StatusFound {
			t.Fatalf("callback %d status=%d location=%s", index, statuses[index], locations[index])
		}
		destination, err := url.Parse(locations[index])
		if err != nil {
			t.Fatal(err)
		}
		switch destination.Scheme + "://" + destination.Host + destination.Path {
		case "https://app.example.com/success":
			successes++
		case "https://app.example.com/error":
			if destination.Query().Get("error") != "account_already_linked_to_different_user" {
				t.Fatalf("unexpected collision redirect: %s", destination)
			}
			collisions++
		default:
			t.Fatalf("unexpected callback redirect: %s", destination)
		}
	}
	if successes != 1 || collisions != 1 {
		t.Fatalf("concurrent collision winners: success=%d collision=%d", successes, collisions)
	}
	count, err := clientA.database.Count(context.Background(), betterauth.CountQuery{
		Model: betterauth.ModelAccount,
		Where: []betterauth.Where{betterauth.Eq("providerId", "test"), betterauth.Eq("accountId", "provider-user-1")},
	})
	if err != nil || count != 1 {
		t.Fatalf("provider identity owners=%d, want 1: %v", count, err)
	}
}

func containsAny(value string, candidates ...string) bool {
	for _, candidate := range candidates {
		if strings.Contains(value, candidate) {
			return true
		}
	}
	return false
}
