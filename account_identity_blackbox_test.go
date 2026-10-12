package betterauth_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	betterauth "github.com/eadwinCode/better-auth-go"
	"github.com/eadwinCode/better-auth-go/adapter/memory"
)

// subjectProvider returns one fixed identity. Two of them with different IDs
// model two provider configurations that share an issuer and a subject.
type subjectProvider struct{ subject string }

func (subjectProvider) AuthorizationURL(state, _, _, redirectURI string) (string, error) {
	destination := &url.URL{Scheme: "https", Host: "provider.example", Path: "/authorize"}
	query := destination.Query()
	query.Set("state", state)
	query.Set("redirect_uri", redirectURI)
	destination.RawQuery = query.Encode()
	return destination.String(), nil
}

func (provider subjectProvider) Exchange(
	context.Context, string, string, string, string,
) (betterauth.OAuthResult, error) {
	return betterauth.OAuthResult{
		Profile: betterauth.OAuthProfile{
			Issuer: "https://shared-issuer.example", ProviderAccountID: provider.subject,
			Email: "shared@example.com", EmailVerified: true, Name: "Shared Subject",
		},
		Tokens: betterauth.ProviderTokens{AccessToken: "access", Scope: "openid"},
	}, nil
}

func identityServer(t *testing.T, database *memory.Adapter) *testClient {
	t.Helper()
	cipher, err := betterauth.NewAESGCMTokenCipher([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	client, _ := newBlackBoxServerConfig(t, func(config *betterauth.Config) {
		config.Database = database
		config.ProviderTokenCipher = cipher
		config.AllowedRedirectURLs = []string{"https://app.example.com/done", "https://app.example.com/error"}
		config.SocialProviders = map[string]betterauth.OAuthProvider{
			"alpha": subjectProvider{subject: "shared-subject"},
			"beta":  subjectProvider{subject: "shared-subject"},
		}
	})
	client.database = database
	return client
}

func socialCallback(t *testing.T, client *testClient, path, provider string) *http.Response {
	t.Helper()
	start := client.request(t, http.MethodPost, path, map[string]any{
		"provider": provider, "callbackURL": "https://app.example.com/done",
		"errorCallbackURL": "https://app.example.com/error", "disableRedirect": true,
	}, path == "/link-social")
	if start.Code != http.StatusOK {
		t.Fatalf("%s %s: %d %s", path, provider, start.Code, start.Body.String())
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
	callback := client.request(t, http.MethodGet,
		"/callback/"+provider+"?state="+url.QueryEscape(destination.Query().Get("state"))+"&code=valid-code",
		nil, false)
	return callback.Result()
}

func accountsWithSubject(t *testing.T, database *memory.Adapter) []betterauth.Record {
	t.Helper()
	rows, err := database.FindMany(context.Background(), betterauth.FindManyQuery{
		Model: betterauth.ModelAccount, Where: []betterauth.Where{betterauth.Eq("accountId", "shared-subject")},
	})
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func TestSameSubjectAtTwoProvidersKeepsTwoAccounts(t *testing.T) {
	t.Parallel()
	database := memory.New()
	client := identityServer(t, database)
	for _, provider := range []string{"alpha", "beta"} {
		response := socialCallback(t, client, "/sign-in/social", provider)
		if response.StatusCode != http.StatusFound ||
			!strings.HasPrefix(response.Header.Get("Location"), "https://app.example.com/done") {
			t.Fatalf("%s sign-in: %d %s", provider, response.StatusCode, response.Header.Get("Location"))
		}
	}
	rows := accountsWithSubject(t, database)
	if len(rows) != 2 {
		t.Fatalf("accounts for one subject at two providers = %#v, want two rows", rows)
	}
	providers := map[any]bool{}
	for _, row := range rows {
		providers[row["providerId"]] = true
		if _, exists := row["issuer"]; exists {
			t.Fatalf("account row still stores an issuer: %#v", row)
		}
	}
	if !providers["alpha"] || !providers["beta"] || rows[0]["userId"] != rows[1]["userId"] {
		t.Fatalf("accounts did not keep their own provider IDs for one user: %#v", rows)
	}
}

func seedDuplicateProviderKey(t *testing.T, database *memory.Adapter) {
	t.Helper()
	// A database built by Better Auth TypeScript has no unique provider key
	// index, so two rows can share one key.
	schema := betterauth.CoreSchema()
	account := schema[betterauth.ModelAccount]
	account.Indexes = nil
	schema[betterauth.ModelAccount] = account
	unindexed, err := database.WithSchema(schema)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	for _, owner := range []string{"owner-a", "owner-b"} {
		if _, err = unindexed.Create(context.Background(), betterauth.CreateQuery{
			Model: betterauth.ModelAccount, ForceAllowID: true, Data: betterauth.Record{
				"id": owner + ":alpha", "userId": owner, "providerId": "alpha",
				"accountId": "shared-subject", "createdAt": now, "updatedAt": now,
			},
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAmbiguousProviderKeyFailsSignInAndLinking(t *testing.T) {
	t.Parallel()
	database := memory.New()
	seedDuplicateProviderKey(t, database)
	client := identityServer(t, database)
	response := socialCallback(t, client, "/sign-in/social", "alpha")
	if response.StatusCode != http.StatusFound ||
		response.Header.Get("Location") != "https://app.example.com/error?error=internal_server_error" {
		t.Fatalf("ambiguous sign-in: %d %s", response.StatusCode, response.Header.Get("Location"))
	}
	for _, cookie := range response.Cookies() {
		if strings.Contains(cookie.Name, "session") && cookie.Value != "" {
			t.Fatal("ambiguous account key issued a session")
		}
	}

	signup := client.request(t, http.MethodPost, "/sign-up/email", map[string]any{
		"email": "shared@example.com", "password": "correct horse battery staple", "name": "Linker",
	}, false)
	if signup.Code != http.StatusOK {
		t.Fatalf("sign-up: %d %s", signup.Code, signup.Body.String())
	}
	link := socialCallback(t, client, "/link-social", "alpha")
	if link.StatusCode != http.StatusFound ||
		link.Header.Get("Location") != "https://app.example.com/error?error=unable_to_link_account" {
		t.Fatalf("ambiguous link: %d %s", link.StatusCode, link.Header.Get("Location"))
	}
	if rows := accountsWithSubject(t, database); len(rows) != 2 {
		t.Fatalf("ambiguous key changed account rows: %#v", rows)
	}
}
