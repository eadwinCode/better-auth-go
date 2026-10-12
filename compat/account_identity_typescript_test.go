package betterauth_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"

	betterauth "github.com/eadwinCode/better-auth-go"
)

// sameSubjectProvider returns one identity for every exchange. Two of them
// under different provider IDs model two configurations that share an issuer
// and a subject.
type sameSubjectProvider struct {
	subject string
	email   string
}

func (sameSubjectProvider) AuthorizationURL(state, _, _, redirectURI string) (string, error) {
	destination := &url.URL{Scheme: "https", Host: "provider.example", Path: "/authorize"}
	query := destination.Query()
	query.Set("state", state)
	query.Set("redirect_uri", redirectURI)
	destination.RawQuery = query.Encode()
	return destination.String(), nil
}

func (provider sameSubjectProvider) Exchange(
	context.Context, string, string, string, string,
) (betterauth.OAuthResult, error) {
	return betterauth.OAuthResult{
		Profile: betterauth.OAuthProfile{
			Issuer: "https://shared-issuer.example", ProviderAccountID: provider.subject,
			Email: provider.email, EmailVerified: true, Name: "Provider Fixture",
		},
		Tokens: betterauth.ProviderTokens{AccessToken: "access", Scope: "openid profile"},
	}, nil
}

type listedAccount struct {
	ProviderID string `json:"providerId"`
	AccountID  string `json:"accountId"`
}

func listedAccounts(t *testing.T, implementation string, response oracleResponse) []listedAccount {
	t.Helper()
	if response.status != http.StatusOK {
		t.Fatalf("%s list-accounts status=%d body=%s", implementation, response.status, response.body)
	}
	var accounts []listedAccount
	if err := json.Unmarshal(response.body, &accounts); err != nil {
		t.Fatalf("%s list-accounts body %s: %v", implementation, response.body, err)
	}
	sort.Slice(accounts, func(left, right int) bool {
		return accounts[left].ProviderID < accounts[right].ProviderID
	})
	return accounts
}

// TestBetterAuthV177SameSubjectAtTwoProvidersCompatibility checks the account
// key that Better Auth 1.7.3 restored: two provider configurations that return
// the same subject create two account rows, one per providerId, for one user.
// Better Auth 1.7.0 to 1.7.2 keyed by issuer and would have used one row.
func TestBetterAuthV177SameSubjectAtTwoProvidersCompatibility(t *testing.T) {
	oracle := newTypeScriptOracle(t).clone(t)
	oracle.basePath += "-two-providers"
	code := fmt.Sprintf("two-providers-%d", time.Now().UnixNano())
	goClient, _ := managementCompatibilityServerConfig(t, func(config *betterauth.Config) {
		provider := sameSubjectProvider{subject: "shared-subject", email: "provider-" + code + "@example.com"}
		config.SocialProviders = map[string]betterauth.OAuthProvider{
			"test": provider, "test-alt": provider,
		}
	})

	for _, provider := range []string{"test", "test-alt"} {
		goInput := map[string]any{
			"provider": provider, "callbackURL": "https://app.example.com/oauth-success",
			"errorCallbackURL": "https://app.example.com/oauth-error", "disableRedirect": true,
		}
		tsInput := map[string]any{
			"provider": provider, "callbackURL": oracle.origin + "/oauth-success",
			"errorCallbackURL": oracle.origin + "/oauth-error", "disableRedirect": true,
		}
		pair := startOAuthPair(t, goClient, oracle, "/sign-in/social", goInput, tsInput)
		goCallback := goResponse(goClient.request(
			t, http.MethodGet,
			"/callback/"+provider+"?state="+
				url.QueryEscape(pair.goAuthorization.Query().Get("state"))+"&code=valid-code",
			nil, false,
		))
		redirect, err := url.Parse(pair.tsAuthorization.Query().Get("redirect_uri"))
		if err != nil {
			t.Fatal(err)
		}
		tsCallback := oracle.request(
			t, http.MethodGet,
			strings.TrimPrefix(redirect.Path, oracle.basePath)+"?state="+
				url.QueryEscape(pair.tsAuthorization.Query().Get("state"))+"&code="+code,
			nil, "",
		)
		assertOAuthRedirect(t, "Go", goCallback, "https://app.example.com/oauth-success", "")
		assertOAuthRedirect(t, "TypeScript", tsCallback, oracle.origin+"/oauth-success", "")
	}

	for implementation, accounts := range map[string][]listedAccount{
		"Go": listedAccounts(t, "Go",
			goResponse(goClient.request(t, http.MethodGet, "/list-accounts", nil, false))),
		"TypeScript": listedAccounts(t, "TypeScript",
			oracle.request(t, http.MethodGet, "/list-accounts", nil, "")),
	} {
		if len(accounts) != 2 ||
			accounts[0].ProviderID != "test" || accounts[1].ProviderID != "test-alt" ||
			accounts[0].AccountID == "" || accounts[0].AccountID != accounts[1].AccountID {
			t.Fatalf("%s accounts for one subject at two providers = %#v", implementation, accounts)
		}
	}
}
