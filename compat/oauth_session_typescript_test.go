package betterauth_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

type oauthPair struct {
	goAuthorization *url.URL
	tsAuthorization *url.URL
}

func startOAuthPair(
	t *testing.T,
	goClient *testClient,
	tsClient *typescriptOracle,
	path string,
	goBody map[string]any,
	tsBody map[string]any,
) oauthPair {
	t.Helper()
	goResponse := goResponse(goClient.request(t, http.MethodPost, path, goBody, path == "/link-social"))
	tsResponse := tsClient.request(t, http.MethodPost, path, tsBody, "")
	for implementation, response := range map[string]oracleResponse{
		"Go": goResponse, "TypeScript": tsResponse,
	} {
		if response.status != http.StatusOK {
			t.Fatalf("%s OAuth start status=%d body=%s", implementation, response.status, response.body)
		}
		body := decodeObject(t, response.body)
		if body["redirect"] != false {
			t.Fatalf("%s disableRedirect response mismatch: %#v", implementation, body)
		}
	}
	goAuthorization, err := url.Parse(decodeObject(t, goResponse.body)["url"].(string))
	if err != nil {
		t.Fatal(err)
	}
	tsAuthorization, err := url.Parse(decodeObject(t, tsResponse.body)["url"].(string))
	if err != nil {
		t.Fatal(err)
	}
	return oauthPair{goAuthorization: goAuthorization, tsAuthorization: tsAuthorization}
}

func oracleOAuthCallbackPath(t *testing.T, authorization *url.URL) string {
	t.Helper()
	redirect, err := url.Parse(authorization.Query().Get("redirect_uri"))
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimPrefix(redirect.Path, "/api/auth")
}

func assertOAuthRedirect(
	t *testing.T,
	implementation string,
	response oracleResponse,
	wantBase string,
	wantError string,
) {
	t.Helper()
	if response.status != http.StatusFound {
		t.Fatalf("%s OAuth callback status=%d body=%s", implementation, response.status, response.body)
	}
	destination, err := url.Parse(response.header.Get("Location"))
	if err != nil {
		t.Fatalf("%s callback location: %v", implementation, err)
	}
	base, err := url.Parse(wantBase)
	if err != nil {
		t.Fatal(err)
	}
	if destination.Scheme != base.Scheme || destination.Host != base.Host || destination.Path != base.Path ||
		destination.Query().Get("error") != wantError {
		t.Fatalf("%s callback redirect=%s, want base=%s error=%q", implementation, destination, wantBase, wantError)
	}
}

func TestBetterAuthV170OAuthCallbackErrorReplayAndRedirectCompatibility(t *testing.T) {
	oracle := newTypeScriptOracle(t)
	goClient, _ := managementCompatibilityServer(t)

	goInput := map[string]any{
		"provider": "test", "callbackURL": "https://app.example.com/oauth-success",
		"errorCallbackURL":   "https://app.example.com/oauth-error",
		"newUserCallbackURL": "https://app.example.com/oauth-new-user", "disableRedirect": true,
	}
	tsInput := map[string]any{
		"provider": "test", "callbackURL": oracle.origin + "/oauth-success",
		"errorCallbackURL":   oracle.origin + "/oauth-error",
		"newUserCallbackURL": oracle.origin + "/oauth-new-user", "disableRedirect": true,
	}

	errorStart := startOAuthPair(t, goClient, oracle, "/sign-in/social", goInput, tsInput)
	goErrorPath := "/callback/test?state=" + url.QueryEscape(errorStart.goAuthorization.Query().Get("state")) +
		"&error=access_denied&error_description=" + url.QueryEscape("do-not-reflect-this-secret")
	tsErrorPath := oracleOAuthCallbackPath(t, errorStart.tsAuthorization) + "?state=" +
		url.QueryEscape(errorStart.tsAuthorization.Query().Get("state")) +
		"&error=access_denied&error_description=" + url.QueryEscape("do-not-reflect-this-secret")
	goError := goResponse(goClient.request(t, http.MethodGet, goErrorPath, nil, false))
	tsError := oracle.request(t, http.MethodGet, tsErrorPath, nil, "")
	assertOAuthRedirect(t, "Go", goError, "https://app.example.com/oauth-error", "access_denied")
	// Better Auth v1.7 binds provider errors to the state-selected error URL,
	// while still reflecting the provider description. Go deliberately keeps
	// the description-free contract from ADR 0016.
	assertOAuthRedirect(t, "TypeScript", tsError, oracle.origin+"/oauth-error", "access_denied")
	if strings.Contains(goError.header.Get("Location"), "do-not-reflect") ||
		strings.Contains(string(goError.body), "do-not-reflect") {
		t.Fatal("Go reflected an untrusted provider error description")
	}
	if !strings.Contains(tsError.header.Get("Location"), "error_description=do-not-reflect-this-secret") {
		t.Fatalf("pinned generic OAuth provider-error behavior changed: %s", tsError.header.Get("Location"))
	}

	goReplay := goResponse(goClient.request(t, http.MethodGet, goErrorPath, nil, false))
	tsReplay := oracle.request(t, http.MethodGet, tsErrorPath, nil, "")
	if goReplay.status < 400 || tsReplay.status != http.StatusFound {
		t.Fatalf("callback replay was accepted: Go=%d %s TypeScript=%d %s",
			goReplay.status, goReplay.body, tsReplay.status, tsReplay.body)
	}

	newStart := startOAuthPair(t, goClient, oracle, "/sign-in/social", goInput, tsInput)
	goNew := goResponse(goClient.request(
		t, http.MethodGet,
		"/callback/test?state="+url.QueryEscape(newStart.goAuthorization.Query().Get("state"))+"&code=valid-code",
		nil, false,
	))
	tsNew := oracle.request(
		t, http.MethodGet,
		oracleOAuthCallbackPath(t, newStart.tsAuthorization)+"?state="+
			url.QueryEscape(newStart.tsAuthorization.Query().Get("state"))+"&code=core-callback-user",
		nil, "",
	)
	assertOAuthRedirect(t, "Go", goNew, "https://app.example.com/oauth-new-user", "")
	assertOAuthRedirect(t, "TypeScript", tsNew, oracle.origin+"/oauth-new-user", "")

	returningStart := startOAuthPair(t, goClient, oracle, "/sign-in/social", goInput, tsInput)
	goReturning := goResponse(goClient.request(
		t, http.MethodGet,
		"/callback/test?state="+url.QueryEscape(returningStart.goAuthorization.Query().Get("state"))+"&code=valid-code",
		nil, false,
	))
	tsReturning := oracle.request(
		t, http.MethodGet,
		oracleOAuthCallbackPath(t, returningStart.tsAuthorization)+"?state="+
			url.QueryEscape(returningStart.tsAuthorization.Query().Get("state"))+"&code=core-callback-user",
		nil, "",
	)
	assertOAuthRedirect(t, "Go", goReturning, "https://app.example.com/oauth-success", "")
	assertOAuthRedirect(t, "TypeScript", tsReturning, oracle.origin+"/oauth-success", "")
}

func TestBetterAuthV170OAuthAccountCollisionCompatibility(t *testing.T) {
	oracleA := newTypeScriptOracle(t)
	oracleB := oracleA.clone(t)
	goA, _ := managementCompatibilityServer(t)
	goB := &testClient{handler: goA.handler, database: goA.database}
	const password = "Correct-Horse-123!"
	signupCompatibilityUser(t, goA, oracleA, uniqueCompatibilityEmail("collision-a"), "Collision A", password)
	signupCompatibilityUser(t, goB, oracleB, uniqueCompatibilityEmail("collision-b"), "Collision B", password)

	goInput := map[string]any{
		"provider": "test", "callbackURL": "https://app.example.com/linked",
		"errorCallbackURL": "https://app.example.com/oauth-error", "disableRedirect": true,
	}
	tsInput := map[string]any{
		"provider": "test", "callbackURL": oracleA.origin + "/linked",
		"errorCallbackURL": oracleA.origin + "/oauth-error", "disableRedirect": true,
	}
	first := startOAuthPair(t, goA, oracleA, "/link-social", goInput, tsInput)
	goFirst := goResponse(goA.request(
		t, http.MethodGet,
		"/callback/test?state="+url.QueryEscape(first.goAuthorization.Query().Get("state"))+"&code=valid-code",
		nil, false,
	))
	tsFirst := oracleA.request(
		t, http.MethodGet,
		oracleOAuthCallbackPath(t, first.tsAuthorization)+"?state="+
			url.QueryEscape(first.tsAuthorization.Query().Get("state"))+"&code=core-collision",
		nil, "",
	)
	assertOAuthRedirect(t, "Go", goFirst, "https://app.example.com/linked", "")
	assertOAuthRedirect(t, "TypeScript", tsFirst, oracleA.origin+"/linked", "")

	second := startOAuthPair(t, goB, oracleB, "/link-social", goInput, tsInput)
	goCollision := goResponse(goB.request(
		t, http.MethodGet,
		"/callback/test?state="+url.QueryEscape(second.goAuthorization.Query().Get("state"))+"&code=valid-code",
		nil, false,
	))
	tsCollision := oracleB.request(
		t, http.MethodGet,
		oracleOAuthCallbackPath(t, second.tsAuthorization)+"?state="+
			url.QueryEscape(second.tsAuthorization.Query().Get("state"))+"&code=core-collision",
		nil, "",
	)
	assertOAuthRedirect(
		t, "Go", goCollision, "https://app.example.com/oauth-error",
		"account_already_linked_to_different_user",
	)
	assertOAuthRedirect(
		t, "TypeScript", tsCollision, oracleB.origin+"/oauth-error",
		"account_already_linked_to_different_user",
	)
}

func TestBetterAuthV170SessionAndSignOutClosureCompatibility(t *testing.T) {
	oracle := newTypeScriptOracle(t)
	goClient, _ := newBlackBoxServer(t)
	for implementation, response := range map[string]oracleResponse{
		"Go":         goResponse(goClient.request(t, http.MethodGet, "/get-session", nil, false)),
		"TypeScript": oracle.request(t, http.MethodGet, "/get-session", nil, ""),
	} {
		if response.status != http.StatusOK || strings.TrimSpace(string(response.body)) != "null" {
			t.Fatalf("%s anonymous session mismatch: status=%d body=%s", implementation, response.status, response.body)
		}
	}
	goAnonymousSignOut := goResponse(goClient.request(t, http.MethodPost, "/sign-out", map[string]any{}, true))
	tsAnonymousSignOut := oracle.request(t, http.MethodPost, "/sign-out", map[string]any{}, "")
	if goAnonymousSignOut.status != http.StatusForbidden ||
		decodeObject(t, goAnonymousSignOut.body)["code"] != "FORBIDDEN" ||
		tsAnonymousSignOut.status != http.StatusOK ||
		decodeObject(t, tsAnonymousSignOut.body)["success"] != true {
		t.Fatalf("anonymous signout security difference changed: Go=%d %s TypeScript=%d %s",
			goAnonymousSignOut.status, goAnonymousSignOut.body,
			tsAnonymousSignOut.status, tsAnonymousSignOut.body)
	}

	email := uniqueCompatibilityEmail("signout")
	signupCompatibilityUser(t, goClient, oracle, email, "Signout User", "Correct-Horse-123!")
	for implementation, response := range map[string]oracleResponse{
		"Go":         goResponse(goClient.request(t, http.MethodGet, "/get-session", nil, false)),
		"TypeScript": oracle.request(t, http.MethodGet, "/get-session", nil, ""),
	} {
		if response.status != http.StatusOK || responseUser(t, response)["email"] != email {
			t.Fatalf("%s authenticated session mismatch: status=%d body=%s", implementation, response.status, response.body)
		}
	}

	for attempt := 1; attempt <= 2; attempt++ {
		responses := map[string]oracleResponse{
			"Go":         goResponse(goClient.request(t, http.MethodPost, "/sign-out", map[string]any{}, true)),
			"TypeScript": oracle.request(t, http.MethodPost, "/sign-out", map[string]any{}, ""),
		}
		for implementation, response := range responses {
			if response.status != http.StatusOK || decodeObject(t, response.body)["success"] != true {
				t.Fatalf("%s signout attempt %d mismatch: status=%d body=%s",
					implementation, attempt, response.status, response.body)
			}
		}
		if attempt == 1 {
			for implementation, response := range responses {
				cleared := false
				for _, cookie := range response.cookies {
					if strings.Contains(cookie.Name, "session") && cookie.Value == "" &&
						(cookie.MaxAge < 0 || (!cookie.Expires.IsZero() && cookie.Expires.Before(time.Now()))) {
						cleared = true
					}
				}
				if !cleared {
					t.Fatalf("%s signout did not clear a session cookie: %#v", implementation, response.cookies)
				}
			}
		}
	}
	for implementation, response := range map[string]oracleResponse{
		"Go":         goResponse(goClient.request(t, http.MethodGet, "/get-session", nil, false)),
		"TypeScript": oracle.request(t, http.MethodGet, "/get-session", nil, ""),
	} {
		if response.status != http.StatusOK || strings.TrimSpace(string(response.body)) != "null" {
			t.Fatalf("%s post-signout session mismatch: status=%d body=%s", implementation, response.status, response.body)
		}
	}
}
