package betterauth_test

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	betterauth "github.com/eadwinCode/better-auth-go"
)

type compatibilityAdminAuthorizer struct{}

func (compatibilityAdminAuthorizer) CanImpersonate(
	_ context.Context,
	actor betterauth.User,
	_ betterauth.User,
) error {
	if actor.Name != "Admin" {
		return errors.New("admin role required")
	}
	return nil
}

func managementCompatibilityServer(
	t *testing.T,
) (*testClient, *captureMailer) {
	t.Helper()
	provider := &fakeOAuthProvider{}
	cipher, err := betterauth.NewAESGCMTokenCipher(
		[]byte("0123456789abcdef0123456789abcdef"),
	)
	if err != nil {
		t.Fatal(err)
	}
	return newBlackBoxServerConfig(t, func(config *betterauth.Config) {
		config.User.ChangeEmailEnabled = true
		config.User.DeleteUserEnabled = true
		config.Account.AllowLinkingDifferentEmails = true
		config.AllowedRedirectURLs = []string{"https://app.example.com/linked"}
		config.SocialProviders = map[string]betterauth.OAuthProvider{"test": provider}
		config.ProviderTokenCipher = cipher
		config.ImpersonationAuthorizer = compatibilityAdminAuthorizer{}
	})
}

func signupCompatibilityUser(
	t *testing.T,
	goClient *testClient,
	tsClient *typescriptOracle,
	email string,
	name string,
	password string,
) (string, string) {
	t.Helper()
	input := map[string]any{"email": email, "password": password, "name": name}
	goSignup := goResponse(goClient.request(t, http.MethodPost, "/sign-up/email", input, false))
	tsSignup := tsClient.request(t, http.MethodPost, "/sign-up/email", input, "")
	if goSignup.status != http.StatusOK || tsSignup.status != http.StatusOK {
		t.Fatalf(
			"signup mismatch: Go=%d %s TypeScript=%d %s",
			goSignup.status,
			goSignup.body,
			tsSignup.status,
			tsSignup.body,
		)
	}
	goID, _ := responseUser(t, goSignup)["id"].(string)
	tsID, _ := responseUser(t, tsSignup)["id"].(string)
	if goID == "" || tsID == "" {
		t.Fatalf("signup returned empty IDs: Go=%s TypeScript=%s", goSignup.body, tsSignup.body)
	}
	return goID, tsID
}

func assertCode(
	t *testing.T,
	wantStatus int,
	wantCode string,
	wantMessage string,
	results map[string]oracleResponse,
) {
	t.Helper()
	for implementation, result := range results {
		if result.status != wantStatus {
			t.Fatalf(
				"%s status=%d, want %d: %s",
				implementation,
				result.status,
				wantStatus,
				result.body,
			)
		}
		body := decodeObject(t, result.body)
		if body["code"] != wantCode || body["message"] != wantMessage {
			t.Fatalf("%s error mismatch: %#v", implementation, body)
		}
	}
}

func TestBetterAuthV1625EmailChangeAndDeletionCompatibility(t *testing.T) {
	oracle := newTypeScriptOracle(t)
	oracle.clearMail(t)
	goClient, goMailer := managementCompatibilityServer(t)
	tsReserved := oracle.clone(t)
	goReserved := &testClient{handler: goClient.handler, database: goClient.database}

	const password = "Correct-Horse-123!"
	originalEmail := uniqueCompatibilityEmail("management")
	reservedEmail := uniqueCompatibilityEmail("reserved")
	changedEmail := uniqueCompatibilityEmail("changed")
	signupCompatibilityUser(t, goClient, oracle, originalEmail, "Lifecycle User", password)
	signupCompatibilityUser(t, goReserved, tsReserved, reservedEmail, "Reserved User", password)

	sameEmailResults := map[string]oracleResponse{
		"Go": goResponse(goClient.request(t, http.MethodPost, "/change-email", map[string]any{
			"newEmail": originalEmail,
		}, true)),
		"TypeScript": oracle.request(t, http.MethodPost, "/change-email", map[string]any{
			"newEmail": originalEmail,
		}, ""),
	}
	for implementation, result := range sameEmailResults {
		if result.status != http.StatusBadRequest ||
			decodeObject(t, result.body)["message"] != "Email is the same" {
			t.Fatalf("%s same-email response mismatch: status=%d body=%s",
				implementation, result.status, result.body)
		}
	}
	if decodeObject(t, sameEmailResults["Go"].body)["code"] != "BAD_REQUEST" {
		t.Fatalf("Go same-email response lost its structured code: %s", sameEmailResults["Go"].body)
	}
	if _, exists := decodeObject(t, sameEmailResults["TypeScript"].body)["code"]; exists {
		t.Fatalf("pinned TypeScript same-email response unexpectedly gained a code: %s",
			sameEmailResults["TypeScript"].body)
	}

	for implementation, result := range map[string]oracleResponse{
		"Go": goResponse(goClient.request(t, http.MethodPost, "/change-email", map[string]any{
			"newEmail": reservedEmail,
		}, true)),
		"TypeScript": oracle.request(t, http.MethodPost, "/change-email", map[string]any{
			"newEmail": reservedEmail,
		}, ""),
	} {
		assertStatusTrue(t, implementation, result)
	}
	if goMailer.count() != 0 || oracle.mailExists(t, "email-verification", reservedEmail) {
		t.Fatal("existing-email change leaked through mail delivery")
	}

	for implementation, result := range map[string]oracleResponse{
		"Go": goResponse(goClient.request(t, http.MethodPost, "/change-email", map[string]any{
			"newEmail": changedEmail,
		}, true)),
		"TypeScript": oracle.request(t, http.MethodPost, "/change-email", map[string]any{
			"newEmail": changedEmail,
		}, ""),
	} {
		assertStatusTrue(t, implementation, result)
	}
	if goMailer.count() != 1 {
		t.Fatalf("Go email-change delivery count=%d, want 1", goMailer.count())
	}
	goToken := goMailer.last().Token
	tsToken := oracle.latestMail(t, "email-verification", changedEmail).Token
	for implementation, result := range map[string]oracleResponse{
		"Go": goResponse(goClient.request(
			t,
			http.MethodGet,
			"/verify-email?token="+url.QueryEscape(goToken),
			nil,
			false,
		)),
		"TypeScript": oracle.request(
			t,
			http.MethodGet,
			"/verify-email?token="+url.QueryEscape(tsToken),
			nil,
			"",
		),
	} {
		if result.status != http.StatusOK {
			t.Fatalf("%s email-change verification status=%d body=%s",
				implementation, result.status, result.body)
		}
		if user, ok := decodeObject(t, result.body)["user"].(map[string]any); !ok ||
			user["email"] != changedEmail {
			t.Fatalf("%s email-change result mismatch: %s", implementation, result.body)
		}
	}

	for implementation, result := range map[string]oracleResponse{
		"Go":         goResponse(goClient.request(t, http.MethodGet, "/get-session", nil, false)),
		"TypeScript": oracle.request(t, http.MethodGet, "/get-session", nil, ""),
	} {
		if responseUser(t, result)["email"] != changedEmail {
			t.Fatalf("%s session retained the old email: %s", implementation, result.body)
		}
	}

	assertCode(
		t,
		http.StatusBadRequest,
		"INVALID_PASSWORD",
		"Invalid password",
		map[string]oracleResponse{
			"Go": goResponse(goClient.request(t, http.MethodPost, "/delete-user", map[string]any{
				"password": "wrong password",
			}, true)),
			"TypeScript": oracle.request(t, http.MethodPost, "/delete-user", map[string]any{
				"password": "wrong password",
			}, ""),
		},
	)
	for implementation, result := range map[string]oracleResponse{
		"Go": goResponse(goClient.request(t, http.MethodPost, "/delete-user", map[string]any{
			"password": password,
		}, true)),
		"TypeScript": oracle.request(t, http.MethodPost, "/delete-user", map[string]any{
			"password": password,
		}, ""),
	} {
		if result.status != http.StatusOK {
			t.Fatalf("%s delete status=%d body=%s", implementation, result.status, result.body)
		}
		body := decodeObject(t, result.body)
		if body["success"] != true || body["message"] != "User deleted" {
			t.Fatalf("%s delete response mismatch: %#v", implementation, body)
		}
	}
	for implementation, result := range map[string]oracleResponse{
		"Go":         goResponse(goClient.request(t, http.MethodGet, "/get-session", nil, false)),
		"TypeScript": oracle.request(t, http.MethodGet, "/get-session", nil, ""),
	} {
		if strings.TrimSpace(string(result.body)) != "null" {
			t.Fatalf("%s deleted session remained active: %s", implementation, result.body)
		}
	}

	goFresh := &testClient{handler: goClient.handler, database: goClient.database}
	tsFresh := oracle.clone(t)
	freshEmail := uniqueCompatibilityEmail("fresh-delete")
	signupCompatibilityUser(t, goFresh, tsFresh, freshEmail, "Fresh Delete", password)
	for implementation, result := range map[string]oracleResponse{
		"Go": goResponse(goFresh.request(
			t, http.MethodPost, "/delete-user", map[string]any{}, true,
		)),
		"TypeScript": tsFresh.request(
			t, http.MethodPost, "/delete-user", map[string]any{}, "",
		),
	} {
		if result.status != http.StatusOK ||
			decodeObject(t, result.body)["message"] != "User deleted" {
			t.Fatalf("%s fresh-session deletion mismatch: status=%d body=%s",
				implementation, result.status, result.body)
		}
	}
}

func linkCompatibilityProvider(
	t *testing.T,
	goClient *testClient,
	tsClient *typescriptOracle,
) {
	t.Helper()
	goStart := goResponse(goClient.request(t, http.MethodPost, "/link-social", map[string]any{
		"provider": "test", "callbackURL": "https://app.example.com/linked", "disableRedirect": true,
	}, true))
	tsStart := tsClient.request(t, http.MethodPost, "/link-social", map[string]any{
		"provider": "test", "callbackURL": tsClient.origin + "/linked", "disableRedirect": true,
	}, "")
	if goStart.status != http.StatusOK || tsStart.status != http.StatusOK {
		t.Fatalf("link start mismatch: Go=%d %s TypeScript=%d %s",
			goStart.status, goStart.body, tsStart.status, tsStart.body)
	}
	goAuthorization, err := url.Parse(decodeObject(t, goStart.body)["url"].(string))
	if err != nil {
		t.Fatal(err)
	}
	tsAuthorization, err := url.Parse(decodeObject(t, tsStart.body)["url"].(string))
	if err != nil {
		t.Fatal(err)
	}
	goCallback := goResponse(goClient.request(
		t,
		http.MethodGet,
		"/callback/test?state="+url.QueryEscape(goAuthorization.Query().Get("state"))+"&code=valid-code",
		nil,
		false,
	))
	tsRedirect, err := url.Parse(tsAuthorization.Query().Get("redirect_uri"))
	if err != nil {
		t.Fatal(err)
	}
	tsCallbackPath := strings.TrimPrefix(tsRedirect.Path, "/api/auth")
	tsCallback := tsClient.request(
		t,
		http.MethodGet,
		tsCallbackPath+"?state="+url.QueryEscape(tsAuthorization.Query().Get("state"))+"&code=fixture-code",
		nil,
		"",
	)
	if goCallback.status != http.StatusFound || tsCallback.status != http.StatusFound {
		t.Fatalf("link callback mismatch: Go=%d %s TypeScript=%d %s",
			goCallback.status, goCallback.body, tsCallback.status, tsCallback.body)
	}
}

func TestBetterAuthV1625AccountAndProviderTokenCompatibility(t *testing.T) {
	oracle := newTypeScriptOracle(t)
	goClient, _ := managementCompatibilityServer(t)
	email := uniqueCompatibilityEmail("account")
	const password = "Correct-Horse-123!"
	signupCompatibilityUser(t, goClient, oracle, email, "Account User", password)

	assertCode(
		t,
		http.StatusBadRequest,
		"PROVIDER_NOT_SUPPORTED",
		"Provider missing is not supported.",
		map[string]oracleResponse{
			"Go": goResponse(goClient.request(t, http.MethodPost, "/get-access-token", map[string]any{
				"providerId": "missing",
			}, true)),
			"TypeScript": oracle.request(t, http.MethodPost, "/get-access-token", map[string]any{
				"providerId": "missing",
			}, ""),
		},
	)
	linkCompatibilityProvider(t, goClient, oracle)

	for implementation, result := range map[string]oracleResponse{
		"Go":         goResponse(goClient.request(t, http.MethodGet, "/list-accounts", nil, false)),
		"TypeScript": oracle.request(t, http.MethodGet, "/list-accounts", nil, ""),
	} {
		if result.status != http.StatusOK {
			t.Fatalf("%s list accounts status=%d body=%s", implementation, result.status, result.body)
		}
		accounts := decodeArray(t, result.body)
		if len(accounts) != 2 {
			t.Fatalf("%s linked account count=%d: %#v", implementation, len(accounts), accounts)
		}
		providers := map[string]bool{}
		for _, account := range accounts {
			providers[account["providerId"].(string)] = true
		}
		if !providers["credential"] || !providers["test"] {
			t.Fatalf("%s provider set mismatch: %#v", implementation, accounts)
		}
	}

	for implementation, result := range map[string]oracleResponse{
		"Go": goResponse(goClient.request(t, http.MethodPost, "/get-access-token", map[string]any{
			"providerId": "test",
		}, true)),
		"TypeScript": oracle.request(t, http.MethodPost, "/get-access-token", map[string]any{
			"providerId": "test",
		}, ""),
	} {
		if result.status != http.StatusOK {
			t.Fatalf("%s access token status=%d body=%s", implementation, result.status, result.body)
		}
		body := decodeObject(t, result.body)
		if body["accessToken"] == "" || body["idToken"] == "" {
			t.Fatalf("%s access-token response missing safe token fields: %#v", implementation, body)
		}
		scopes, ok := body["scopes"].([]any)
		if !ok || len(scopes) != 2 {
			t.Fatalf("%s access-token scopes mismatch: %#v", implementation, body)
		}
		if _, leaked := body["refreshToken"]; leaked {
			t.Fatalf("%s get-access-token leaked refresh token: %#v", implementation, body)
		}
	}

	refreshResults := map[string]oracleResponse{
		"Go": goResponse(goClient.request(t, http.MethodPost, "/refresh-token", map[string]any{
			"providerId": "test",
		}, true)),
		"TypeScript": oracle.request(t, http.MethodPost, "/refresh-token", map[string]any{
			"providerId": "test",
		}, ""),
	}
	for implementation, result := range refreshResults {
		if result.status != http.StatusOK {
			t.Fatalf("%s refresh token status=%d body=%s", implementation, result.status, result.body)
		}
		body := decodeObject(t, result.body)
		if body["accessToken"] == "" || body["idToken"] == "" ||
			body["providerId"] != "test" || body["accountId"] == "" {
			t.Fatalf("%s refresh-token response mismatch: %#v", implementation, body)
		}
	}
	if _, leaked := decodeObject(t, refreshResults["Go"].body)["refreshToken"]; leaked {
		t.Fatal("Go refresh-token route disclosed the provider refresh token")
	}
	if refreshToken, ok := decodeObject(t, refreshResults["TypeScript"].body)["refreshToken"].(string); !ok || refreshToken == "" {
		t.Fatal("the pinned TypeScript difference no longer returns a refresh token")
	}

	assertCode(
		t,
		http.StatusBadRequest,
		"ACCOUNT_NOT_FOUND",
		"Account not found",
		map[string]oracleResponse{
			"Go": goResponse(goClient.request(t, http.MethodPost, "/unlink-account", map[string]any{
				"providerId": "missing",
			}, true)),
			"TypeScript": oracle.request(t, http.MethodPost, "/unlink-account", map[string]any{
				"providerId": "missing",
			}, ""),
		},
	)
	for implementation, result := range map[string]oracleResponse{
		"Go": goResponse(goClient.request(t, http.MethodPost, "/unlink-account", map[string]any{
			"providerId": "test",
		}, true)),
		"TypeScript": oracle.request(t, http.MethodPost, "/unlink-account", map[string]any{
			"providerId": "test",
		}, ""),
	} {
		assertStatusTrue(t, implementation, result)
	}
	assertCode(
		t,
		http.StatusBadRequest,
		"ACCOUNT_NOT_FOUND",
		"Account not found",
		map[string]oracleResponse{
			"Go": goResponse(goClient.request(t, http.MethodPost, "/get-access-token", map[string]any{
				"providerId": "test",
			}, true)),
			"TypeScript": oracle.request(t, http.MethodPost, "/get-access-token", map[string]any{
				"providerId": "test",
			}, ""),
		},
	)

	assertCode(
		t,
		http.StatusBadRequest,
		"FAILED_TO_UNLINK_LAST_ACCOUNT",
		"You can't unlink your last account",
		map[string]oracleResponse{
			"Go": goResponse(goClient.request(t, http.MethodPost, "/unlink-account", map[string]any{
				"providerId": "credential",
			}, true)),
			"TypeScript": oracle.request(t, http.MethodPost, "/unlink-account", map[string]any{
				"providerId": "credential",
			}, ""),
		},
	)
}

func TestBetterAuthV1625ImpersonationCompatibility(t *testing.T) {
	oracle := newTypeScriptOracle(t)
	tsTarget := oracle.clone(t)
	goAdmin, _ := managementCompatibilityServer(t)
	goTarget := &testClient{handler: goAdmin.handler, database: goAdmin.database}
	const password = "Correct-Horse-123!"
	adminEmail := uniqueCompatibilityEmail("admin")
	targetEmail := uniqueCompatibilityEmail("impersonated")
	goAdminID, tsAdminID := signupCompatibilityUser(
		t, goAdmin, oracle, adminEmail, "Admin", password,
	)
	goTargetID, tsTargetID := signupCompatibilityUser(
		t, goTarget, tsTarget, targetEmail, "Target", password,
	)

	for implementation, result := range map[string]oracleResponse{
		"Go": goResponse(goTarget.request(t, http.MethodPost, "/admin/impersonate-user", map[string]any{
			"userId": goAdminID,
		}, true)),
		"TypeScript": tsTarget.request(t, http.MethodPost, "/admin/impersonate-user", map[string]any{
			"userId": tsAdminID,
		}, ""),
	} {
		if result.status != http.StatusForbidden {
			t.Fatalf("%s non-admin impersonation status=%d body=%s",
				implementation, result.status, result.body)
		}
	}

	started := map[string]oracleResponse{
		"Go": goResponse(goAdmin.request(t, http.MethodPost, "/admin/impersonate-user", map[string]any{
			"userId": goTargetID,
		}, true)),
		"TypeScript": oracle.request(t, http.MethodPost, "/admin/impersonate-user", map[string]any{
			"userId": tsTargetID,
		}, ""),
	}
	for implementation, result := range started {
		if result.status != http.StatusOK {
			t.Fatalf("%s impersonation start status=%d body=%s",
				implementation, result.status, result.body)
		}
		body := decodeObject(t, result.body)
		user, userOK := body["user"].(map[string]any)
		session, sessionOK := body["session"].(map[string]any)
		if !userOK || user["email"] != targetEmail || !sessionOK ||
			session["impersonatedBy"] == "" {
			t.Fatalf("%s impersonation response mismatch: %#v", implementation, body)
		}
		createdAt, createdErr := time.Parse(time.RFC3339Nano, session["createdAt"].(string))
		expiresAt, expiresErr := time.Parse(time.RFC3339Nano, session["expiresAt"].(string))
		if createdErr != nil || expiresErr != nil ||
			expiresAt.Sub(createdAt) > time.Hour || !expiresAt.After(createdAt) {
			t.Fatalf("%s impersonation duration is not bounded to one hour: %#v",
				implementation, session)
		}
	}
	for implementation, result := range map[string]oracleResponse{
		"Go":         goResponse(goAdmin.request(t, http.MethodGet, "/get-session", nil, false)),
		"TypeScript": oracle.request(t, http.MethodGet, "/get-session", nil, ""),
	} {
		if responseUser(t, result)["email"] != targetEmail {
			t.Fatalf("%s did not enter the target identity: %s", implementation, result.body)
		}
	}
	for implementation, result := range map[string]oracleResponse{
		"Go": goResponse(goAdmin.request(
			t, http.MethodPost, "/admin/stop-impersonating", map[string]any{}, true,
		)),
		"TypeScript": oracle.request(
			t, http.MethodPost, "/admin/stop-impersonating", map[string]any{}, "",
		),
	} {
		if result.status != http.StatusOK || responseUser(t, result)["email"] != adminEmail {
			t.Fatalf("%s impersonation stop mismatch: status=%d body=%s",
				implementation, result.status, result.body)
		}
	}
	for implementation, result := range map[string]oracleResponse{
		"Go":         goResponse(goAdmin.request(t, http.MethodGet, "/get-session", nil, false)),
		"TypeScript": oracle.request(t, http.MethodGet, "/get-session", nil, ""),
	} {
		if responseUser(t, result)["email"] != adminEmail {
			t.Fatalf("%s did not restore the administrator identity: %s", implementation, result.body)
		}
	}
}
