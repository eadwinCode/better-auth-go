package betterauth_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	betterauth "github.com/eadwinCode/better-auth-go"
)

func uniqueCompatibilityEmail(prefix string) string {
	return prefix + "-" + time.Now().UTC().Format("20060102t150405.000000000") + "@example.com"
}

func assertStatusTrue(t *testing.T, implementation string, response oracleResponse) {
	t.Helper()
	if response.status != http.StatusOK {
		t.Fatalf("%s status=%d body=%s", implementation, response.status, response.body)
	}
	if decodeObject(t, response.body)["status"] != true {
		t.Fatalf("%s response does not contain status=true: %s", implementation, response.body)
	}
}

func TestBetterAuthV170PasswordRecoveryCompatibility(t *testing.T) {
	oracle := newTypeScriptOracle(t)
	oracle.clearMail(t)
	const goCallbackURL = "https://app.example.com/recovery"
	goClient, goMailer := newBlackBoxServerConfig(t, func(config *betterauth.Config) {
		config.AllowedRedirectURLs = []string{goCallbackURL}
	})
	email := uniqueCompatibilityEmail("recovery")
	missingEmail := "missing-" + email
	const (
		name        = "Recovery Compatibility User"
		password    = "Correct-Horse-123!"
		newPassword = "Updated-Horse-456!"
	)

	for implementation, response := range map[string]oracleResponse{
		"Go": goResponse(goClient.request(t, http.MethodPost, "/sign-up/email", map[string]any{
			"email": email, "password": password, "name": name,
		}, false)),
		"TypeScript": oracle.request(t, http.MethodPost, "/sign-up/email", map[string]any{
			"email": email, "password": password, "name": name,
		}, ""),
	} {
		if response.status != http.StatusOK {
			t.Fatalf("%s signup status=%d body=%s", implementation, response.status, response.body)
		}
	}

	const genericMessage = "If this email exists in our system, check your email for the reset link"
	for implementation, response := range map[string]oracleResponse{
		"Go": goResponse(goClient.request(
			t,
			http.MethodPost,
			"/request-password-reset",
			map[string]any{"email": missingEmail},
			false,
		)),
		"TypeScript": oracle.request(
			t,
			http.MethodPost,
			"/request-password-reset",
			map[string]any{"email": missingEmail},
			"",
		),
	} {
		if response.status != http.StatusOK {
			t.Fatalf("%s missing-account reset status=%d body=%s", implementation, response.status, response.body)
		}
		body := decodeObject(t, response.body)
		if body["status"] != true || body["message"] != genericMessage {
			t.Fatalf("%s generic reset response mismatch: %#v", implementation, body)
		}
	}

	goRequest := goResponse(goClient.request(
		t,
		http.MethodPost,
		"/request-password-reset",
		map[string]any{"email": email},
		false,
	))
	tsRequest := oracle.request(
		t,
		http.MethodPost,
		"/request-password-reset",
		map[string]any{"email": email},
		"",
	)
	for implementation, response := range map[string]oracleResponse{
		"Go": goRequest, "TypeScript": tsRequest,
	} {
		if response.status != http.StatusOK {
			t.Fatalf("%s reset request status=%d body=%s", implementation, response.status, response.body)
		}
		body := decodeObject(t, response.body)
		if body["status"] != true || body["message"] != genericMessage {
			t.Fatalf("%s reset request response mismatch: %#v", implementation, body)
		}
	}
	goToken := goMailer.last().Token
	tsToken := oracle.latestMail(t, "password-reset", email).Token

	const invalidToken = "invalid-reset-token-long-enough"
	for implementation, response := range map[string]oracleResponse{
		"Go": goResponse(goClient.request(t, http.MethodPost, "/reset-password", map[string]any{
			"token": invalidToken, "newPassword": newPassword,
		}, false)),
		"TypeScript": oracle.request(t, http.MethodPost, "/reset-password", map[string]any{
			"token": invalidToken, "newPassword": newPassword,
		}, ""),
	} {
		if response.status != http.StatusBadRequest {
			t.Fatalf("%s invalid reset status=%d body=%s", implementation, response.status, response.body)
		}
		body := decodeObject(t, response.body)
		if body["code"] != "INVALID_TOKEN" || body["message"] != "Invalid token" {
			t.Fatalf("%s invalid reset response mismatch: %#v", implementation, body)
		}
	}

	for implementation, response := range map[string]oracleResponse{
		"Go": goResponse(goClient.request(t, http.MethodPost, "/reset-password", map[string]any{
			"token": goToken, "newPassword": newPassword,
		}, false)),
		"TypeScript": oracle.request(t, http.MethodPost, "/reset-password", map[string]any{
			"token": tsToken, "newPassword": newPassword,
		}, ""),
	} {
		assertStatusTrue(t, implementation, response)
		if len(response.cookies) != 0 {
			t.Fatalf("%s password reset unexpectedly issued a session cookie: %#v", implementation, response.cookies)
		}
	}

	for implementation, response := range map[string]oracleResponse{
		"Go": goResponse(goClient.request(t, http.MethodPost, "/reset-password", map[string]any{
			"token": goToken, "newPassword": "Another-Horse-789!",
		}, false)),
		"TypeScript": oracle.request(t, http.MethodPost, "/reset-password", map[string]any{
			"token": tsToken, "newPassword": "Another-Horse-789!",
		}, ""),
	} {
		if response.status != http.StatusBadRequest ||
			decodeObject(t, response.body)["code"] != "INVALID_TOKEN" {
			t.Fatalf("%s accepted reset-token replay: status=%d body=%s", implementation, response.status, response.body)
		}
	}

	tsCallbackURL := oracle.origin + "/recovery"
	goCallbackRequest := goResponse(goClient.request(
		t,
		http.MethodPost,
		"/request-password-reset",
		map[string]any{"email": email, "redirectTo": goCallbackURL},
		false,
	))
	tsCallbackRequest := oracle.request(
		t,
		http.MethodPost,
		"/request-password-reset",
		map[string]any{"email": email, "redirectTo": tsCallbackURL},
		"",
	)
	if goCallbackRequest.status != http.StatusOK || tsCallbackRequest.status != http.StatusOK {
		t.Fatalf("callback reset request mismatch: Go=%d %s TypeScript=%d %s",
			goCallbackRequest.status, goCallbackRequest.body,
			tsCallbackRequest.status, tsCallbackRequest.body)
	}
	goCallbackToken := goMailer.last().Token
	tsCallbackToken := oracle.latestMail(t, "password-reset", email).Token
	goCallback := goResponse(goClient.request(
		t,
		http.MethodGet,
		"/reset-password/"+url.PathEscape(goCallbackToken)+"?callbackURL="+url.QueryEscape(goCallbackURL),
		nil,
		false,
	))
	tsCallback := oracle.request(
		t,
		http.MethodGet,
		"/reset-password/"+url.PathEscape(tsCallbackToken)+"?callbackURL="+url.QueryEscape(tsCallbackURL),
		nil,
		"",
	)
	for implementation, result := range map[string]struct {
		response oracleResponse
		callback string
		token    string
	}{
		"Go":         {goCallback, goCallbackURL, goCallbackToken},
		"TypeScript": {tsCallback, tsCallbackURL, tsCallbackToken},
	} {
		if result.response.status != http.StatusFound {
			t.Fatalf("%s reset callback status=%d body=%s",
				implementation, result.response.status, result.response.body)
		}
		location, err := url.Parse(result.response.header.Get("Location"))
		if err != nil {
			t.Fatalf("%s reset callback location: %v", implementation, err)
		}
		if location.Scheme+"://"+location.Host+location.Path != result.callback ||
			location.Query().Get("token") != result.token {
			t.Fatalf("%s reset callback mismatch: %s", implementation, location)
		}
	}

	goLogin := &testClient{handler: goClient.handler, database: goClient.database}
	tsLogin := oracle.clone(t)
	for implementation, response := range map[string]oracleResponse{
		"Go": goResponse(goLogin.request(t, http.MethodPost, "/sign-in/email", map[string]any{
			"email": email, "password": newPassword,
		}, false)),
		"TypeScript": tsLogin.request(t, http.MethodPost, "/sign-in/email", map[string]any{
			"email": email, "password": newPassword,
		}, ""),
	} {
		if response.status != http.StatusOK {
			t.Fatalf("%s could not sign in with reset password: status=%d body=%s", implementation, response.status, response.body)
		}
	}
}

func TestBetterAuthV170EmailVerificationCompatibility(t *testing.T) {
	oracle := newTypeScriptOracle(t)
	oracle.clearMail(t)
	goClient, goMailer := newBlackBoxServer(t)
	email := uniqueCompatibilityEmail("verification")
	const (
		name     = "Verification Compatibility User"
		password = "Correct-Horse-123!"
	)

	goSignup := goResponse(goClient.request(t, http.MethodPost, "/sign-up/email", map[string]any{
		"email": email, "password": password, "name": name,
	}, false))
	tsSignup := oracle.request(t, http.MethodPost, "/sign-up/email", map[string]any{
		"email": email, "password": password, "name": name,
	}, "")
	if goSignup.status != http.StatusOK || tsSignup.status != http.StatusOK {
		t.Fatalf("signup mismatch: Go=%d %s TypeScript=%d %s",
			goSignup.status, goSignup.body, tsSignup.status, tsSignup.body)
	}

	for implementation, response := range map[string]oracleResponse{
		"Go": goResponse(goClient.request(t, http.MethodPost, "/send-verification-email", map[string]any{
			"email": email,
		}, true)),
		"TypeScript": oracle.request(t, http.MethodPost, "/send-verification-email", map[string]any{
			"email": email,
		}, ""),
	} {
		assertStatusTrue(t, implementation, response)
	}
	goToken := goMailer.last().Token
	tsToken := oracle.latestMail(t, "email-verification", email).Token

	goVerify := goResponse(goClient.request(
		t,
		http.MethodGet,
		"/verify-email?token="+url.QueryEscape(goToken),
		nil,
		false,
	))
	tsVerify := oracle.request(
		t,
		http.MethodGet,
		"/verify-email?token="+url.QueryEscape(tsToken),
		nil,
		"",
	)
	for implementation, response := range map[string]oracleResponse{
		"Go": goVerify, "TypeScript": tsVerify,
	} {
		assertStatusTrue(t, implementation, response)
		if decodeObject(t, response.body)["user"] != nil {
			t.Fatalf("%s ordinary verification exposed a user payload: %s", implementation, response.body)
		}
	}

	for implementation, response := range map[string]oracleResponse{
		"Go":         goResponse(goClient.request(t, http.MethodGet, "/get-session", nil, false)),
		"TypeScript": oracle.request(t, http.MethodGet, "/get-session", nil, ""),
	} {
		if response.status != http.StatusOK {
			t.Fatalf("%s session status=%d body=%s", implementation, response.status, response.body)
		}
		user := responseUser(t, response)
		if user["emailVerified"] != true {
			t.Fatalf("%s session did not observe verification: %#v", implementation, user)
		}
	}

	goReplay := goResponse(goClient.request(
		t,
		http.MethodGet,
		"/verify-email?token="+url.QueryEscape(goToken),
		nil,
		false,
	))
	tsReplay := oracle.request(
		t,
		http.MethodGet,
		"/verify-email?token="+url.QueryEscape(tsToken),
		nil,
		"",
	)
	if goReplay.status != http.StatusBadRequest ||
		decodeObject(t, goReplay.body)["code"] != "INVALID_TOKEN" {
		t.Fatalf("Go accepted single-use verification replay: %d %s", goReplay.status, goReplay.body)
	}
	assertStatusTrue(t, "TypeScript", tsReplay)
	if decodeObject(t, tsReplay.body)["user"] != nil {
		t.Fatalf("unexpected TypeScript replay response: %s", tsReplay.body)
	}

	for implementation, response := range map[string]oracleResponse{
		"Go": goResponse(goClient.request(t, http.MethodPost, "/send-verification-email", map[string]any{
			"email": email,
		}, true)),
		"TypeScript": oracle.request(t, http.MethodPost, "/send-verification-email", map[string]any{
			"email": email,
		}, ""),
	} {
		if response.status != http.StatusBadRequest {
			t.Fatalf("%s already-verified status=%d body=%s", implementation, response.status, response.body)
		}
		body := decodeObject(t, response.body)
		if body["code"] != "EMAIL_ALREADY_VERIFIED" ||
			body["message"] != "Email is already verified" {
			t.Fatalf("%s already-verified response mismatch: %#v", implementation, body)
		}
	}

	missingEmail := "missing-" + email
	goAnonymous := &testClient{handler: goClient.handler, database: goClient.database}
	tsAnonymous := oracle.clone(t)
	for implementation, response := range map[string]oracleResponse{
		"Go": goResponse(goAnonymous.request(t, http.MethodPost, "/send-verification-email", map[string]any{
			"email": missingEmail,
		}, false)),
		"TypeScript": tsAnonymous.request(t, http.MethodPost, "/send-verification-email", map[string]any{
			"email": missingEmail,
		}, ""),
	} {
		assertStatusTrue(t, implementation, response)
	}
}

func TestBetterAuthV170SessionManagementCompatibility(t *testing.T) {
	oracle := newTypeScriptOracle(t)
	goFirst, _ := newBlackBoxServerConfig(t, func(config *betterauth.Config) {
		config.Plugins = append(config.Plugins, betterauth.Plugin{
			ID: "compat-session-field",
			Schema: betterauth.Schema{
				betterauth.ModelSession: {
					Fields: map[string]betterauth.FieldSchema{
						"label": {
							Type: betterauth.FieldString, Input: true, Returned: true,
						},
					},
				},
			},
		})
	})
	goSecond := &testClient{handler: goFirst.handler, database: goFirst.database}
	tsSecond := oracle.clone(t)
	email := uniqueCompatibilityEmail("sessions")
	const (
		name     = "Session Compatibility User"
		password = "Correct-Horse-123!"
	)

	goSignup := goResponse(goFirst.request(t, http.MethodPost, "/sign-up/email", map[string]any{
		"email": email, "password": password, "name": name,
	}, false))
	tsSignup := oracle.request(t, http.MethodPost, "/sign-up/email", map[string]any{
		"email": email, "password": password, "name": name,
	}, "")
	if goSignup.status != http.StatusOK || tsSignup.status != http.StatusOK {
		t.Fatalf("signup mismatch: Go=%d %s TypeScript=%d %s",
			goSignup.status, goSignup.body, tsSignup.status, tsSignup.body)
	}

	goSignin := goResponse(goSecond.request(t, http.MethodPost, "/sign-in/email", map[string]any{
		"email": email, "password": password,
	}, false))
	tsSignin := tsSecond.request(t, http.MethodPost, "/sign-in/email", map[string]any{
		"email": email, "password": password,
	}, "")
	if goSignin.status != http.StatusOK || tsSignin.status != http.StatusOK {
		t.Fatalf("second signin mismatch: Go=%d %s TypeScript=%d %s",
			goSignin.status, goSignin.body, tsSignin.status, tsSignin.body)
	}
	tsSecondToken, ok := decodeObject(t, tsSignin.body)["token"].(string)
	if !ok || tsSecondToken == "" {
		t.Fatalf("TypeScript signin did not return its bearer token: %s", tsSignin.body)
	}

	goList := goResponse(goFirst.request(t, http.MethodGet, "/list-sessions", nil, false))
	tsList := oracle.request(t, http.MethodGet, "/list-sessions", nil, "")
	if goList.status != http.StatusOK || tsList.status != http.StatusOK {
		t.Fatalf("list mismatch: Go=%d %s TypeScript=%d %s",
			goList.status, goList.body, tsList.status, tsList.body)
	}
	goSessions := decodeArray(t, goList.body)
	tsSessions := decodeArray(t, tsList.body)
	if len(goSessions) != 2 || len(tsSessions) != 2 {
		t.Fatalf("session counts differ: Go=%#v TypeScript=%#v", goSessions, tsSessions)
	}
	var goOtherID string
	for _, session := range goSessions {
		if session["current"] == false {
			goOtherID, _ = session["id"].(string)
		}
		if _, exposed := session["token"]; exposed {
			t.Fatalf("Go exposed a session bearer token: %#v", session)
		}
	}
	if goOtherID == "" {
		t.Fatalf("Go did not identify the non-current session: %#v", goSessions)
	}
	for _, session := range tsSessions {
		if token, _ := session["token"].(string); token == "" {
			t.Fatalf("TypeScript session has no token for difference characterization: %#v", session)
		}
	}

	for implementation, response := range map[string]oracleResponse{
		"Go": goResponse(goFirst.request(t, http.MethodPost, "/revoke-session", map[string]any{
			"sessionId": goOtherID,
		}, true)),
		"TypeScript": oracle.request(t, http.MethodPost, "/revoke-session", map[string]any{
			"token": tsSecondToken,
		}, ""),
	} {
		assertStatusTrue(t, implementation, response)
	}
	for implementation, response := range map[string]oracleResponse{
		"Go":         goResponse(goSecond.request(t, http.MethodGet, "/get-session", nil, false)),
		"TypeScript": tsSecond.request(t, http.MethodGet, "/get-session", nil, ""),
	} {
		if response.status != http.StatusOK || strings.TrimSpace(string(response.body)) != "null" {
			t.Fatalf("%s revoked session survived: status=%d body=%s", implementation, response.status, response.body)
		}
	}

	for implementation, response := range map[string]oracleResponse{
		"Go": goResponse(goFirst.request(t, http.MethodPost, "/update-session", map[string]any{
			"label": "primary",
		}, true)),
		"TypeScript": oracle.request(t, http.MethodPost, "/update-session", map[string]any{
			"label": "primary",
		}, ""),
	} {
		if response.status != http.StatusOK {
			t.Fatalf("%s update-session status=%d body=%s", implementation, response.status, response.body)
		}
		body := decodeObject(t, response.body)
		session, ok := body["session"].(map[string]any)
		if !ok || session["label"] != "primary" {
			t.Fatalf("%s update-session response mismatch: %#v", implementation, body)
		}
		if _, exposed := body["user"]; exposed {
			t.Fatalf("%s update-session unexpectedly returned a user: %#v", implementation, body)
		}
	}

	goSecond = &testClient{handler: goFirst.handler, database: goFirst.database}
	tsSecond = oracle.clone(t)
	if response := goSecond.request(t, http.MethodPost, "/sign-in/email", map[string]any{
		"email": email, "password": password,
	}, false); response.Code != http.StatusOK {
		t.Fatalf("Go second signin failed: %s", response.Body.String())
	}
	if response := tsSecond.request(t, http.MethodPost, "/sign-in/email", map[string]any{
		"email": email, "password": password,
	}, ""); response.status != http.StatusOK {
		t.Fatalf("TypeScript second signin failed: %s", response.body)
	}

	for implementation, response := range map[string]oracleResponse{
		"Go": goResponse(goFirst.request(
			t, http.MethodPost, "/revoke-other-sessions", map[string]any{}, true,
		)),
		"TypeScript": oracle.request(
			t, http.MethodPost, "/revoke-other-sessions", map[string]any{}, "",
		),
	} {
		assertStatusTrue(t, implementation, response)
	}
	for implementation, response := range map[string]oracleResponse{
		"Go":         goResponse(goSecond.request(t, http.MethodGet, "/get-session", nil, false)),
		"TypeScript": tsSecond.request(t, http.MethodGet, "/get-session", nil, ""),
	} {
		if response.status != http.StatusOK || strings.TrimSpace(string(response.body)) != "null" {
			t.Fatalf("%s other session survived revocation: status=%d body=%s", implementation, response.status, response.body)
		}
	}

	for implementation, response := range map[string]oracleResponse{
		"Go": goResponse(goFirst.request(
			t, http.MethodPost, "/revoke-sessions", map[string]any{}, true,
		)),
		"TypeScript": oracle.request(
			t, http.MethodPost, "/revoke-sessions", map[string]any{}, "",
		),
	} {
		assertStatusTrue(t, implementation, response)
	}
	for implementation, response := range map[string]oracleResponse{
		"Go":         goResponse(goFirst.request(t, http.MethodGet, "/get-session", nil, false)),
		"TypeScript": oracle.request(t, http.MethodGet, "/get-session", nil, ""),
	} {
		if response.status != http.StatusOK || strings.TrimSpace(string(response.body)) != "null" {
			t.Fatalf("%s current session survived revoke-sessions: status=%d body=%s", implementation, response.status, response.body)
		}
	}
}
