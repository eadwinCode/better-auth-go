package betterauth_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

const betterAuthV1626 = "1.6.26"

type oracleResponse struct {
	status  int
	header  http.Header
	body    []byte
	cookies []*http.Cookie
}

type typescriptOracle struct {
	baseURL       *url.URL
	origin        string
	basePath      string
	controlSecret string
	client        *http.Client
}

func newTypeScriptOracle(t *testing.T) *typescriptOracle {
	t.Helper()
	rawURL := strings.TrimRight(strings.TrimSpace(os.Getenv("BETTER_AUTH_TS_URL")), "/")
	if rawURL == "" {
		t.Skip("set BETTER_AUTH_TS_URL to run the Better Auth 1.6.26 differential suite")
	}
	baseURL, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse BETTER_AUTH_TS_URL: %v", err)
	}
	if baseURL.Scheme != "http" && baseURL.Scheme != "https" {
		t.Fatalf("BETTER_AUTH_TS_URL must use HTTP or HTTPS")
	}
	controlSecret := strings.TrimSpace(os.Getenv("BETTER_AUTH_TS_CONTROL_SECRET"))
	if controlSecret == "" {
		t.Fatal("BETTER_AUTH_TS_CONTROL_SECRET is required with BETTER_AUTH_TS_URL")
	}
	return newTypeScriptOracleClient(t, baseURL, controlSecret)
}

func newTypeScriptOracleClient(
	t *testing.T,
	baseURL *url.URL,
	controlSecret string,
) *typescriptOracle {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &typescriptOracle{
		baseURL:       baseURL,
		origin:        baseURL.Scheme + "://" + baseURL.Host,
		basePath:      "/api/auth",
		controlSecret: controlSecret,
		client: &http.Client{
			Jar:     jar,
			Timeout: 10 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (oracle *typescriptOracle) clone(t *testing.T) *typescriptOracle {
	t.Helper()
	clone := newTypeScriptOracleClient(t, oracle.baseURL, oracle.controlSecret)
	clone.basePath = oracle.basePath
	return clone
}

func (oracle *typescriptOracle) deletionVerificationClone(t *testing.T) *typescriptOracle {
	t.Helper()
	clone := oracle.clone(t)
	clone.basePath += "-delete"
	return clone
}

func (oracle *typescriptOracle) adminImpersonationClone(t *testing.T) *typescriptOracle {
	t.Helper()
	clone := oracle.clone(t)
	clone.basePath += "-admin-allow"
	return clone
}

type capturedOracleMail struct {
	Kind  string `json:"kind"`
	Email string `json:"email"`
	Token string `json:"token"`
	URL   string `json:"url"`
}

func (oracle *typescriptOracle) clearMail(t *testing.T) {
	t.Helper()
	request, err := http.NewRequest(
		http.MethodDelete,
		oracle.baseURL.String()+"/__better_auth_test/mail",
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("X-Better-Auth-Test-Secret", oracle.controlSecret)
	response, err := oracle.client.Do(request)
	if err != nil {
		t.Fatalf("clear TypeScript oracle mail: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		t.Fatalf("clear TypeScript oracle mail: status=%d body=%s", response.StatusCode, body)
	}
}

func (oracle *typescriptOracle) latestMail(
	t *testing.T,
	kind string,
	email string,
) capturedOracleMail {
	t.Helper()
	query := url.Values{"kind": {kind}, "email": {email}}
	request, err := http.NewRequest(
		http.MethodGet,
		oracle.baseURL.String()+"/__better_auth_test/mail/latest?"+query.Encode(),
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("X-Better-Auth-Test-Secret", oracle.controlSecret)
	response, err := oracle.client.Do(request)
	if err != nil {
		t.Fatalf("read TypeScript oracle mail: %v", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("read TypeScript oracle mail: status=%d body=%s", response.StatusCode, body)
	}
	var mail capturedOracleMail
	if err := json.Unmarshal(body, &mail); err != nil {
		t.Fatalf("decode TypeScript oracle mail %q: %v", body, err)
	}
	if mail.Token == "" || mail.Email != email || mail.Kind != kind {
		t.Fatalf("unexpected TypeScript oracle mail: %#v", mail)
	}
	return mail
}

func (oracle *typescriptOracle) mailExists(t *testing.T, kind string, email string) bool {
	t.Helper()
	query := url.Values{"kind": {kind}, "email": {email}}
	request, err := http.NewRequest(
		http.MethodGet,
		oracle.baseURL.String()+"/__better_auth_test/mail/latest?"+query.Encode(),
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("X-Better-Auth-Test-Secret", oracle.controlSecret)
	response, err := oracle.client.Do(request)
	if err != nil {
		t.Fatalf("check TypeScript oracle mail: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		return false
	}
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		t.Fatalf("check TypeScript oracle mail: status=%d body=%s", response.StatusCode, body)
	}
	return true
}

func (oracle *typescriptOracle) request(
	t *testing.T,
	method string,
	path string,
	body any,
	origin string,
) oracleResponse {
	t.Helper()
	return oracle.requestWithHeaders(t, method, path, body, origin, nil)
}

func (oracle *typescriptOracle) requestWithHeaders(
	t *testing.T,
	method string,
	path string,
	body any,
	origin string,
	headers http.Header,
) oracleResponse {
	t.Helper()
	var payload io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		payload = bytes.NewReader(encoded)
	}
	request, err := http.NewRequest(method, oracle.baseURL.String()+oracle.basePath+path, payload)
	if err != nil {
		t.Fatal(err)
	}
	if headers != nil {
		request.Header = headers.Clone()
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if origin == "" {
		origin = oracle.origin
	}
	request.Header.Set("Origin", origin)
	response, err := oracle.client.Do(request)
	if err != nil {
		t.Fatalf("TypeScript oracle request %s %s: %v", method, path, err)
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		t.Fatal(err)
	}
	return oracleResponse{
		status:  response.StatusCode,
		header:  response.Header.Clone(),
		body:    responseBody,
		cookies: response.Cookies(),
	}
}

func goResponse(recorder *httptest.ResponseRecorder) oracleResponse {
	result := recorder.Result()
	return oracleResponse{
		status:  recorder.Code,
		header:  result.Header.Clone(),
		body:    append([]byte(nil), recorder.Body.Bytes()...),
		cookies: result.Cookies(),
	}
}

func decodeObject(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("decode response %q: %v", body, err)
	}
	return result
}

func decodeArray(t *testing.T, body []byte) []map[string]any {
	t.Helper()
	var result []map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("decode response %q: %v", body, err)
	}
	return result
}

func responseUser(t *testing.T, response oracleResponse) map[string]any {
	t.Helper()
	object := decodeObject(t, response.body)
	user, ok := object["user"].(map[string]any)
	if !ok {
		t.Fatalf("response has no user object: %s", response.body)
	}
	return user
}

func assertEquivalentUser(
	t *testing.T,
	goResult oracleResponse,
	tsResult oracleResponse,
	email string,
	name string,
) {
	t.Helper()
	goUser := responseUser(t, goResult)
	tsUser := responseUser(t, tsResult)
	for implementation, user := range map[string]map[string]any{"Go": goUser, "TypeScript": tsUser} {
		if user["email"] != email || user["name"] != name {
			t.Fatalf("%s user mismatch: %#v", implementation, user)
		}
		verified, ok := user["emailVerified"].(bool)
		if !ok || verified {
			t.Fatalf("%s email verification mismatch: %#v", implementation, user)
		}
		for _, legacyField := range []string{"email_verified", "image_url", "created_at", "updated_at"} {
			if _, exists := user[legacyField]; exists {
				t.Fatalf("%s exposed legacy user field %q: %#v", implementation, legacyField, user)
			}
		}
		if _, exists := user["image"]; !exists {
			t.Fatalf("%s user has no nullable image field: %#v", implementation, user)
		}
		for _, timestamp := range []string{"createdAt", "updatedAt"} {
			if value, ok := user[timestamp].(string); !ok || value == "" {
				t.Fatalf("%s user has no %s: %#v", implementation, timestamp, user)
			}
		}
		if value, ok := user["id"].(string); !ok || value == "" {
			t.Fatalf("%s user has no ID: %#v", implementation, user)
		}
	}
}

// TestBetterAuthV1626BlackBoxCompatibility characterizes the common password
// and session lifecycle against the published Better Auth 1.6.26 HTTP server.
// Deliberate security differences and unresolved wire-format differences are
// asserted separately so they cannot disappear into normalization.
func TestBetterAuthV1626BlackBoxCompatibility(t *testing.T) {
	oracle := newTypeScriptOracle(t)

	healthRequest, err := http.NewRequest(http.MethodGet, oracle.baseURL.String()+"/healthz", nil)
	if err != nil {
		t.Fatal(err)
	}
	healthResponse, err := oracle.client.Do(healthRequest)
	if err != nil {
		t.Fatalf("TypeScript oracle health check: %v", err)
	}
	healthBody, readErr := io.ReadAll(io.LimitReader(healthResponse.Body, 1<<20))
	healthResponse.Body.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}
	health := decodeObject(t, healthBody)
	if healthResponse.StatusCode != http.StatusOK || health["betterAuthVersion"] != betterAuthV1626 {
		t.Fatalf("unexpected TypeScript oracle: status=%d body=%s", healthResponse.StatusCode, healthBody)
	}

	goClient, _ := newBlackBoxServer(t)
	email := "compat-" + time.Now().UTC().Format("20060102t150405.000000000") + "@example.com"
	const (
		name            = "Compatibility User"
		updatedName     = "Updated Compatibility User"
		password        = "Correct-Horse-123!"
		updatedPassword = "Updated-Horse-456!"
	)

	t.Run("unauthenticated session", func(t *testing.T) {
		goResult := goResponse(goClient.request(t, http.MethodGet, "/get-session", nil, false))
		tsResult := oracle.request(t, http.MethodGet, "/get-session", nil, "")
		if goResult.status != http.StatusOK || tsResult.status != http.StatusOK {
			t.Fatalf("status mismatch: Go=%d TypeScript=%d", goResult.status, tsResult.status)
		}
		if strings.TrimSpace(string(goResult.body)) != "null" ||
			strings.TrimSpace(string(tsResult.body)) != "null" {
			t.Fatalf("unauthenticated sessions differ: Go=%s TypeScript=%s", goResult.body, tsResult.body)
		}
	})

	t.Run("password bounds", func(t *testing.T) {
		for _, test := range []struct {
			name     string
			email    string
			password string
			code     string
		}{
			{
				name: "empty", email: "empty-" + email, password: "",
				code: "VALIDATION_ERROR",
			},
			{
				name: "too short", email: "short-" + email, password: "1234567",
				code: "PASSWORD_TOO_SHORT",
			},
			{
				name: "too long", email: "long-" + email, password: strings.Repeat("a", 129),
				code: "PASSWORD_TOO_LONG",
			},
		} {
			t.Run(test.name, func(t *testing.T) {
				input := map[string]any{
					"email": test.email, "password": test.password, "name": name,
				}
				goResult := goResponse(goClient.request(t, http.MethodPost, "/sign-up/email", input, false))
				tsResult := oracle.request(t, http.MethodPost, "/sign-up/email", input, "")
				if goResult.status != http.StatusBadRequest || tsResult.status != http.StatusBadRequest {
					t.Fatalf("status mismatch: Go=%d %s TypeScript=%d %s",
						goResult.status, goResult.body, tsResult.status, tsResult.body)
				}
				for implementation, result := range map[string]oracleResponse{
					"Go": goResult, "TypeScript": tsResult,
				} {
					body := decodeObject(t, result.body)
					if body["code"] != test.code {
						t.Fatalf("%s password error mismatch: %#v", implementation, body)
					}
				}
			})
		}
	})

	t.Run("invalid email", func(t *testing.T) {
		input := map[string]any{"email": "not-an-email", "password": password, "name": name}
		goResult := goResponse(goClient.request(t, http.MethodPost, "/sign-up/email", input, false))
		tsResult := oracle.request(t, http.MethodPost, "/sign-up/email", input, "")
		if goResult.status != http.StatusBadRequest || tsResult.status != http.StatusBadRequest {
			t.Fatalf("status mismatch: Go=%d %s TypeScript=%d %s",
				goResult.status, goResult.body, tsResult.status, tsResult.body)
		}
		for implementation, result := range map[string]oracleResponse{
			"Go": goResult, "TypeScript": tsResult,
		} {
			body := decodeObject(t, result.body)
			if body["code"] != "VALIDATION_ERROR" ||
				body["message"] != "[body.email] Invalid email address" {
				t.Fatalf("%s invalid-email error mismatch: %#v", implementation, body)
			}
		}
	})

	t.Run("sign up", func(t *testing.T) {
		input := map[string]any{"email": email, "password": password, "name": name}
		goResult := goResponse(goClient.request(t, http.MethodPost, "/sign-up/email", input, false))
		tsResult := oracle.request(t, http.MethodPost, "/sign-up/email", input, "")
		if goResult.status != http.StatusOK || tsResult.status != http.StatusOK {
			t.Fatalf("status mismatch: Go=%d %s TypeScript=%d %s",
				goResult.status, goResult.body, tsResult.status, tsResult.body)
		}
		assertEquivalentUser(t, goResult, tsResult, email, name)

		goBody := decodeObject(t, goResult.body)
		tsBody := decodeObject(t, tsResult.body)
		if goBody["token"] != nil {
			t.Fatalf("Go must not expose its cookie session token: %s", goResult.body)
		}
		if token, ok := tsBody["token"].(string); !ok || token == "" {
			t.Fatalf("expected upstream bearer token for difference characterization: %s", tsResult.body)
		}
		if goClient.session == nil || goClient.session.Name != "__Host-better_auth_session" ||
			!goClient.session.Secure || !goClient.session.HttpOnly {
			t.Fatalf("Go host-cookie contract changed: %#v", goClient.session)
		}
	})

	t.Run("authenticated session", func(t *testing.T) {
		goResult := goResponse(goClient.request(t, http.MethodGet, "/get-session", nil, false))
		tsResult := oracle.request(t, http.MethodGet, "/get-session", nil, "")
		if goResult.status != http.StatusOK || tsResult.status != http.StatusOK {
			t.Fatalf("status mismatch: Go=%d TypeScript=%d", goResult.status, tsResult.status)
		}
		assertEquivalentUser(t, goResult, tsResult, email, name)
		for implementation, result := range map[string]oracleResponse{"Go": goResult, "TypeScript": tsResult} {
			session, ok := decodeObject(t, result.body)["session"].(map[string]any)
			if !ok {
				t.Fatalf("%s response has no session: %s", implementation, result.body)
			}
			for _, field := range []string{"id", "userId", "expiresAt", "createdAt", "updatedAt"} {
				if _, exists := session[field]; !exists {
					t.Fatalf("%s session has no %s: %#v", implementation, field, session)
				}
			}
			for _, legacyField := range []string{"user_id", "expires_at", "created_at", "updated_at"} {
				if _, exists := session[legacyField]; exists {
					t.Fatalf("%s exposed legacy session field %q: %#v", implementation, legacyField, session)
				}
			}
		}
	})

	t.Run("credential account listing", func(t *testing.T) {
		goResult := goResponse(goClient.request(t, http.MethodGet, "/list-accounts", nil, false))
		tsResult := oracle.request(t, http.MethodGet, "/list-accounts", nil, "")
		if goResult.status != http.StatusOK || tsResult.status != http.StatusOK {
			t.Fatalf("status mismatch: Go=%d %s TypeScript=%d %s",
				goResult.status, goResult.body, tsResult.status, tsResult.body)
		}
		for implementation, accounts := range map[string][]map[string]any{
			"Go": decodeArray(t, goResult.body), "TypeScript": decodeArray(t, tsResult.body),
		} {
			if len(accounts) != 1 || accounts[0]["providerId"] != "credential" {
				t.Fatalf("%s credential account mismatch: %#v", implementation, accounts)
			}
			for _, secret := range []string{"password", "accessToken", "refreshToken", "idToken"} {
				if _, exists := accounts[0][secret]; exists {
					t.Fatalf("%s account leaked %s: %#v", implementation, secret, accounts[0])
				}
			}
		}
	})

	t.Run("session listing token difference", func(t *testing.T) {
		goResult := goResponse(goClient.request(t, http.MethodGet, "/list-sessions", nil, false))
		tsResult := oracle.request(t, http.MethodGet, "/list-sessions", nil, "")
		if goResult.status != http.StatusOK || tsResult.status != http.StatusOK {
			t.Fatalf("status mismatch: Go=%d %s TypeScript=%d %s",
				goResult.status, goResult.body, tsResult.status, tsResult.body)
		}
		goSessions := decodeArray(t, goResult.body)
		tsSessions := decodeArray(t, tsResult.body)
		if len(goSessions) != 1 || len(tsSessions) != 1 {
			t.Fatalf("session counts differ: Go=%#v TypeScript=%#v", goSessions, tsSessions)
		}
		if _, exists := goSessions[0]["token"]; exists {
			t.Fatalf("Go session listing exposed a bearer token: %#v", goSessions[0])
		}
		if token, ok := tsSessions[0]["token"].(string); !ok || token == "" {
			t.Fatalf("expected upstream token for difference characterization: %#v", tsSessions[0])
		}
	})

	t.Run("user update", func(t *testing.T) {
		input := map[string]any{"name": updatedName}
		goResult := goResponse(goClient.request(t, http.MethodPost, "/update-user", input, true))
		tsResult := oracle.request(t, http.MethodPost, "/update-user", input, "")
		if goResult.status != http.StatusOK || tsResult.status != http.StatusOK {
			t.Fatalf("status mismatch: Go=%d %s TypeScript=%d %s",
				goResult.status, goResult.body, tsResult.status, tsResult.body)
		}
		for implementation, result := range map[string]oracleResponse{"Go": goResult, "TypeScript": tsResult} {
			if decodeObject(t, result.body)["status"] != true {
				t.Fatalf("%s update-user response mismatch: %s", implementation, result.body)
			}
		}
		goSession := goResponse(goClient.request(t, http.MethodGet, "/get-session", nil, false))
		tsSession := oracle.request(t, http.MethodGet, "/get-session", nil, "")
		assertEquivalentUser(t, goSession, tsSession, email, updatedName)
	})

	t.Run("revoke other sessions", func(t *testing.T) {
		goResult := goResponse(goClient.request(
			t, http.MethodPost, "/revoke-other-sessions", map[string]any{}, true,
		))
		tsResult := oracle.request(t, http.MethodPost, "/revoke-other-sessions", map[string]any{}, "")
		if goResult.status != http.StatusOK || tsResult.status != http.StatusOK {
			t.Fatalf("status mismatch: Go=%d %s TypeScript=%d %s",
				goResult.status, goResult.body, tsResult.status, tsResult.body)
		}
	})

	t.Run("invalid credentials remain generic", func(t *testing.T) {
		input := map[string]any{"email": "missing-" + email, "password": password}
		goResult := goResponse(goClient.request(t, http.MethodPost, "/sign-in/email", input, false))
		tsResult := oracle.request(t, http.MethodPost, "/sign-in/email", input, "")
		if goResult.status != http.StatusUnauthorized || tsResult.status != http.StatusUnauthorized {
			t.Fatalf("status mismatch: Go=%d %s TypeScript=%d %s",
				goResult.status, goResult.body, tsResult.status, tsResult.body)
		}
		for implementation, body := range map[string][]byte{"Go": goResult.body, "TypeScript": tsResult.body} {
			if bytes.Contains(body, []byte("missing-"+email)) || bytes.Contains(body, []byte(password)) {
				t.Fatalf("%s leaked submitted credentials: %s", implementation, body)
			}
			errorBody := decodeObject(t, body)
			if errorBody["code"] != "INVALID_EMAIL_OR_PASSWORD" ||
				errorBody["message"] != "Invalid email or password" {
				t.Fatalf("%s credential error mismatch: %#v", implementation, errorBody)
			}
			if _, nested := errorBody["error"]; nested {
				t.Fatalf("%s returned a legacy nested error: %#v", implementation, errorBody)
			}
		}
	})

	t.Run("change password", func(t *testing.T) {
		input := map[string]any{
			"currentPassword": password, "newPassword": updatedPassword, "revokeOtherSessions": true,
		}
		goResult := goResponse(goClient.request(t, http.MethodPost, "/change-password", input, true))
		tsResult := oracle.request(t, http.MethodPost, "/change-password", input, "")
		if goResult.status != http.StatusOK || tsResult.status != http.StatusOK {
			t.Fatalf("status mismatch: Go=%d %s TypeScript=%d %s",
				goResult.status, goResult.body, tsResult.status, tsResult.body)
		}
		assertEquivalentUser(t, goResult, tsResult, email, updatedName)
	})

	t.Run("untrusted origin", func(t *testing.T) {
		input := map[string]any{"email": "origin-" + email, "password": password, "name": name}
		encoded, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(
			http.MethodPost,
			"https://auth.example.com/api/auth/sign-up/email",
			bytes.NewReader(encoded),
		)
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Origin", "https://evil.example")
		recorder := httptest.NewRecorder()
		goClient.handler.ServeHTTP(recorder, request)
		goResult := goResponse(recorder)
		tsResult := oracle.request(t, http.MethodPost, "/sign-up/email", input, "https://evil.example")
		if goResult.status != http.StatusForbidden || tsResult.status != http.StatusForbidden {
			t.Fatalf("status mismatch: Go=%d %s TypeScript=%d %s",
				goResult.status, goResult.body, tsResult.status, tsResult.body)
		}
		for implementation, result := range map[string]oracleResponse{"Go": goResult, "TypeScript": tsResult} {
			errorBody := decodeObject(t, result.body)
			if errorBody["code"] != "INVALID_ORIGIN" || errorBody["message"] != "Invalid origin" {
				t.Fatalf("%s origin error mismatch: %#v", implementation, errorBody)
			}
			if _, nested := errorBody["error"]; nested {
				t.Fatalf("%s returned a legacy nested error: %#v", implementation, errorBody)
			}
		}
	})

	t.Run("duplicate account", func(t *testing.T) {
		input := map[string]any{"email": email, "password": password, "name": name}
		goResult := goResponse(goClient.request(t, http.MethodPost, "/sign-up/email", input, false))
		tsResult := oracle.request(t, http.MethodPost, "/sign-up/email", input, "")
		if goResult.status != http.StatusUnprocessableEntity ||
			tsResult.status != http.StatusUnprocessableEntity {
			t.Fatalf("status mismatch: Go=%d %s TypeScript=%d %s",
				goResult.status, goResult.body, tsResult.status, tsResult.body)
		}
		for implementation, result := range map[string]oracleResponse{
			"Go": goResult, "TypeScript": tsResult,
		} {
			body := decodeObject(t, result.body)
			if body["code"] != "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL" ||
				body["message"] != "User already exists. Use another email." {
				t.Fatalf("%s duplicate error mismatch: %#v", implementation, body)
			}
		}
	})

	t.Run("sign out", func(t *testing.T) {
		goResult := goResponse(goClient.request(t, http.MethodPost, "/sign-out", map[string]any{}, true))
		tsResult := oracle.request(t, http.MethodPost, "/sign-out", map[string]any{}, "")
		if goResult.status != http.StatusOK || tsResult.status != http.StatusOK {
			t.Fatalf("status mismatch: Go=%d %s TypeScript=%d %s",
				goResult.status, goResult.body, tsResult.status, tsResult.body)
		}
		goSession := goResponse(goClient.request(t, http.MethodGet, "/get-session", nil, false))
		tsSession := oracle.request(t, http.MethodGet, "/get-session", nil, "")
		if strings.TrimSpace(string(goSession.body)) != "null" ||
			strings.TrimSpace(string(tsSession.body)) != "null" {
			t.Fatalf("sessions survived sign-out: Go=%s TypeScript=%s", goSession.body, tsSession.body)
		}
	})

	t.Run("sign in with changed password", func(t *testing.T) {
		input := map[string]any{"email": email, "password": updatedPassword}
		goResult := goResponse(goClient.request(t, http.MethodPost, "/sign-in/email", input, false))
		tsResult := oracle.request(t, http.MethodPost, "/sign-in/email", input, "")
		if goResult.status != http.StatusOK || tsResult.status != http.StatusOK {
			t.Fatalf("status mismatch: Go=%d %s TypeScript=%d %s",
				goResult.status, goResult.body, tsResult.status, tsResult.body)
		}
		assertEquivalentUser(t, goResult, tsResult, email, updatedName)
	})
}
