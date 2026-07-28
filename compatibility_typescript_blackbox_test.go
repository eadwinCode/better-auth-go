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

	betterauth "github.com/eadwinCode/better-auth-go"
)

const betterAuthV1625 = "1.6.25"

type oracleResponse struct {
	status  int
	header  http.Header
	body    []byte
	cookies []*http.Cookie
}

type typescriptOracle struct {
	baseURL *url.URL
	origin  string
	client  *http.Client
}

func newTypeScriptOracle(t *testing.T) *typescriptOracle {
	t.Helper()
	rawURL := strings.TrimRight(strings.TrimSpace(os.Getenv("BETTER_AUTH_TS_URL")), "/")
	if rawURL == "" {
		t.Skip("set BETTER_AUTH_TS_URL to run the Better Auth 1.6.25 differential suite")
	}
	baseURL, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse BETTER_AUTH_TS_URL: %v", err)
	}
	if baseURL.Scheme != "http" && baseURL.Scheme != "https" {
		t.Fatalf("BETTER_AUTH_TS_URL must use HTTP or HTTPS")
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &typescriptOracle{
		baseURL: baseURL,
		origin:  baseURL.Scheme + "://" + baseURL.Host,
		client: &http.Client{
			Jar:     jar,
			Timeout: 10 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (oracle *typescriptOracle) request(
	t *testing.T,
	method string,
	path string,
	body any,
	origin string,
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
	request, err := http.NewRequest(method, oracle.baseURL.String()+"/api/auth"+path, payload)
	if err != nil {
		t.Fatal(err)
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

func booleanField(object map[string]any, names ...string) (bool, bool) {
	for _, name := range names {
		value, exists := object[name]
		if !exists {
			continue
		}
		result, ok := value.(bool)
		return result, ok
	}
	return false, false
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
		verified, ok := booleanField(user, "emailVerified", "email_verified")
		if !ok || verified {
			t.Fatalf("%s email verification mismatch: %#v", implementation, user)
		}
		if value, ok := user["id"].(string); !ok || value == "" {
			t.Fatalf("%s user has no ID: %#v", implementation, user)
		}
	}
}

// TestBetterAuthV1625BlackBoxCompatibility characterizes the common password
// and session lifecycle against the published Better Auth 1.6.25 HTTP server.
// Deliberate security differences and unresolved wire-format differences are
// asserted separately so they cannot disappear into normalization.
func TestBetterAuthV1625BlackBoxCompatibility(t *testing.T) {
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
	if healthResponse.StatusCode != http.StatusOK || health["betterAuthVersion"] != betterAuthV1625 {
		t.Fatalf("unexpected TypeScript oracle: status=%d body=%s", healthResponse.StatusCode, healthBody)
	}

	goClient, _ := newBlackBoxServerConfig(t, func(config *betterauth.Config) {
		config.MinPasswordBytes = 8
	})
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

	t.Run("user update response difference", func(t *testing.T) {
		input := map[string]any{"name": updatedName}
		goResult := goResponse(goClient.request(t, http.MethodPost, "/update-user", input, true))
		tsResult := oracle.request(t, http.MethodPost, "/update-user", input, "")
		if goResult.status != http.StatusOK || tsResult.status != http.StatusOK {
			t.Fatalf("status mismatch: Go=%d %s TypeScript=%d %s",
				goResult.status, goResult.body, tsResult.status, tsResult.body)
		}
		if _, exists := decodeObject(t, goResult.body)["user"]; !exists {
			t.Fatalf("Go update-user response characterization changed: %s", goResult.body)
		}
		if decodeObject(t, tsResult.body)["status"] != true {
			t.Fatalf("TypeScript update-user response characterization changed: %s", tsResult.body)
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
	})

	t.Run("duplicate account known status difference", func(t *testing.T) {
		input := map[string]any{"email": email, "password": password, "name": name}
		goResult := goResponse(goClient.request(t, http.MethodPost, "/sign-up/email", input, false))
		tsResult := oracle.request(t, http.MethodPost, "/sign-up/email", input, "")
		if goResult.status != http.StatusConflict || tsResult.status != http.StatusUnprocessableEntity {
			t.Fatalf("documented status difference changed: Go=%d %s TypeScript=%d %s",
				goResult.status, goResult.body, tsResult.status, tsResult.body)
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
