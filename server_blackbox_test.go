package betterauth_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	betterauth "github.com/eadwinCode/better-auth-go"
	"github.com/eadwinCode/better-auth-go/adapter/memory"
)

type fixedClock struct{ now time.Time }

func (clock fixedClock) Now() time.Time { return clock.now }

type sequenceTokens struct {
	mu      sync.Mutex
	counter uint64
}

func (source *sequenceTokens) Token(byteLength int) (string, error) {
	source.mu.Lock()
	defer source.mu.Unlock()
	source.counter++
	return fmt.Sprintf("test-token-%03d-%0*d", source.counter, byteLength, source.counter), nil
}

type captureMailer struct {
	mu    sync.Mutex
	mails []betterauth.Mail
}

func (mailer *captureMailer) Send(_ context.Context, message betterauth.Mail) error {
	mailer.mu.Lock()
	defer mailer.mu.Unlock()
	mailer.mails = append(mailer.mails, message)
	return nil
}

func (mailer *captureMailer) last() betterauth.Mail {
	mailer.mu.Lock()
	defer mailer.mu.Unlock()
	return mailer.mails[len(mailer.mails)-1]
}

type allowImpersonation struct{}

func (allowImpersonation) CanImpersonate(context.Context, betterauth.User, betterauth.User) error {
	return nil
}

type testClient struct {
	handler  http.Handler
	database *memory.Adapter
	session  *http.Cookie
	csrf     *http.Cookie
}

func newBlackBoxServer(t *testing.T) (*testClient, *captureMailer) {
	t.Helper()
	mailer := &captureMailer{}
	params := betterauth.Argon2Params{
		Memory: 19 * 1024, Iterations: 2, Parallelism: 1, SaltLength: 16, KeyLength: 32,
	}
	passwords, err := betterauth.NewArgon2idVerifier(params, 1024)
	if err != nil {
		t.Fatal(err)
	}
	database := memory.New()
	server, err := betterauth.New(betterauth.Config{
		PublicURL: "https://auth.example.com", TrustedOrigins: []string{"https://app.example.com"},
		Database: database, Mailer: mailer, ImpersonationAuthorizer: allowImpersonation{},
		Clock:  fixedClock{now: time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)},
		Tokens: &sequenceTokens{}, Passwords: passwords,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &testClient{handler: server.Handler(), database: database}, mailer
}

func (client *testClient) request(t *testing.T, method, path string, body any, csrf bool) *httptest.ResponseRecorder {
	t.Helper()
	var payload []byte
	if body != nil {
		var err error
		payload, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	request := httptest.NewRequest(method, "https://auth.example.com/api/auth"+path, bytes.NewReader(payload))
	request.Header.Set("Origin", "https://app.example.com")
	request.Header.Set("Content-Type", "application/json")
	if client.session != nil {
		request.AddCookie(client.session)
	}
	if client.csrf != nil {
		request.AddCookie(client.csrf)
		if csrf {
			request.Header.Set("X-CSRF-Token", client.csrf.Value)
		}
	}
	recorder := httptest.NewRecorder()
	client.handler.ServeHTTP(recorder, request)
	for _, cookie := range recorder.Result().Cookies() {
		switch cookie.Name {
		case "__Host-better_auth_session":
			client.session = cookie
		case "__Host-better_auth_csrf":
			client.csrf = cookie
		}
	}
	return recorder
}

func TestEmailPasswordSessionLifecycle(t *testing.T) {
	t.Parallel()
	client, _ := newBlackBoxServer(t)
	signup := client.request(t, http.MethodPost, "/sign-up/email", map[string]any{
		"email": "User@Example.com", "password": "correct horse battery staple", "name": "Example User",
	}, false)
	if signup.Code != http.StatusOK {
		t.Fatalf("signup status %d: %s", signup.Code, signup.Body.String())
	}
	assertSecureSessionCookie(t, client.session)
	if client.csrf == nil || client.csrf.HttpOnly {
		t.Fatal("expected readable CSRF cookie")
	}
	session := client.request(t, http.MethodGet, "/get-session", nil, false)
	if session.Code != http.StatusOK || !bytes.Contains(session.Body.Bytes(), []byte(`"email":"user@example.com"`)) {
		t.Fatalf("session response %d: %s", session.Code, session.Body.String())
	}
	oldToken := client.session.Value
	refresh := client.request(t, http.MethodPost, "/refresh-session", map[string]any{}, true)
	if refresh.Code != http.StatusOK {
		t.Fatalf("refresh response %d: %s", refresh.Code, refresh.Body.String())
	}
	if client.session.Value == oldToken {
		t.Fatal("session token did not rotate")
	}
	signout := client.request(t, http.MethodPost, "/sign-out", map[string]any{}, true)
	if signout.Code != http.StatusOK {
		t.Fatalf("signout response %d: %s", signout.Code, signout.Body.String())
	}
}

func TestCSRFAndOriginEnforcement(t *testing.T) {
	t.Parallel()
	client, _ := newBlackBoxServer(t)
	signup := client.request(t, http.MethodPost, "/sign-up/email", map[string]any{
		"email": "csrf@example.com", "password": "correct horse battery staple", "name": "CSRF User",
	}, false)
	if signup.Code != http.StatusOK {
		t.Fatal(signup.Body.String())
	}
	withoutCSRF := client.request(t, http.MethodPost, "/sign-out", map[string]any{}, false)
	if withoutCSRF.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", withoutCSRF.Code)
	}
	request := httptest.NewRequest(http.MethodPost, "https://auth.example.com/api/auth/sign-in/email", bytes.NewBufferString(`{}`))
	request.Header.Set("Origin", "https://evil.example")
	recorder := httptest.NewRecorder()
	client.handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected untrusted origin rejection, got %d", recorder.Code)
	}
}

func TestPasswordResetIsSingleUse(t *testing.T) {
	t.Parallel()
	client, mailer := newBlackBoxServer(t)
	signup := client.request(t, http.MethodPost, "/sign-up/email", map[string]any{
		"email": "reset@example.com", "password": "correct horse battery staple", "name": "Reset User",
	}, false)
	if signup.Code != http.StatusOK {
		t.Fatal(signup.Body.String())
	}
	forgot := client.request(t, http.MethodPost, "/forget-password", map[string]any{"email": "reset@example.com"}, false)
	if forgot.Code != http.StatusOK {
		t.Fatal(forgot.Body.String())
	}
	token := mailer.last().Token
	reset := client.request(t, http.MethodPost, "/reset-password", map[string]any{
		"token": token, "newPassword": "new correct horse password",
	}, false)
	if reset.Code != http.StatusOK {
		t.Fatalf("reset response %d: %s", reset.Code, reset.Body.String())
	}
	replay := client.request(t, http.MethodPost, "/reset-password", map[string]any{
		"token": token, "newPassword": "another correct horse password",
	}, false)
	if replay.Code != http.StatusBadRequest {
		t.Fatalf("expected reset replay rejection, got %d: %s", replay.Code, replay.Body.String())
	}
}

func TestAuthenticationErrorsAreGeneric(t *testing.T) {
	t.Parallel()
	client, _ := newBlackBoxServer(t)
	missing := client.request(t, http.MethodPost, "/sign-in/email", map[string]any{
		"email": "missing@example.com", "password": "some password",
	}, false)
	if missing.Code != http.StatusUnauthorized {
		t.Fatalf("unexpected status: %d", missing.Code)
	}
	var response struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(missing.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Error.Code != string(betterauth.CodeInvalidCredentials) || response.Error.Message != "Invalid email or password." {
		t.Fatalf("unexpected error: %#v", response.Error)
	}
}

func TestSignInRotatesExistingBrowserSession(t *testing.T) {
	t.Parallel()
	client, _ := newBlackBoxServer(t)
	signup := client.request(t, http.MethodPost, "/sign-up/email", map[string]any{
		"email": "rotate@example.com", "password": "correct horse battery staple", "name": "Rotate User",
	}, false)
	if signup.Code != http.StatusOK {
		t.Fatal(signup.Body.String())
	}
	oldCookie := *client.session
	signin := client.request(t, http.MethodPost, "/sign-in/email", map[string]any{
		"email": "rotate@example.com", "password": "correct horse battery staple",
	}, false)
	if signin.Code != http.StatusOK {
		t.Fatalf("sign in status %d: %s", signin.Code, signin.Body.String())
	}
	if client.session.Value == oldCookie.Value {
		t.Fatal("sign in did not rotate the existing browser session")
	}
	stale := &testClient{handler: client.handler, database: client.database, session: &oldCookie}
	response := stale.request(t, http.MethodGet, "/get-session", nil, false)
	if response.Code != http.StatusOK || response.Body.String() != "null\n" {
		t.Fatalf("old session remained valid: %d %s", response.Code, response.Body.String())
	}
}

func TestImpersonationStartAndStopAreAudited(t *testing.T) {
	t.Parallel()
	actor, _ := newBlackBoxServer(t)
	target := &testClient{handler: actor.handler, database: actor.database}
	actorSignup := actor.request(t, http.MethodPost, "/sign-up/email", map[string]any{
		"email": "admin@example.com", "password": "correct horse battery staple", "name": "Admin",
	}, false)
	if actorSignup.Code != http.StatusOK {
		t.Fatal(actorSignup.Body.String())
	}
	targetSignup := target.request(t, http.MethodPost, "/sign-up/email", map[string]any{
		"email": "target@example.com", "password": "correct horse battery staple", "name": "Target",
	}, false)
	if targetSignup.Code != http.StatusOK {
		t.Fatal(targetSignup.Body.String())
	}
	var targetResponse struct {
		User betterauth.User `json:"user"`
	}
	if err := json.Unmarshal(targetSignup.Body.Bytes(), &targetResponse); err != nil {
		t.Fatal(err)
	}
	start := actor.request(t, http.MethodPost, "/admin/impersonate-user", map[string]any{
		"userId": targetResponse.User.ID,
	}, true)
	if start.Code != http.StatusOK {
		t.Fatalf("start impersonation status %d: %s", start.Code, start.Body.String())
	}
	stop := actor.request(t, http.MethodPost, "/admin/stop-impersonating", map[string]any{}, true)
	if stop.Code != http.StatusOK || !bytes.Contains(stop.Body.Bytes(), []byte(`"email":"admin@example.com"`)) {
		t.Fatalf("stop impersonation status %d: %s", stop.Code, stop.Body.String())
	}
	audits, err := actor.database.FindMany(context.Background(), betterauth.FindManyQuery{
		Model: betterauth.ModelAuditEvent,
		Sort:  &betterauth.Sort{Field: "occurredAt", Direction: "asc"},
	})
	if err != nil {
		t.Fatal(err)
	}
	actions := map[any]bool{}
	for _, audit := range audits {
		actions[audit["action"]] = true
	}
	if len(audits) != 2 ||
		!actions[betterauth.AuditImpersonationStart] ||
		!actions[betterauth.AuditImpersonationStop] {
		t.Fatalf("unexpected impersonation audit trail: %#v", audits)
	}
}

func assertSecureSessionCookie(t *testing.T, cookie *http.Cookie) {
	t.Helper()
	if cookie == nil {
		t.Fatal("missing session cookie")
	}
	if !cookie.Secure || !cookie.HttpOnly || cookie.Domain != "" || cookie.Path != "/" ||
		(cookie.SameSite != http.SameSiteLaxMode && cookie.SameSite != http.SameSiteStrictMode) {
		t.Fatalf("insecure session cookie: %#v", cookie)
	}
}

func FuzzSessionCookieParsing(f *testing.F) {
	f.Add("normal-token")
	f.Add("")
	f.Fuzz(func(t *testing.T, value string) {
		if len(value) > 4096 {
			t.Skip()
		}
		client, _ := newBlackBoxServer(t)
		client.session = &http.Cookie{Name: "__Host-better_auth_session", Value: value}
		response := client.request(t, http.MethodGet, "/get-session", nil, false)
		if response.Code != http.StatusOK {
			t.Fatalf("get-session should return null for invalid cookie, got %d", response.Code)
		}
	})
}
