package betterauth_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	betterauth "github.com/eadwinCode/better-auth-go"
	sqliteadapter "github.com/eadwinCode/better-auth-go/adapter/sqlite"
	_ "modernc.org/sqlite"
)

type publicErrorResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func decodePublicError(t *testing.T, responseBody []byte) publicErrorResponse {
	t.Helper()
	var response publicErrorResponse
	if err := json.Unmarshal(responseBody, &response); err != nil {
		t.Fatal(err)
	}
	return response
}

func TestEmailPasswordDefaultBoundsAndDuplicateContract(t *testing.T) {
	t.Parallel()
	client, _ := newBlackBoxServer(t)

	empty := client.request(t, http.MethodPost, "/sign-up/email", map[string]any{
		"email": "empty@example.com", "password": "", "name": "Empty",
	}, false)
	if empty.Code != http.StatusBadRequest {
		t.Fatalf("empty password status %d: %s", empty.Code, empty.Body.String())
	}
	if got := decodePublicError(t, empty.Body.Bytes()); got.Code != "VALIDATION_ERROR" ||
		got.Message != "[body.password] Too small: expected string to have >=1 characters" {
		t.Fatalf("unexpected empty-password error: %#v", got)
	}

	short := client.request(t, http.MethodPost, "/sign-up/email", map[string]any{
		"email": "short@example.com", "password": "1234567", "name": "Short",
	}, false)
	if short.Code != http.StatusBadRequest {
		t.Fatalf("short password status %d: %s", short.Code, short.Body.String())
	}
	if got := decodePublicError(t, short.Body.Bytes()); got.Code != "PASSWORD_TOO_SHORT" {
		t.Fatalf("unexpected short-password error: %#v", got)
	}

	long := client.request(t, http.MethodPost, "/sign-up/email", map[string]any{
		"email": "long@example.com", "password": string(make([]byte, 129)), "name": "Long",
	}, false)
	if long.Code != http.StatusBadRequest {
		t.Fatalf("long password status %d: %s", long.Code, long.Body.String())
	}
	if got := decodePublicError(t, long.Body.Bytes()); got.Code != "PASSWORD_TOO_LONG" {
		t.Fatalf("unexpected long-password error: %#v", got)
	}

	invalidEmail := client.request(t, http.MethodPost, "/sign-in/email", map[string]any{
		"email": "not-an-email", "password": "password",
	}, false)
	if invalidEmail.Code != http.StatusBadRequest {
		t.Fatalf("invalid email status %d: %s", invalidEmail.Code, invalidEmail.Body.String())
	}
	if got := decodePublicError(t, invalidEmail.Body.Bytes()); got.Code != "INVALID_EMAIL" ||
		got.Message != "Invalid email" {
		t.Fatalf("unexpected invalid-email error: %#v", got)
	}

	body := map[string]any{
		"email": "valid@example.com", "password": "12345678", "name": "Valid",
	}
	first := client.request(t, http.MethodPost, "/sign-up/email", body, false)
	if first.Code != http.StatusOK {
		t.Fatalf("valid password status %d: %s", first.Code, first.Body.String())
	}
	duplicate := (&testClient{handler: client.handler, database: client.database}).request(
		t,
		http.MethodPost,
		"/sign-up/email",
		body,
		false,
	)
	if duplicate.Code != http.StatusUnprocessableEntity {
		t.Fatalf("duplicate status %d: %s", duplicate.Code, duplicate.Body.String())
	}
	got := decodePublicError(t, duplicate.Body.Bytes())
	if got.Code != "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL" ||
		got.Message != "User already exists. Use another email." {
		t.Fatalf("unexpected duplicate error: %#v", got)
	}
}

func TestEmailPasswordSignUpCanBeDisabled(t *testing.T) {
	t.Parallel()
	client, _ := newBlackBoxServerConfig(t, func(config *betterauth.Config) {
		config.EmailPassword.DisableSignUp = true
	})
	response := client.request(t, http.MethodPost, "/sign-up/email", map[string]any{
		"email": "disabled@example.com", "password": "password", "name": "Disabled",
	}, false)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status %d: %s", response.Code, response.Body.String())
	}
	got := decodePublicError(t, response.Body.Bytes())
	if got.Code != "EMAIL_PASSWORD_SIGN_UP_DISABLED" ||
		got.Message != "Email and password sign up is not enabled" {
		t.Fatalf("unexpected error: %#v", got)
	}
}

func TestSignUpRememberMeFalseUsesShortSession(t *testing.T) {
	t.Parallel()
	client, _ := newBlackBoxServer(t)
	response := client.request(t, http.MethodPost, "/sign-up/email", map[string]any{
		"email": "short-session@example.com", "password": "password",
		"name": "Short session", "rememberMe": false,
	}, false)
	if response.Code != http.StatusOK {
		t.Fatalf("signup status %d: %s", response.Code, response.Body.String())
	}
	sessionResponse := client.request(t, http.MethodGet, "/get-session", nil, false)
	var body struct {
		Session betterauth.Session `json:"session"`
	}
	if err := json.Unmarshal(sessionResponse.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	want := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	if !body.Session.ExpiresAt.Equal(want) {
		t.Fatalf("rememberMe=false expiry = %s, want %s", body.Session.ExpiresAt, want)
	}
}

func TestAutoSignInFalseReturnsSyntheticDuplicateWithoutSession(t *testing.T) {
	t.Parallel()
	autoSignIn := false
	client, _ := newBlackBoxServerConfig(t, func(config *betterauth.Config) {
		config.EmailPassword.AutoSignIn = &autoSignIn
	})
	// New must copy pointer-backed configuration so caller mutation cannot race
	// with requests or change the server after construction.
	autoSignIn = true

	body := map[string]any{
		"email": "sessionless@example.com", "password": "password", "name": "Sessionless",
	}
	first := client.request(t, http.MethodPost, "/sign-up/email", body, false)
	if first.Code != http.StatusOK {
		t.Fatalf("first signup status %d: %s", first.Code, first.Body.String())
	}
	if client.session != nil || client.csrf != nil {
		t.Fatal("sessionless signup issued authentication cookies")
	}
	var firstBody struct {
		Token any             `json:"token"`
		User  betterauth.User `json:"user"`
	}
	if err := json.Unmarshal(first.Body.Bytes(), &firstBody); err != nil {
		t.Fatal(err)
	}
	if firstBody.Token != nil {
		t.Fatalf("sessionless signup returned token %#v", firstBody.Token)
	}

	duplicate := client.request(t, http.MethodPost, "/sign-up/email", body, false)
	if duplicate.Code != http.StatusOK {
		t.Fatalf("duplicate status %d: %s", duplicate.Code, duplicate.Body.String())
	}
	var duplicateBody struct {
		Token any             `json:"token"`
		User  betterauth.User `json:"user"`
	}
	if err := json.Unmarshal(duplicate.Body.Bytes(), &duplicateBody); err != nil {
		t.Fatal(err)
	}
	if duplicateBody.Token != nil || duplicateBody.User.Email != firstBody.User.Email ||
		duplicateBody.User.ID == firstBody.User.ID || duplicateBody.User.EmailVerified {
		t.Fatalf("unexpected synthetic response: %#v", duplicateBody)
	}
	users, err := client.database.Count(context.Background(), betterauth.CountQuery{
		Model: betterauth.ModelUser,
	})
	if err != nil {
		t.Fatal(err)
	}
	if users != 1 {
		t.Fatalf("duplicate signup created %d users", users)
	}
	session := client.request(t, http.MethodGet, "/get-session", nil, false)
	if session.Code != http.StatusOK || session.Body.String() != "null\n" {
		t.Fatalf("sessionless signup authenticated browser: %d %s", session.Code, session.Body.String())
	}
}

func TestRequiredEmailVerificationBlocksSessionUntilVerified(t *testing.T) {
	t.Parallel()
	client, mailer := newBlackBoxServerConfig(t, func(config *betterauth.Config) {
		config.EmailPassword.RequireEmailVerification = true
	})
	body := map[string]any{
		"email": "verify-required@example.com", "password": "password", "name": "Verify",
	}
	signup := client.request(t, http.MethodPost, "/sign-up/email", body, false)
	if signup.Code != http.StatusOK {
		t.Fatalf("signup status %d: %s", signup.Code, signup.Body.String())
	}
	if client.session != nil || client.csrf != nil {
		t.Fatal("unverified signup issued authentication cookies")
	}
	message := mailer.last()
	if message.Kind != "email-verification" || message.Token == "" {
		t.Fatalf("unexpected verification mail: %#v", message)
	}
	wantExpiry := time.Date(2026, 7, 28, 13, 0, 0, 0, time.UTC)
	if !message.ExpiresAt.Equal(wantExpiry) {
		t.Fatalf("verification expiry = %s, want %s", message.ExpiresAt, wantExpiry)
	}

	wrong := client.request(t, http.MethodPost, "/sign-in/email", map[string]any{
		"email": "verify-required@example.com", "password": "incorrect",
	}, false)
	if wrong.Code != http.StatusUnauthorized ||
		decodePublicError(t, wrong.Body.Bytes()).Code != "INVALID_EMAIL_OR_PASSWORD" {
		t.Fatalf("wrong password leaked verification state: %d %s", wrong.Code, wrong.Body.String())
	}
	blocked := client.request(t, http.MethodPost, "/sign-in/email", map[string]any{
		"email": "verify-required@example.com", "password": "password",
	}, false)
	if blocked.Code != http.StatusForbidden {
		t.Fatalf("unverified signin status %d: %s", blocked.Code, blocked.Body.String())
	}
	blockedError := decodePublicError(t, blocked.Body.Bytes())
	if blockedError.Code != "EMAIL_NOT_VERIFIED" || blockedError.Message != "Email not verified" {
		t.Fatalf("unexpected verification error: %#v", blockedError)
	}

	verified := client.request(
		t,
		http.MethodGet,
		"/verify-email?token="+message.Token,
		nil,
		false,
	)
	if verified.Code != http.StatusOK {
		t.Fatalf("verification status %d: %s", verified.Code, verified.Body.String())
	}
	duplicate := client.request(t, http.MethodPost, "/sign-up/email", body, false)
	if duplicate.Code != http.StatusOK {
		t.Fatalf("protected duplicate status %d: %s", duplicate.Code, duplicate.Body.String())
	}
	var duplicateBody struct {
		User betterauth.User `json:"user"`
	}
	if err := json.Unmarshal(duplicate.Body.Bytes(), &duplicateBody); err != nil {
		t.Fatal(err)
	}
	if client.session != nil || duplicateBody.User.EmailVerified {
		t.Fatal("protected duplicate exposed verified state or issued a session")
	}
	mailer.mu.Lock()
	mailCount := len(mailer.mails)
	mailer.mu.Unlock()
	if mailCount != 1 {
		t.Fatalf("protected duplicate sent %d verification messages", mailCount)
	}
	signin := client.request(t, http.MethodPost, "/sign-in/email", map[string]any{
		"email": "verify-required@example.com", "password": "password",
	}, false)
	if signin.Code != http.StatusOK || client.session == nil {
		t.Fatalf("verified signin status %d: %s", signin.Code, signin.Body.String())
	}
}

func TestPasswordResetPreservesSessionsByDefaultAndDoesNotSignIn(t *testing.T) {
	t.Parallel()
	first, mailer := newBlackBoxServer(t)
	second := &testClient{handler: first.handler, database: first.database}
	resetBrowser := &testClient{handler: first.handler, database: first.database}

	signup := first.request(t, http.MethodPost, "/sign-up/email", map[string]any{
		"email": "preserve@example.com", "password": "old-password", "name": "Preserve",
	}, false)
	if signup.Code != http.StatusOK {
		t.Fatal(signup.Body.String())
	}
	signin := second.request(t, http.MethodPost, "/sign-in/email", map[string]any{
		"email": "preserve@example.com", "password": "old-password",
	}, false)
	if signin.Code != http.StatusOK {
		t.Fatal(signin.Body.String())
	}
	forgot := resetBrowser.request(t, http.MethodPost, "/forget-password", map[string]any{
		"email": "preserve@example.com",
	}, false)
	if forgot.Code != http.StatusOK {
		t.Fatal(forgot.Body.String())
	}
	if want := time.Date(2026, 7, 28, 13, 0, 0, 0, time.UTC); !mailer.last().ExpiresAt.Equal(want) {
		t.Fatalf("reset expiry = %s, want %s", mailer.last().ExpiresAt, want)
	}
	reset := resetBrowser.request(t, http.MethodPost, "/reset-password", map[string]any{
		"token": mailer.last().Token, "newPassword": "new-password",
	}, false)
	if reset.Code != http.StatusOK || reset.Body.String() != "{\"status\":true}\n" {
		t.Fatalf("reset status %d: %s", reset.Code, reset.Body.String())
	}
	if resetBrowser.session != nil || resetBrowser.csrf != nil {
		t.Fatal("password reset signed in the reset browser")
	}
	assertSessionPresent(t, first)
	assertSessionPresent(t, second)

	oldPassword := (&testClient{handler: first.handler, database: first.database}).request(
		t,
		http.MethodPost,
		"/sign-in/email",
		map[string]any{"email": "preserve@example.com", "password": "old-password"},
		false,
	)
	if oldPassword.Code != http.StatusUnauthorized {
		t.Fatalf("old password remained valid: %d %s", oldPassword.Code, oldPassword.Body.String())
	}
	newPassword := (&testClient{handler: first.handler, database: first.database}).request(
		t,
		http.MethodPost,
		"/sign-in/email",
		map[string]any{"email": "preserve@example.com", "password": "new-password"},
		false,
	)
	if newPassword.Code != http.StatusOK {
		t.Fatalf("new password rejected: %d %s", newPassword.Code, newPassword.Body.String())
	}
}

func TestPasswordResetCanRevokeEverySession(t *testing.T) {
	t.Parallel()
	first, mailer := newBlackBoxServerConfig(t, func(config *betterauth.Config) {
		config.EmailPassword.RevokeSessionsOnPasswordReset = true
	})
	second := &testClient{handler: first.handler, database: first.database}
	resetBrowser := &testClient{handler: first.handler, database: first.database}

	if response := first.request(t, http.MethodPost, "/sign-up/email", map[string]any{
		"email": "revoke@example.com", "password": "old-password", "name": "Revoke",
	}, false); response.Code != http.StatusOK {
		t.Fatal(response.Body.String())
	}
	if response := second.request(t, http.MethodPost, "/sign-in/email", map[string]any{
		"email": "revoke@example.com", "password": "old-password",
	}, false); response.Code != http.StatusOK {
		t.Fatal(response.Body.String())
	}
	resetBrowser.request(t, http.MethodPost, "/forget-password", map[string]any{
		"email": "revoke@example.com",
	}, false)
	reset := resetBrowser.request(t, http.MethodPost, "/reset-password", map[string]any{
		"token": mailer.last().Token, "newPassword": "new-password",
	}, false)
	if reset.Code != http.StatusOK {
		t.Fatalf("reset status %d: %s", reset.Code, reset.Body.String())
	}
	assertSessionAbsent(t, first)
	assertSessionAbsent(t, second)
	if resetBrowser.session != nil {
		t.Fatal("reset browser received a replacement session")
	}
}

func TestPasswordResetCreatesMissingCredentialAccount(t *testing.T) {
	t.Parallel()
	client, mailer := newBlackBoxServer(t)
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	if _, err := client.database.Create(context.Background(), betterauth.CreateQuery{
		Model: betterauth.ModelUser,
		Data: betterauth.Record{
			"id": "oauth-only-user", "email": "oauth-only@example.com", "name": "OAuth only",
			"image": nil, "emailVerified": true, "createdAt": now, "updatedAt": now,
		},
		ForceAllowID: true,
	}); err != nil {
		t.Fatal(err)
	}
	client.request(t, http.MethodPost, "/forget-password", map[string]any{
		"email": "oauth-only@example.com",
	}, false)
	reset := client.request(t, http.MethodPost, "/reset-password", map[string]any{
		"token": mailer.last().Token, "newPassword": "new-password",
	}, false)
	if reset.Code != http.StatusOK {
		t.Fatalf("reset status %d: %s", reset.Code, reset.Body.String())
	}
	signin := client.request(t, http.MethodPost, "/sign-in/email", map[string]any{
		"email": "oauth-only@example.com", "password": "new-password",
	}, false)
	if signin.Code != http.StatusOK {
		t.Fatalf("new credential signin status %d: %s", signin.Code, signin.Body.String())
	}
}

type countingPasswordVerifier struct {
	delegate betterauth.PasswordVerifier
	mu       sync.Mutex
	hashes   int
}

func (verifier *countingPasswordVerifier) Hash(ctx context.Context, password string) (string, error) {
	verifier.mu.Lock()
	verifier.hashes++
	verifier.mu.Unlock()
	return verifier.delegate.Hash(ctx, password)
}

func (verifier *countingPasswordVerifier) Verify(
	ctx context.Context,
	hash string,
	password string,
) (betterauth.PasswordVerification, error) {
	return verifier.delegate.Verify(ctx, hash, password)
}

func (verifier *countingPasswordVerifier) hashCount() int {
	verifier.mu.Lock()
	defer verifier.mu.Unlock()
	return verifier.hashes
}

func TestMissingUserSignInAndProtectedDuplicatePerformHashWork(t *testing.T) {
	t.Parallel()
	counter := &countingPasswordVerifier{}
	autoSignIn := false
	client, _ := newBlackBoxServerConfig(t, func(config *betterauth.Config) {
		counter.delegate = config.Passwords
		config.Passwords = counter
		config.EmailPassword.AutoSignIn = &autoSignIn
	})
	missing := client.request(t, http.MethodPost, "/sign-in/email", map[string]any{
		"email": "missing@example.com", "password": "password",
	}, false)
	if missing.Code != http.StatusUnauthorized || counter.hashCount() != 1 {
		t.Fatalf("missing-user path did not perform hash work: %d hashes=%d", missing.Code, counter.hashCount())
	}
	body := map[string]any{
		"email": "duplicate-hash@example.com", "password": "password", "name": "Hash",
	}
	if response := client.request(t, http.MethodPost, "/sign-up/email", body, false); response.Code != http.StatusOK {
		t.Fatal(response.Body.String())
	}
	beforeDuplicate := counter.hashCount()
	if response := client.request(t, http.MethodPost, "/sign-up/email", body, false); response.Code != http.StatusOK {
		t.Fatal(response.Body.String())
	}
	if counter.hashCount() != beforeDuplicate+1 {
		t.Fatalf("protected duplicate did not perform one hash: before=%d after=%d", beforeDuplicate, counter.hashCount())
	}
}

func TestProtectedDuplicateSignUpIsConcurrencySafe(t *testing.T) {
	t.Parallel()
	autoSignIn := false
	client, _ := newBlackBoxServerConfig(t, func(config *betterauth.Config) {
		config.EmailPassword.AutoSignIn = &autoSignIn
	})
	payload := []byte(`{"email":"concurrent@example.com","password":"password","name":"Concurrent"}`)
	const attempts = 8
	statuses := make(chan int, attempts)
	var wait sync.WaitGroup
	for range attempts {
		wait.Add(1)
		go func() {
			defer wait.Done()
			statuses <- rawJSONRequest(client.handler, http.MethodPost, "/sign-up/email", payload).Code
		}()
	}
	wait.Wait()
	close(statuses)
	for status := range statuses {
		if status != http.StatusOK {
			t.Fatalf("protected concurrent signup returned %d", status)
		}
	}
	users, err := client.database.Count(context.Background(), betterauth.CountQuery{
		Model: betterauth.ModelUser,
	})
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := client.database.Count(context.Background(), betterauth.CountQuery{
		Model: betterauth.ModelSession,
	})
	if err != nil {
		t.Fatal(err)
	}
	if users != 1 || sessions != 0 {
		t.Fatalf("concurrent signup persisted users=%d sessions=%d", users, sessions)
	}
}

func TestPasswordResetTokenHasOneConcurrentWinner(t *testing.T) {
	t.Parallel()
	client, mailer := newBlackBoxServer(t)
	if response := client.request(t, http.MethodPost, "/sign-up/email", map[string]any{
		"email": "reset-race@example.com", "password": "old-password", "name": "Reset race",
	}, false); response.Code != http.StatusOK {
		t.Fatal(response.Body.String())
	}
	client.request(t, http.MethodPost, "/forget-password", map[string]any{
		"email": "reset-race@example.com",
	}, false)
	payload, err := json.Marshal(map[string]any{
		"token": mailer.last().Token, "newPassword": "new-password",
	})
	if err != nil {
		t.Fatal(err)
	}

	const attempts = 8
	statuses := make(chan int, attempts)
	var wait sync.WaitGroup
	for range attempts {
		wait.Add(1)
		go func() {
			defer wait.Done()
			statuses <- rawJSONRequest(client.handler, http.MethodPost, "/reset-password", payload).Code
		}()
	}
	wait.Wait()
	close(statuses)
	var successes int
	for status := range statuses {
		switch status {
		case http.StatusOK:
			successes++
		case http.StatusBadRequest:
		default:
			t.Fatalf("concurrent reset returned %d", status)
		}
	}
	if successes != 1 {
		t.Fatalf("expected one reset winner, got %d", successes)
	}
}

func TestEmailPasswordResetTransactionOnSQLite(t *testing.T) {
	t.Parallel()
	database, err := sql.Open(
		"sqlite",
		"file:"+filepath.Join(t.TempDir(), "auth.db")+
			"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)",
	)
	if err != nil {
		t.Fatal(err)
	}
	database.SetMaxOpenConns(8)
	t.Cleanup(func() { _ = database.Close() })
	adapter, err := sqliteadapter.New(database)
	if err != nil {
		t.Fatal(err)
	}
	mailer := &captureMailer{}
	passwords, err := betterauth.NewArgon2idVerifier(betterauth.Argon2Params{
		Memory: 19 * 1024, Iterations: 2, Parallelism: 1, SaltLength: 16, KeyLength: 32,
	}, 128)
	if err != nil {
		t.Fatal(err)
	}
	server, err := betterauth.New(betterauth.Config{
		PublicURL: "https://auth.example.com", TrustedOrigins: []string{"https://app.example.com"},
		Database: adapter, Mailer: mailer, ImpersonationAuthorizer: allowImpersonation{},
		Clock:  fixedClock{now: time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)},
		Tokens: &sequenceTokens{}, Passwords: passwords,
		EmailPassword: betterauth.EmailPasswordConfig{
			RevokeSessionsOnPasswordReset: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := adapter.Migrate(t.Context(), server.Schema()); err != nil {
		t.Fatal(err)
	}
	first := &testClient{handler: server.Handler()}
	second := &testClient{handler: server.Handler()}
	resetBrowser := &testClient{handler: server.Handler()}
	if response := first.request(t, http.MethodPost, "/sign-up/email", map[string]any{
		"email": "sqlite-reset@example.com", "password": "old-password", "name": "SQLite",
	}, false); response.Code != http.StatusOK {
		t.Fatalf("signup status %d: %s", response.Code, response.Body.String())
	}
	if response := second.request(t, http.MethodPost, "/sign-in/email", map[string]any{
		"email": "sqlite-reset@example.com", "password": "old-password",
	}, false); response.Code != http.StatusOK {
		t.Fatalf("signin status %d: %s", response.Code, response.Body.String())
	}
	resetBrowser.request(t, http.MethodPost, "/forget-password", map[string]any{
		"email": "sqlite-reset@example.com",
	}, false)
	reset := resetBrowser.request(t, http.MethodPost, "/reset-password", map[string]any{
		"token": mailer.last().Token, "newPassword": "new-password",
	}, false)
	if reset.Code != http.StatusOK {
		t.Fatalf("reset status %d: %s", reset.Code, reset.Body.String())
	}
	assertSessionAbsent(t, first)
	assertSessionAbsent(t, second)
	fresh := (&testClient{handler: server.Handler()}).request(
		t,
		http.MethodPost,
		"/sign-in/email",
		map[string]any{"email": "sqlite-reset@example.com", "password": "new-password"},
		false,
	)
	if fresh.Code != http.StatusOK {
		t.Fatalf("new password signin status %d: %s", fresh.Code, fresh.Body.String())
	}
}

func rawJSONRequest(handler http.Handler, method, route string, payload []byte) *httptest.ResponseRecorder {
	request := httptest.NewRequest(
		method,
		"https://auth.example.com/api/auth"+route,
		bytes.NewReader(payload),
	)
	request.Header.Set("Origin", "https://app.example.com")
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func assertSessionPresent(t *testing.T, client *testClient) {
	t.Helper()
	response := client.request(t, http.MethodGet, "/get-session", nil, false)
	if response.Code != http.StatusOK || response.Body.String() == "null\n" {
		t.Fatalf("expected active session: %d %s", response.Code, response.Body.String())
	}
}

func assertSessionAbsent(t *testing.T, client *testClient) {
	t.Helper()
	response := client.request(t, http.MethodGet, "/get-session", nil, false)
	if response.Code != http.StatusOK || response.Body.String() != "null\n" {
		t.Fatalf("expected revoked session: %d %s", response.Code, response.Body.String())
	}
}
