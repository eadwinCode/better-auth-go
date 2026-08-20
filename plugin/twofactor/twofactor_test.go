package twofactor

import (
	"bytes"
	"context"
	"encoding/base32"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	betterauth "github.com/eadwinCode/better-auth-go"
	"github.com/eadwinCode/better-auth-go/adapter/memory"
)

type fixedClock struct {
	now time.Time
}

func (clock fixedClock) Now() time.Time { return clock.now }

type discardMailer struct{}

func (discardMailer) Send(context.Context, betterauth.Mail) error { return nil }

type denyImpersonation struct{}

func (denyImpersonation) CanImpersonate(
	context.Context,
	betterauth.User,
	betterauth.User,
) error {
	return betterauth.ErrNotFound
}

type testBrowser struct {
	handler http.Handler
	cookies map[string]*http.Cookie
}

func newTestBrowser(handler http.Handler) *testBrowser {
	return &testBrowser{handler: handler, cookies: make(map[string]*http.Cookie)}
}

func (browser *testBrowser) request(
	t *testing.T,
	method string,
	path string,
	body map[string]any,
	csrf bool,
) *httptest.ResponseRecorder {
	t.Helper()
	var encoded []byte
	var err error
	if body != nil {
		encoded, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	request := httptest.NewRequest(
		method, "https://auth.example.com/api/auth"+path, bytes.NewReader(encoded),
	)
	request.Header.Set("Origin", "https://app.example.com")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	for _, cookie := range browser.cookies {
		request.AddCookie(cookie)
	}
	if csrf {
		if cookie := browser.cookies["__Host-better_auth_csrf"]; cookie != nil {
			request.Header.Set("X-CSRF-Token", cookie.Value)
		}
	}
	response := httptest.NewRecorder()
	browser.handler.ServeHTTP(response, request)
	for _, cookie := range response.Result().Cookies() {
		if cookie.MaxAge < 0 || cookie.Value == "" {
			delete(browser.cookies, cookie.Name)
			continue
		}
		copy := *cookie
		browser.cookies[cookie.Name] = &copy
	}
	return response
}

func decodeBody(t *testing.T, response *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response %d %q: %v", response.Code, response.Body.String(), err)
	}
	return body
}

func newTwoFactorTestServer(
	t *testing.T,
	configure func(*Config),
) (http.Handler, *memory.Adapter, fixedClock, *Manager, *string) {
	t.Helper()
	database := memory.New()
	clock := fixedClock{now: time.Date(2026, 7, 28, 9, 0, 0, 0, time.UTC)}
	cipher, err := betterauth.NewAESGCMTokenCipher(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	var delivered string
	config := Config{
		Issuer: "Example App", Cipher: cipher,
		DeliverOTP: func(
			_ *betterauth.HookContext,
			_ betterauth.User,
			code string,
		) error {
			delivered = code
			return nil
		},
	}
	if configure != nil {
		configure(&config)
	}
	manager, err := NewManager(config)
	if err != nil {
		t.Fatal(err)
	}
	server, err := betterauth.New(betterauth.Config{
		PublicURL: "https://auth.example.com",
		TrustedOrigins: []string{
			"https://app.example.com",
		},
		Database: database, Clock: clock, Mailer: discardMailer{},
		ImpersonationAuthorizer: denyImpersonation{},
		Plugins:                 []betterauth.Plugin{manager.Plugin()},
	})
	if err != nil {
		t.Fatal(err)
	}
	return server.Handler(), database, clock, manager, &delivered
}

func signUp(t *testing.T, browser *testBrowser) {
	t.Helper()
	response := browser.request(t, http.MethodPost, "/sign-up/email", map[string]any{
		"email": "owner@example.com", "name": "Owner",
		"password": "correct horse battery staple",
	}, false)
	if response.Code != http.StatusOK {
		t.Fatalf("sign up: %d %s", response.Code, response.Body.String())
	}
}

func signOut(t *testing.T, browser *testBrowser) {
	t.Helper()
	response := browser.request(t, http.MethodPost, "/sign-out", map[string]any{}, true)
	if response.Code != http.StatusOK {
		t.Fatalf("sign out: %d %s", response.Code, response.Body.String())
	}
}

func signInChallenge(t *testing.T, browser *testBrowser) map[string]any {
	t.Helper()
	response := browser.request(t, http.MethodPost, "/sign-in/email", map[string]any{
		"email": "owner@example.com", "password": "correct horse battery staple",
	}, false)
	if response.Code != http.StatusOK {
		t.Fatalf("sign in: %d %s", response.Code, response.Body.String())
	}
	body := decodeBody(t, response)
	if body["twoFactorRedirect"] != true {
		t.Fatalf("missing two-factor redirect: %#v", body)
	}
	if browser.cookies[defaultPendingCookie] == nil {
		t.Fatal("pending-login cookie was not set")
	}
	if browser.cookies["__Host-better_auth_session"] != nil {
		t.Fatal("provisional first-factor session escaped")
	}
	return body
}

func enrollTOTP(
	t *testing.T,
	browser *testBrowser,
	clock fixedClock,
) (string, []string) {
	t.Helper()
	response := browser.request(t, http.MethodPost, "/two-factor/enable", map[string]any{
		"password": "correct horse battery staple",
	}, true)
	if response.Code != http.StatusOK {
		t.Fatalf("enable: %d %s", response.Code, response.Body.String())
	}
	body := decodeBody(t, response)
	if body["method"] != "totp" {
		t.Fatalf("unexpected enable method: %#v", body)
	}
	uri, err := url.Parse(body["totpURI"].(string))
	if err != nil {
		t.Fatal(err)
	}
	secret := uri.Query().Get("secret")
	rawCodes, _ := body["backupCodes"].([]any)
	codes := make([]string, len(rawCodes))
	for index := range rawCodes {
		codes[index], _ = rawCodes[index].(string)
	}
	code, err := totpCode(secret, clock.Now(), 30*time.Second, 6)
	if err != nil {
		t.Fatal(err)
	}
	verified := browser.request(t, http.MethodPost, "/two-factor/verify-totp", map[string]any{
		"code": code,
	}, true)
	if verified.Code != http.StatusOK {
		t.Fatalf("verify enrollment: %d %s", verified.Code, verified.Body.String())
	}
	return secret, codes
}

func TestTwoFactorOTPEnablementIsDiscriminatedAndDoesNotCreateTOTPState(t *testing.T) {
	handler, database, _, _, _ := newTwoFactorTestServer(t, nil)
	browser := newTestBrowser(handler)
	signUp(t, browser)

	response := browser.request(t, http.MethodPost, "/two-factor/enable", map[string]any{
		"password": "correct horse battery staple", "method": "otp",
	}, true)
	if response.Code != http.StatusOK {
		t.Fatalf("enable OTP: %d %s", response.Code, response.Body.String())
	}
	body := decodeBody(t, response)
	if len(body) != 1 || body["method"] != "otp" {
		t.Fatalf("OTP enable response is not discriminated: %#v", body)
	}
	row, err := database.FindOne(context.Background(), betterauth.FindOneQuery{
		Model: ModelTwoFactor,
		Where: []betterauth.Where{betterauth.Eq("userId", firstUserID(t, database))},
	})
	if err != nil || row != nil {
		t.Fatalf("OTP enrollment created TOTP state: %#v %v", row, err)
	}

	signOut(t, browser)
	methods := signInChallenge(t, browser)["twoFactorMethods"].([]any)
	if len(methods) != 1 || methods[0] != "otp" {
		t.Fatalf("unexpected OTP-only challenge: %#v", methods)
	}
}

func TestTwoFactorTOTPOTPBackupAndTrustedDeviceFlow(t *testing.T) {
	handler, database, clock, manager, delivered := newTwoFactorTestServer(t, nil)
	browser := newTestBrowser(handler)
	signUp(t, browser)
	secret, backupCodes := enrollTOTP(t, browser, clock)
	sessionResponse := browser.request(t, http.MethodGet, "/get-session", nil, false)
	sessionBody := decodeBody(t, sessionResponse)
	sessionUser, _ := sessionBody["user"].(map[string]any)
	if sessionUser["twoFactorEnabled"] != true {
		t.Fatalf("session response omitted twoFactorEnabled: %#v", sessionBody)
	}

	row, err := database.FindOne(context.Background(), betterauth.FindOneQuery{
		Model: ModelTwoFactor,
		Where: []betterauth.Where{betterauth.Eq("userId", firstUserID(t, database))},
	})
	if err != nil || row == nil {
		t.Fatalf("stored configuration: %#v %v", row, err)
	}
	if strings.Contains(recordString(row["secret"]), secret) ||
		strings.Contains(recordString(row["backupCodes"]), backupCodes[0]) {
		t.Fatal("TOTP secret or backup code was stored in plaintext")
	}
	viewed, err := manager.ViewBackupCodes(
		context.Background(), database, firstUserID(t, database),
	)
	if err != nil || len(viewed) != 10 || viewed[0] != backupCodes[0] {
		t.Fatalf("server-only backup-code view: %#v %v", viewed, err)
	}

	signOut(t, browser)
	methods := signInChallenge(t, browser)["twoFactorMethods"].([]any)
	if len(methods) != 2 || methods[0] != "totp" || methods[1] != "otp" {
		t.Fatalf("unexpected methods: %#v", methods)
	}
	code, _ := totpCode(secret, clock.Now(), 30*time.Second, 6)
	verified := browser.request(t, http.MethodPost, "/two-factor/verify-totp", map[string]any{
		"code": code, "trustDevice": true,
	}, false)
	if verified.Code != http.StatusOK {
		t.Fatalf("TOTP sign-in: %d %s", verified.Code, verified.Body.String())
	}
	if browser.cookies[defaultTrustedCookie] == nil ||
		browser.cookies["__Host-better_auth_session"] == nil {
		t.Fatal("verified session or trusted-device cookie missing")
	}
	replay := browser.request(t, http.MethodPost, "/two-factor/verify-totp", map[string]any{
		"code": code,
	}, false)
	if replay.Code != http.StatusForbidden && replay.Code != http.StatusUnauthorized {
		t.Fatalf("pending challenge replay succeeded: %d %s", replay.Code, replay.Body.String())
	}

	oldTrusted := browser.cookies[defaultTrustedCookie].Value
	signOut(t, browser)
	direct := browser.request(t, http.MethodPost, "/sign-in/email", map[string]any{
		"email": "owner@example.com", "password": "correct horse battery staple",
	}, false)
	if direct.Code != http.StatusOK ||
		decodeBody(t, direct)["twoFactorRedirect"] == true {
		t.Fatalf("trusted-device sign-in was challenged: %d %s", direct.Code, direct.Body.String())
	}
	directUser, _ := decodeBody(t, direct)["user"].(map[string]any)
	if directUser["twoFactorEnabled"] != true {
		t.Fatalf("trusted sign-in omitted twoFactorEnabled: %#v", directUser)
	}
	if browser.cookies[defaultTrustedCookie].Value == oldTrusted {
		t.Fatal("trusted-device token was not rotated")
	}

	signOut(t, browser)
	delete(browser.cookies, defaultTrustedCookie)
	signInChallenge(t, browser)
	send := browser.request(t, http.MethodPost, "/two-factor/send-otp", map[string]any{}, false)
	if send.Code != http.StatusOK || *delivered == "" {
		t.Fatalf("send OTP: %d %s code=%q", send.Code, send.Body.String(), *delivered)
	}
	otp := browser.request(t, http.MethodPost, "/two-factor/verify-otp", map[string]any{
		"code": *delivered,
	}, false)
	if otp.Code != http.StatusOK {
		t.Fatalf("verify OTP: %d %s", otp.Code, otp.Body.String())
	}

	signOut(t, browser)
	signInChallenge(t, browser)
	backup := browser.request(
		t, http.MethodPost, "/two-factor/verify-backup-code",
		map[string]any{"code": backupCodes[0]}, false,
	)
	if backup.Code != http.StatusOK {
		t.Fatalf("verify backup code: %d %s", backup.Code, backup.Body.String())
	}
	signOut(t, browser)
	signInChallenge(t, browser)
	reused := browser.request(
		t, http.MethodPost, "/two-factor/verify-backup-code",
		map[string]any{"code": backupCodes[0]}, false,
	)
	if reused.Code != http.StatusUnauthorized {
		t.Fatalf("backup code replay succeeded: %d %s", reused.Code, reused.Body.String())
	}
}

func TestTwoFactorSecurityFailuresAndAttemptSerialization(t *testing.T) {
	handler, database, clock, _, _ := newTwoFactorTestServer(t, func(config *Config) {
		config.ChallengeMaxAttempts = 2
		config.AccountMaxFailedAttempts = 2
	})
	browser := newTestBrowser(handler)
	signUp(t, browser)
	secret, _ := enrollTOTP(t, browser, clock)

	stale := browser.request(t, http.MethodPost, "/two-factor/disable", map[string]any{
		"password": "correct horse battery staple",
	}, false)
	if stale.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF accepted: %d %s", stale.Code, stale.Body.String())
	}
	wrongOrigin := httptest.NewRequest(
		http.MethodPost, "https://auth.example.com/api/auth/two-factor/disable",
		bytes.NewBufferString(`{"password":"correct horse battery staple"}`),
	)
	wrongOrigin.Header.Set("Origin", "https://evil.example")
	for _, cookie := range browser.cookies {
		wrongOrigin.AddCookie(cookie)
	}
	wrongOrigin.Header.Set("Content-Type", "application/json")
	wrongOrigin.Header.Set(
		"X-CSRF-Token", browser.cookies["__Host-better_auth_csrf"].Value,
	)
	blocked := httptest.NewRecorder()
	handler.ServeHTTP(blocked, wrongOrigin)
	if blocked.Code != http.StatusForbidden {
		t.Fatalf("untrusted origin accepted: %d %s", blocked.Code, blocked.Body.String())
	}

	signOut(t, browser)
	signInChallenge(t, browser)
	var wait sync.WaitGroup
	codes := []string{"000000", "111111"}
	statuses := make(chan int, len(codes))
	for _, value := range codes {
		wait.Add(1)
		go func(candidate string) {
			defer wait.Done()
			clone := &testBrowser{handler: handler, cookies: make(map[string]*http.Cookie)}
			for name, cookie := range browser.cookies {
				copy := *cookie
				clone.cookies[name] = &copy
			}
			statuses <- clone.request(
				t, http.MethodPost, "/two-factor/verify-totp",
				map[string]any{"code": candidate}, false,
			).Code
		}(value)
	}
	wait.Wait()
	close(statuses)
	var unauthorized, limited int
	for status := range statuses {
		switch status {
		case http.StatusUnauthorized:
			unauthorized++
		case http.StatusTooManyRequests:
			limited++
		}
	}
	if unauthorized+limited != 2 || unauthorized < 1 {
		t.Fatalf("attempt race was not serialized: unauthorized=%d limited=%d", unauthorized, limited)
	}

	userID := firstUserID(t, database)
	record, err := database.FindOne(context.Background(), betterauth.FindOneQuery{
		Model: ModelTwoFactor,
		Where: []betterauth.Where{betterauth.Eq("userId", userID)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if record["lockedUntil"] == nil && limited == 1 {
		_ = browser.request(t, http.MethodPost, "/two-factor/verify-totp", map[string]any{
			"code": "222222",
		}, false)
		record, err = database.FindOne(context.Background(), betterauth.FindOneQuery{
			Model: ModelTwoFactor,
			Where: []betterauth.Where{betterauth.Eq("userId", userID)},
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if record["lockedUntil"] == nil {
		t.Fatal("account lockout was not persisted")
	}
	valid, _ := totpCode(secret, clock.Now(), 30*time.Second, 6)
	locked := browser.request(t, http.MethodPost, "/two-factor/verify-totp", map[string]any{
		"code": valid,
	}, false)
	if locked.Code != http.StatusUnauthorized && locked.Code != http.StatusTooManyRequests {
		t.Fatalf("spent challenge/locked account accepted: %d %s", locked.Code, locked.Body.String())
	}
}

func TestConcurrentBackupCodeHasOneWinner(t *testing.T) {
	handler, _, clock, _, _ := newTwoFactorTestServer(t, nil)
	browser := newTestBrowser(handler)
	signUp(t, browser)
	_, backupCodes := enrollTOTP(t, browser, clock)
	signOut(t, browser)
	signInChallenge(t, browser)

	const requests = 2
	statuses := make(chan int, requests)
	var wait sync.WaitGroup
	for range requests {
		wait.Add(1)
		go func() {
			defer wait.Done()
			clone := &testBrowser{handler: handler, cookies: make(map[string]*http.Cookie)}
			for name, cookie := range browser.cookies {
				copy := *cookie
				clone.cookies[name] = &copy
			}
			response := clone.request(
				t, http.MethodPost, "/two-factor/verify-backup-code",
				map[string]any{"code": backupCodes[0]}, false,
			)
			statuses <- response.Code
		}()
	}
	wait.Wait()
	close(statuses)
	successes := 0
	for status := range statuses {
		if status == http.StatusOK {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent backup code had %d winners, want 1", successes)
	}
}

func TestTwoFactorConfigurationAndTOTPVector(t *testing.T) {
	cipher, err := betterauth.NewAESGCMTokenCipher(bytes.Repeat([]byte{3}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(Config{Issuer: "Example"}); err == nil {
		t.Fatal("missing cipher accepted")
	}
	if _, err := New(Config{
		Issuer: "Example", Cipher: cipher, DisableTOTP: true,
	}); err == nil {
		t.Fatal("configuration without a factor accepted")
	}
	secret := base32Secret("12345678901234567890")
	code, err := totpCode(
		secret, time.Unix(59, 0), 30*time.Second, 8,
	)
	if err != nil || code != "94287082" {
		t.Fatalf("RFC 6238 vector: code=%q err=%v", code, err)
	}
	if !verifyTOTP(secret, "94287082", time.Unix(59, 0), 30*time.Second, 8) {
		t.Fatal("RFC 6238 vector did not verify")
	}
}

func base32Secret(value string) string {
	return strings.TrimRight(
		base32Encoding().EncodeToString([]byte(value)), "=",
	)
}

func base32Encoding() *base32.Encoding {
	return base32.StdEncoding
}

func firstUserID(t *testing.T, database betterauth.DatabaseAdapter) string {
	t.Helper()
	rows, err := database.FindMany(context.Background(), betterauth.FindManyQuery{
		Model: betterauth.ModelUser, Limit: 10,
	})
	if err != nil || len(rows) != 1 {
		t.Fatalf("find user: %#v %v", rows, err)
	}
	id, _ := rows[0]["id"].(string)
	return id
}

func FuzzTwoFactorCookieValue(f *testing.F) {
	f.Add("")
	f.Add("opaque")
	f.Add(strings.Repeat("x", 1025))
	f.Fuzz(func(t *testing.T, value string) {
		request := httptest.NewRequest(http.MethodGet, "https://auth.example.com/", nil)
		request.Header.Set("Cookie", defaultPendingCookie+"="+value)
		_, _ = cookieValue(request, defaultPendingCookie)
	})
}
