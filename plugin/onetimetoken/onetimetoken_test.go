package onetimetoken

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	betterauth "github.com/eadwinCode/better-auth-go"
	"github.com/eadwinCode/better-auth-go/adapter/memory"
)

const (
	sessionCookie = "__Host-better_auth_session"
	testPassword  = "Correct-Horse-123!"
)

type movingClock struct {
	mu  sync.Mutex
	now time.Time
}

func (clock *movingClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.now
}

func (clock *movingClock) advance(duration time.Duration) {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	clock.now = clock.now.Add(duration)
}

type discardMailer struct{}

func (discardMailer) Send(context.Context, betterauth.Mail) error { return nil }

type denyImpersonation struct{}

func (denyImpersonation) CanImpersonate(context.Context, betterauth.User, betterauth.User) error {
	return betterauth.ErrNotFound
}

type testServer struct {
	handler  http.Handler
	server   *betterauth.Server
	database *memory.Adapter
	clock    *movingClock
	manager  *Manager
}

func newTestServer(t *testing.T, config Config, configure ...func(*betterauth.Config)) *testServer {
	t.Helper()
	manager, err := NewManager(config)
	if err != nil {
		t.Fatal(err)
	}
	database := memory.New()
	clock := &movingClock{now: time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)}
	serverConfig := betterauth.Config{
		PublicURL:      "https://auth.example.com",
		TrustedOrigins: []string{"https://app.example.com"},
		Database:       database, Clock: clock, Mailer: discardMailer{},
		ImpersonationAuthorizer: denyImpersonation{},
		Plugins:                 []betterauth.Plugin{manager.Plugin()},
	}
	for _, apply := range configure {
		apply(&serverConfig)
	}
	server, err := betterauth.New(serverConfig)
	if err != nil {
		t.Fatal(err)
	}
	return &testServer{
		handler: server.Handler(), server: server, database: database, clock: clock, manager: manager,
	}
}

type requestOptions struct {
	cookies []*http.Cookie
	origin  string
	noJSON  bool
}

func (server *testServer) do(
	t *testing.T,
	method string,
	path string,
	body any,
	options requestOptions,
) *httptest.ResponseRecorder {
	t.Helper()
	var payload []byte
	if body != nil {
		var err error
		if payload, err = json.Marshal(body); err != nil {
			t.Fatal(err)
		}
	}
	request := httptest.NewRequest(method, "https://auth.example.com/api/auth"+path, bytes.NewReader(payload))
	if options.origin != "-" {
		origin := options.origin
		if origin == "" {
			origin = "https://app.example.com"
		}
		request.Header.Set("Origin", origin)
	}
	if body != nil && !options.noJSON {
		request.Header.Set("Content-Type", "application/json")
	}
	for _, cookie := range options.cookies {
		request.AddCookie(cookie)
	}
	recorder := httptest.NewRecorder()
	server.handler.ServeHTTP(recorder, request)
	return recorder
}

// signUp creates a user and returns its session cookie.
func (server *testServer) signUp(t *testing.T, email string) *http.Cookie {
	t.Helper()
	response := server.do(t, http.MethodPost, "/sign-up/email", map[string]any{
		"email": email, "password": testPassword, "name": "OTT User",
	}, requestOptions{})
	if response.Code != http.StatusOK {
		t.Fatalf("sign-up status=%d body=%s", response.Code, response.Body)
	}
	return responseCookie(t, response, sessionCookie)
}

func (server *testServer) generate(t *testing.T, session *http.Cookie) string {
	t.Helper()
	response := server.do(t, http.MethodGet, "/one-time-token/generate", nil,
		requestOptions{cookies: []*http.Cookie{session}})
	if response.Code != http.StatusOK {
		t.Fatalf("generate status=%d body=%s", response.Code, response.Body)
	}
	token, _ := decode(t, response)["token"].(string)
	if token == "" {
		t.Fatalf("generate returned no token: %s", response.Body)
	}
	return token
}

func (server *testServer) verify(t *testing.T, token string) *httptest.ResponseRecorder {
	t.Helper()
	return server.do(t, http.MethodPost, "/one-time-token/verify", map[string]any{"token": token}, requestOptions{})
}

func responseCookie(t *testing.T, response *httptest.ResponseRecorder, name string) *http.Cookie {
	t.Helper()
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == name && cookie.Value != "" {
			return cookie
		}
	}
	t.Fatalf("response has no %s cookie: %v", name, response.Header().Values("Set-Cookie"))
	return nil
}

func decode(t *testing.T, response *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode %d %q: %v", response.Code, response.Body, err)
	}
	return body
}

func assertError(t *testing.T, response *httptest.ResponseRecorder, status int, message string) {
	t.Helper()
	if response.Code != status {
		t.Fatalf("status=%d want=%d body=%s", response.Code, status, response.Body)
	}
	if message != "" && decode(t, response)["message"] != message {
		t.Fatalf("message=%v want=%q", decode(t, response)["message"], message)
	}
	if len(response.Header().Values("Set-Cookie")) != 0 {
		t.Fatalf("error response set cookies: %v", response.Header().Values("Set-Cookie"))
	}
}

func verificationRows(t *testing.T, server *testServer) []betterauth.Record {
	t.Helper()
	rows, err := server.database.FindMany(t.Context(), betterauth.FindManyQuery{
		Model: betterauth.ModelVerification,
		Where: []betterauth.Where{betterauth.Eq("identifier", verificationIdentifier)},
	})
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

// Ported from upstream "should work".
func TestGenerateVerifyAndSingleUse(t *testing.T) {
	server := newTestServer(t, Config{})
	session := server.signUp(t, "ott@example.com")
	token := server.generate(t, session)
	if len(token) != 32 || strings.Trim(token, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_") != "" {
		t.Fatalf("token %q does not match Better Auth's 32-character alphabet", token)
	}

	response := server.verify(t, token)
	if response.Code != http.StatusOK {
		t.Fatalf("verify status=%d body=%s", response.Code, response.Body)
	}
	body := decode(t, response)
	user, _ := body["user"].(map[string]any)
	sessionBody, _ := body["session"].(map[string]any)
	if user["email"] != "ott@example.com" || sessionBody["userId"] != user["id"] {
		t.Fatalf("verify body=%s", response.Body)
	}
	if _, exposed := sessionBody["token"]; exposed {
		t.Fatal("verify exposed the session token in JSON")
	}
	// The cookie is the same session, not a new one.
	if cookie := responseCookie(t, response, sessionCookie); cookie.Value != session.Value {
		t.Fatal("verify set a different session token")
	}
	if response.Header().Get("X-CSRF-Token") == "" {
		t.Fatal("verify did not issue a CSRF token for the attached session")
	}

	assertError(t, server.verify(t, token), http.StatusBadRequest, "Invalid token")
}

// Ported from upstream "should expire".
func TestTokenExpires(t *testing.T) {
	server := newTestServer(t, Config{})
	token := server.generate(t, server.signUp(t, "expire@example.com"))
	server.clock.advance(DefaultExpiresIn + time.Second)
	assertError(t, server.verify(t, token), http.StatusBadRequest, "Invalid token")
}

func TestCustomExpiresIn(t *testing.T) {
	server := newTestServer(t, Config{ExpiresIn: 30 * time.Second})
	session := server.signUp(t, "short@example.com")
	early := server.generate(t, session)
	late := server.generate(t, session)
	server.clock.advance(29 * time.Second)
	if response := server.verify(t, early); response.Code != http.StatusOK {
		t.Fatalf("token rejected before expiry: %d %s", response.Code, response.Body)
	}
	server.clock.advance(2 * time.Second)
	assertError(t, server.verify(t, late), http.StatusBadRequest, "Invalid token")
}

// Ported from upstream "should only redeem a token once under concurrent
// verification".
func TestConcurrentVerificationRedeemsOnce(t *testing.T) {
	server := newTestServer(t, Config{})
	token := server.generate(t, server.signUp(t, "race@example.com"))
	const workers = 16
	codes := make(chan int, workers)
	var wait sync.WaitGroup
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			codes <- server.verify(t, token).Code
		}()
	}
	wait.Wait()
	close(codes)
	succeeded := 0
	for code := range codes {
		switch code {
		case http.StatusOK:
			succeeded++
		case http.StatusBadRequest:
		default:
			t.Fatalf("unexpected status %d", code)
		}
	}
	if succeeded != 1 {
		t.Fatalf("token redeemed %d times", succeeded)
	}
}

// Ported from upstream "should reject token when underlying session has
// expired". Upstream still sets the expired session cookie on this error; Go
// does not.
func TestExpiredSessionIsRejected(t *testing.T) {
	server := newTestServer(t, Config{ExpiresIn: 10 * time.Minute}, func(config *betterauth.Config) {
		config.SessionDuration = 5 * time.Minute
	})
	token := server.generate(t, server.signUp(t, "old-session@example.com"))
	server.clock.advance(6 * time.Minute)
	assertError(t, server.verify(t, token), http.StatusBadRequest, "Session expired")
}

func TestRevokedSessionIsRejected(t *testing.T) {
	server := newTestServer(t, Config{})
	session := server.signUp(t, "revoked@example.com")
	token := server.generate(t, session)
	signIn := server.do(t, http.MethodGet, "/get-session", nil, requestOptions{cookies: []*http.Cookie{session}})
	csrf := responseCookie(t, signIn, "__Host-better_auth_csrf")
	request := httptest.NewRequest(http.MethodPost, "https://auth.example.com/api/auth/sign-out", nil)
	request.Header.Set("Origin", "https://app.example.com")
	request.Header.Set("X-CSRF-Token", csrf.Value)
	request.AddCookie(session)
	request.AddCookie(csrf)
	signOut := httptest.NewRecorder()
	server.handler.ServeHTTP(signOut, request)
	if signOut.Code != http.StatusOK {
		t.Fatalf("sign-out status=%d body=%s", signOut.Code, signOut.Body)
	}
	assertError(t, server.verify(t, token), http.StatusBadRequest, "Session not found")
}

func TestDisabledUserIsRejected(t *testing.T) {
	server := newTestServer(t, Config{})
	token := server.generate(t, server.signUp(t, "disabled@example.com"))
	if _, err := server.database.Update(t.Context(), betterauth.UpdateQuery{
		Model:  betterauth.ModelUser,
		Where:  []betterauth.Where{betterauth.Eq("email", "disabled@example.com")},
		Update: betterauth.Record{"disabledAt": server.clock.Now()},
	}); err != nil {
		t.Fatal(err)
	}
	assertError(t, server.verify(t, token), http.StatusBadRequest, "Session not found")
}

// Ported from upstream "should work with hashed".
func TestHashedStorage(t *testing.T) {
	server := newTestServer(t, Config{
		StoreToken: TokenStorageHashed,
		GenerateToken: func(context.Context, betterauth.SessionResult) (string, error) {
			return "123456", nil
		},
	})
	session := server.signUp(t, "hashed@example.com")
	if token := server.generate(t, session); token != "123456" {
		t.Fatalf("token=%q", token)
	}
	rows := verificationRows(t, server)
	if len(rows) != 1 || rows[0]["value"] != betterauth.HashToken("123456") {
		t.Fatalf("stored rows=%v", rows)
	}
	assertNoSecretsAtRest(t, rows[0], "123456", session.Value)
	response := server.verify(t, "123456")
	if response.Code != http.StatusOK {
		t.Fatalf("verify status=%d body=%s", response.Code, response.Body)
	}
	if user, _ := decode(t, response)["user"].(map[string]any); user["email"] != "hashed@example.com" {
		t.Fatalf("verify body=%s", response.Body)
	}
}

// Plain storage is the default, as in Better Auth. Unlike Better Auth, the
// session token itself is still never stored in the clear.
func TestDefaultPlainStorageStillSealsSession(t *testing.T) {
	server := newTestServer(t, Config{})
	session := server.signUp(t, "plain@example.com")
	token := server.generate(t, session)
	rows := verificationRows(t, server)
	if len(rows) != 1 || rows[0]["value"] != token {
		t.Fatalf("stored rows=%v", rows)
	}
	encoded, _ := json.Marshal(rows[0])
	if strings.Contains(string(encoded), session.Value) {
		t.Fatal("plain storage kept the raw session token")
	}
	if response := server.verify(t, token); response.Code != http.StatusOK {
		t.Fatalf("verify status=%d body=%s", response.Code, response.Body)
	}
}

// Ported from upstream "should work with custom hasher".
func TestCustomHasher(t *testing.T) {
	server := newTestServer(t, Config{
		StoreToken: TokenStorageCustom,
		HashToken: func(_ context.Context, token string) (string, error) {
			return token + "hashed", nil
		},
		GenerateToken: func(context.Context, betterauth.SessionResult) (string, error) {
			return "123456", nil
		},
	})
	server.generate(t, server.signUp(t, "custom@example.com"))
	if rows := verificationRows(t, server); len(rows) != 1 || rows[0]["value"] != "123456hashed" {
		t.Fatalf("stored rows=%v", rows)
	}
	if response := server.verify(t, "123456"); response.Code != http.StatusOK {
		t.Fatalf("verify status=%d body=%s", response.Code, response.Body)
	}
}

func TestGenerateTokenReceivesSession(t *testing.T) {
	var seen betterauth.SessionResult
	server := newTestServer(t, Config{
		GenerateToken: func(_ context.Context, session betterauth.SessionResult) (string, error) {
			seen = session
			return "custom-token-value-with-entropy", nil
		},
	})
	server.generate(t, server.signUp(t, "seen@example.com"))
	if seen.User.Email != "seen@example.com" || seen.Session.UserID != seen.User.ID {
		t.Fatalf("generator saw %#v", seen)
	}
}

// Ported from upstream "disableClientRequest option".
func TestDisableClientRequest(t *testing.T) {
	server := newTestServer(t, Config{DisableClientRequest: true})
	session := server.signUp(t, "server-only@example.com")
	response := server.do(t, http.MethodGet, "/one-time-token/generate", nil,
		requestOptions{cookies: []*http.Cookie{session}})
	assertError(t, response, http.StatusBadRequest, "Client requests are disabled")

	// Server code can still create a token.
	request := httptest.NewRequest(http.MethodGet, "https://auth.example.com/", nil)
	request.AddCookie(session)
	resolved, err := server.server.ResolveSession(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	token, err := server.manager.Generate(t.Context(), server.database, resolved, session.Value)
	if err != nil {
		t.Fatal(err)
	}
	if response := server.verify(t, token); response.Code != http.StatusOK {
		t.Fatalf("verify status=%d body=%s", response.Code, response.Body)
	}
	if _, err := server.manager.Generate(t.Context(), server.database, resolved, "other-token"); !errors.Is(err, betterauth.ErrNoSession) {
		t.Fatalf("mismatched session token err=%v", err)
	}
}

// Ported from upstream "disableSetSessionCookie option".
func TestDisableSetSessionCookie(t *testing.T) {
	server := newTestServer(t, Config{DisableSetSessionCookie: true})
	token := server.generate(t, server.signUp(t, "no-cookie@example.com"))
	// Server-to-server callers do not need an Origin header in this mode.
	response := server.do(t, http.MethodPost, "/one-time-token/verify", map[string]any{"token": token},
		requestOptions{origin: "-"})
	if response.Code != http.StatusOK {
		t.Fatalf("verify status=%d body=%s", response.Code, response.Body)
	}
	if cookies := response.Header().Values("Set-Cookie"); len(cookies) != 0 {
		t.Fatalf("verify set cookies: %v", cookies)
	}
	if response.Header().Get("X-CSRF-Token") != "" {
		t.Fatal("verify issued a CSRF token without a session cookie")
	}
}

// Like Better Auth, verify checks the Origin only when the request carries
// cookies. A server-to-server call without cookies needs no Origin.
func TestVerifyOriginRuleMatchesBetterAuth(t *testing.T) {
	server := newTestServer(t, Config{})
	token := server.generate(t, server.signUp(t, "origin@example.com"))
	browserCookie := []*http.Cookie{{Name: "theme", Value: "dark"}}
	for _, origin := range []string{"-", "null", "https://evil.example.net"} {
		response := server.do(t, http.MethodPost, "/one-time-token/verify", map[string]any{"token": token},
			requestOptions{origin: origin, cookies: browserCookie})
		if response.Code != http.StatusForbidden {
			t.Fatalf("origin %q status=%d body=%s", origin, response.Code, response.Body)
		}
	}
	// Rejected requests must not burn the token.
	response := server.do(t, http.MethodPost, "/one-time-token/verify", map[string]any{"token": token},
		requestOptions{origin: "-"})
	if response.Code != http.StatusOK {
		t.Fatalf("verify without cookies or Origin status=%d body=%s", response.Code, response.Body)
	}
	other := server.generate(t, server.signUp(t, "origin-ok@example.com"))
	response = server.do(t, http.MethodPost, "/one-time-token/verify", map[string]any{"token": other},
		requestOptions{cookies: browserCookie})
	if response.Code != http.StatusOK {
		t.Fatalf("verify with cookie and trusted Origin status=%d body=%s", response.Code, response.Body)
	}
}

// Ported from upstream "setOttHeaderOnNewSession option".
func TestSetOTTHeaderOnNewSession(t *testing.T) {
	server := newTestServer(t, Config{SetOTTHeaderOnNewSession: true})
	signUp := server.do(t, http.MethodPost, "/sign-up/email", map[string]any{
		"email": "header@example.com", "password": testPassword, "name": "Header",
	}, requestOptions{})
	header := signUp.Header().Get(HeaderName)
	if signUp.Code != http.StatusOK || len(header) != 32 {
		t.Fatalf("sign-up status=%d set-ott=%q", signUp.Code, header)
	}
	if !strings.Contains(signUp.Header().Get("Access-Control-Expose-Headers"), HeaderName) {
		t.Fatalf("expose headers=%q", signUp.Header().Get("Access-Control-Expose-Headers"))
	}

	signIn := server.do(t, http.MethodPost, "/sign-in/email", map[string]any{
		"email": "header@example.com", "password": testPassword,
	}, requestOptions{})
	signInToken := signIn.Header().Get(HeaderName)
	if signIn.Code != http.StatusOK || len(signInToken) != 32 {
		t.Fatalf("sign-in status=%d set-ott=%q", signIn.Code, signInToken)
	}

	// The header token verifies to the session that response created, and
	// verify itself sets a session cookie, so it carries a new header too.
	verified := server.verify(t, signInToken)
	if verified.Code != http.StatusOK {
		t.Fatalf("verify status=%d body=%s", verified.Code, verified.Body)
	}
	if responseCookie(t, verified, sessionCookie).Value != responseCookie(t, signIn, sessionCookie).Value {
		t.Fatal("set-ott token resolved to another session")
	}
	if len(verified.Header().Get(HeaderName)) != 32 {
		t.Fatalf("verify set-ott=%q", verified.Header().Get(HeaderName))
	}

	// Responses that set no session cookie get no header.
	session := responseCookie(t, signIn, sessionCookie)
	generate := server.do(t, http.MethodGet, "/one-time-token/generate", nil,
		requestOptions{cookies: []*http.Cookie{session}})
	if generate.Header().Get(HeaderName) != "" {
		t.Fatal("generate response carried a set-ott header")
	}
}

func TestNoOTTHeaderByDefault(t *testing.T) {
	server := newTestServer(t, Config{})
	signUp := server.do(t, http.MethodPost, "/sign-up/email", map[string]any{
		"email": "no-header@example.com", "password": testPassword, "name": "No Header",
	}, requestOptions{})
	if signUp.Header().Get(HeaderName) != "" {
		t.Fatal("set-ott header sent without the option")
	}
}

func TestEndpointInputErrors(t *testing.T) {
	server := newTestServer(t, Config{})
	if response := server.do(t, http.MethodGet, "/one-time-token/generate", nil, requestOptions{}); response.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous generate status=%d body=%s", response.Code, response.Body)
	}
	for name, body := range map[string]any{
		"missing token": map[string]any{},
		"number token":  map[string]any{"token": 5},
		"long token":    map[string]any{"token": strings.Repeat("a", maxTokenLength+1)},
	} {
		if response := server.do(t, http.MethodPost, "/one-time-token/verify", body, requestOptions{}); response.Code != http.StatusBadRequest {
			t.Fatalf("%s status=%d body=%s", name, response.Code, response.Body)
		}
	}
	assertError(t, server.verify(t, ""), http.StatusBadRequest, "Invalid token")
	assertError(t, server.verify(t, "unknown"), http.StatusBadRequest, "Invalid token")
	if response := server.do(t, http.MethodPost, "/one-time-token/generate", nil, requestOptions{}); response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST generate status=%d", response.Code)
	}
}

func TestTamperedRecordIsRejected(t *testing.T) {
	server := newTestServer(t, Config{})
	first := server.generate(t, server.signUp(t, "first@example.com"))
	second := server.generate(t, server.signUp(t, "second@example.com"))
	rows := verificationRows(t, server)
	if len(rows) != 2 {
		t.Fatalf("rows=%v", rows)
	}
	// Swap the sealed sessions between the two records.
	byValue := map[string]betterauth.Record{}
	for _, row := range rows {
		byValue[row["value"].(string)] = row
	}
	firstRow, secondRow := byValue[first], byValue[second]
	if firstRow == nil || secondRow == nil {
		t.Fatalf("rows=%v", rows)
	}
	for _, swap := range []struct {
		row      betterauth.Record
		metadata any
	}{{firstRow, secondRow["metadata"]}, {secondRow, firstRow["metadata"]}} {
		if _, err := server.database.Update(t.Context(), betterauth.UpdateQuery{
			Model:  betterauth.ModelVerification,
			Where:  []betterauth.Where{betterauth.Eq("id", swap.row["id"])},
			Update: betterauth.Record{"metadata": swap.metadata},
		}); err != nil {
			t.Fatal(err)
		}
	}
	assertError(t, server.verify(t, first), http.StatusBadRequest, "Invalid token")
	assertError(t, server.verify(t, second), http.StatusBadRequest, "Invalid token")
}

func TestSealSession(t *testing.T) {
	sealed, err := sealSession("one-time", "stored", "raw-session")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sealed, "raw-session") {
		t.Fatal("sealed value contains the session token")
	}
	if raw, err := openSession("one-time", "stored", sealed); err != nil || raw != "raw-session" {
		t.Fatalf("open=%q err=%v", raw, err)
	}
	for name, args := range map[string][3]string{
		"wrong token":  {"other", "stored", sealed},
		"wrong record": {"one-time", "other", sealed},
		"no prefix":    {"one-time", "stored", strings.TrimPrefix(sealed, sealPrefix)},
		"truncated":    {"one-time", "stored", sealed[:len(sealed)-4]},
		"empty":        {"one-time", "stored", ""},
	} {
		if _, err := openSession(args[0], args[1], args[2]); err == nil {
			t.Fatalf("%s: opened", name)
		}
	}
}

func TestConfigValidation(t *testing.T) {
	hasher := func(_ context.Context, token string) (string, error) { return token, nil }
	for name, config := range map[string]Config{
		"negative expiry":    {ExpiresIn: -time.Second},
		"unknown storage":    {StoreToken: "encrypted"},
		"custom no hasher":   {StoreToken: TokenStorageCustom},
		"hasher with hashed": {StoreToken: TokenStorageHashed, HashToken: hasher},
		"hasher default":     {HashToken: hasher},
	} {
		if _, err := New(config); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	manager, err := NewManager(Config{})
	if err != nil {
		t.Fatal(err)
	}
	if manager.runtime.config.ExpiresIn != DefaultExpiresIn ||
		manager.runtime.config.StoreToken != TokenStoragePlain {
		t.Fatalf("defaults=%#v", manager.runtime.config)
	}
	plugin := manager.Plugin()
	if plugin.ID != PluginID || len(plugin.Endpoints) != 2 || len(plugin.After) != 0 {
		t.Fatalf("plugin=%#v", plugin)
	}
	for _, endpoint := range plugin.Endpoints {
		// verify replaces the kernel check with cookieOriginCheck.
		if endpoint.SkipOriginCheck != (endpoint.Path == "/one-time-token/verify") ||
			(endpoint.SkipOriginCheck && len(endpoint.Use) != 1) {
			t.Fatalf("%s origin handling changed", endpoint.Path)
		}
	}
}

func assertNoSecretsAtRest(t *testing.T, row betterauth.Record, token, rawSession string) {
	t.Helper()
	encoded, err := json.Marshal(row)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{token, rawSession} {
		if strings.Contains(string(encoded), `"`+secret+`"`) || strings.Contains(string(encoded), rawSession) {
			t.Fatalf("verification row stores a secret: %s", encoded)
		}
	}
	if !strings.HasPrefix(metadataString(row["metadata"], metadataSession), sealPrefix) {
		t.Fatalf("verification row has no sealed session: %s", encoded)
	}
}
