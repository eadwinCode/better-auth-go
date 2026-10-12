package betterauth_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	betterauth "github.com/eadwinCode/better-auth-go"
	"github.com/eadwinCode/better-auth-go/plugin/onetimetoken"
)

const ottTokenAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"

type movingCompatibilityClock struct {
	mu  sync.Mutex
	now time.Time
}

func (clock *movingCompatibilityClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.now
}

func (clock *movingCompatibilityClock) advance(duration time.Duration) {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	clock.now = clock.now.Add(duration)
}

// ottPair drives one Go server and the matching TypeScript oracle instance
// (selected by base-path suffix) through the same one-time-token steps.
type ottPair struct {
	goClient *testClient
	goClock  *movingCompatibilityClock
	ts       *typescriptOracle
}

func newOTTPair(
	t *testing.T,
	oracle *typescriptOracle,
	suffix string,
	config onetimetoken.Config,
	configure func(*betterauth.Config),
) *ottPair {
	t.Helper()
	plugin, err := onetimetoken.New(config)
	if err != nil {
		t.Fatal(err)
	}
	clock := &movingCompatibilityClock{now: time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)}
	goClient, _ := newBlackBoxServerConfig(t, func(server *betterauth.Config) {
		server.Clock = clock
		server.Tokens = nil
		server.Plugins = []betterauth.Plugin{plugin}
		if configure != nil {
			configure(server)
		}
	})
	ts := oracle.clone(t)
	ts.basePath += suffix
	return &ottPair{goClient: goClient, goClock: clock, ts: ts}
}

func (pair *ottPair) signUp(t *testing.T, email string) (oracleResponse, oracleResponse) {
	t.Helper()
	body := map[string]any{"email": email, "password": "Correct-Horse-123!", "name": "OTT User"}
	goResult := goResponse(pair.goClient.request(t, http.MethodPost, "/sign-up/email", body, false))
	tsResult := pair.ts.request(t, http.MethodPost, "/sign-up/email", body, "")
	assertBothStatus(t, "sign-up", goResult, tsResult, http.StatusOK)
	return goResult, tsResult
}

func (pair *ottPair) generate(t *testing.T) (oracleResponse, oracleResponse) {
	t.Helper()
	return goResponse(pair.goClient.request(t, http.MethodGet, "/one-time-token/generate", nil, false)),
		pair.ts.request(t, http.MethodGet, "/one-time-token/generate", nil, "")
}

func (pair *ottPair) tokens(t *testing.T) (string, string) {
	t.Helper()
	goResult, tsResult := pair.generate(t)
	assertBothStatus(t, "generate", goResult, tsResult, http.StatusOK)
	goToken, _ := decodeObject(t, goResult.body)["token"].(string)
	tsToken, _ := decodeObject(t, tsResult.body)["token"].(string)
	for implementation, token := range map[string]string{"Go": goToken, "TypeScript": tsToken} {
		if len(token) != 32 || strings.Trim(token, ottTokenAlphabet) != "" {
			t.Fatalf("%s token %q is not 32 URL-safe characters", implementation, token)
		}
	}
	return goToken, tsToken
}

// verify calls verify like a separate server would: no session cookie.
// origin "-" sends no Origin header; "" sends the implementation's trusted
// origin.
func (pair *ottPair) verify(
	t *testing.T,
	goToken string,
	tsToken string,
	origin string,
	cookie string,
) (oracleResponse, oracleResponse) {
	t.Helper()
	send := func(body any, target string, trusted string, serve func(*http.Request) oracleResponse) oracleResponse {
		payload, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		request, err := http.NewRequest(http.MethodPost, target, bytes.NewReader(payload))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/json")
		switch origin {
		case "-":
		case "":
			request.Header.Set("Origin", trusted)
		default:
			request.Header.Set("Origin", origin)
		}
		if cookie != "" {
			request.Header.Set("Cookie", cookie)
		}
		return serve(request)
	}
	goResult := send(map[string]any{"token": goToken},
		"https://auth.example.com/api/auth/one-time-token/verify", "https://app.example.com",
		func(request *http.Request) oracleResponse {
			recorder := httptest.NewRecorder()
			pair.goClient.handler.ServeHTTP(recorder, request)
			return goResponse(recorder)
		})
	tsResult := send(map[string]any{"token": tsToken},
		pair.ts.baseURL.String()+pair.ts.basePath+"/one-time-token/verify", pair.ts.origin,
		func(request *http.Request) oracleResponse {
			response, err := (&http.Client{Timeout: 10 * time.Second}).Do(request)
			if err != nil {
				t.Fatalf("TypeScript verify: %v", err)
			}
			defer response.Body.Close()
			body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
			if err != nil {
				t.Fatal(err)
			}
			return oracleResponse{
				status: response.StatusCode, header: response.Header.Clone(),
				body: body, cookies: response.Cookies(),
			}
		})
	return goResult, tsResult
}

func assertBothStatus(t *testing.T, step string, goResult, tsResult oracleResponse, want int) {
	t.Helper()
	for implementation, result := range map[string]oracleResponse{"Go": goResult, "TypeScript": tsResult} {
		if result.status != want {
			t.Fatalf("%s %s status=%d want=%d body=%s", implementation, step, result.status, want, result.body)
		}
	}
}

func assertBothMessage(t *testing.T, step string, goResult, tsResult oracleResponse, want int, message string) {
	t.Helper()
	assertBothStatus(t, step, goResult, tsResult, want)
	for implementation, result := range map[string]oracleResponse{"Go": goResult, "TypeScript": tsResult} {
		if got := decodeObject(t, result.body)["message"]; got != message {
			t.Fatalf("%s %s message=%v want=%q", implementation, step, got, message)
		}
	}
}

func sessionCookieSet(result oracleResponse) bool {
	for _, cookie := range result.cookies {
		if (cookie.Name == "__Host-better_auth_session" || cookie.Name == "better-auth.session_token") &&
			cookie.Value != "" && cookie.MaxAge >= 0 {
			return true
		}
	}
	return false
}

func assertVerifiedSession(t *testing.T, goResult, tsResult oracleResponse, email string, wantCookie bool) {
	t.Helper()
	assertBothStatus(t, "verify", goResult, tsResult, http.StatusOK)
	assertEquivalentUser(t, goResult, tsResult, email, "OTT User")
	for implementation, result := range map[string]oracleResponse{"Go": goResult, "TypeScript": tsResult} {
		body := decodeObject(t, result.body)
		session, _ := body["session"].(map[string]any)
		user, _ := body["user"].(map[string]any)
		if session["id"] == nil || session["userId"] != user["id"] || session["expiresAt"] == nil {
			t.Fatalf("%s verify session=%v", implementation, session)
		}
		if sessionCookieSet(result) != wantCookie {
			t.Fatalf("%s verify session cookie=%v want=%v (%v)",
				implementation, !wantCookie, wantCookie, result.header.Values("Set-Cookie"))
		}
	}
	// Go never serializes session tokens (as with get-session); Better Auth
	// returns the session token in the verify body.
	if _, exposed := decodeObject(t, goResult.body)["session"].(map[string]any)["token"]; exposed {
		t.Fatal("Go verify exposed the session token")
	}
	if token, _ := decodeObject(t, tsResult.body)["session"].(map[string]any)["token"].(string); token == "" {
		t.Fatal("pinned Better Auth verify no longer returns session.token")
	}
}

func TestBetterAuthV177OneTimeTokenCompatibility(t *testing.T) {
	oracle := newTypeScriptOracle(t)

	t.Run("generate verify and single use", func(t *testing.T) {
		pair := newOTTPair(t, oracle, "-ott", onetimetoken.Config{}, nil)
		anonymousGo, anonymousTS := pair.generate(t)
		assertBothStatus(t, "anonymous generate", anonymousGo, anonymousTS, http.StatusUnauthorized)

		email := uniqueCompatibilityEmail("ott")
		pair.signUp(t, email)
		goToken, tsToken := pair.tokens(t)
		goResult, tsResult := pair.verify(t, goToken, tsToken, "", "")
		assertVerifiedSession(t, goResult, tsResult, email, true)

		goReplay, tsReplay := pair.verify(t, goToken, tsToken, "", "")
		assertBothMessage(t, "replay", goReplay, tsReplay, http.StatusBadRequest, "Invalid token")
		goUnknown, tsUnknown := pair.verify(t, "unknown-token", "unknown-token", "", "")
		assertBothMessage(t, "unknown token", goUnknown, tsUnknown, http.StatusBadRequest, "Invalid token")
	})

	t.Run("request validation", func(t *testing.T) {
		pair := newOTTPair(t, oracle, "-ott", onetimetoken.Config{}, nil)
		goMissing := goResponse(pair.goClient.request(t, http.MethodPost, "/one-time-token/verify", map[string]any{}, false))
		tsMissing := pair.ts.request(t, http.MethodPost, "/one-time-token/verify", map[string]any{}, "")
		assertBothStatus(t, "missing token", goMissing, tsMissing, http.StatusBadRequest)
		goNumber := goResponse(pair.goClient.request(t, http.MethodPost, "/one-time-token/verify", map[string]any{"token": 5}, false))
		tsNumber := pair.ts.request(t, http.MethodPost, "/one-time-token/verify", map[string]any{"token": 5}, "")
		assertBothStatus(t, "numeric token", goNumber, tsNumber, http.StatusBadRequest)
	})

	t.Run("origin is checked only with cookies", func(t *testing.T) {
		pair := newOTTPair(t, oracle, "-ott", onetimetoken.Config{}, nil)
		for _, origin := range []string{"-", "https://evil.example.net"} {
			goResult, tsResult := pair.verify(t, "unknown", "unknown", origin, "theme=dark")
			assertBothStatus(t, "cookie with origin "+origin, goResult, tsResult, http.StatusForbidden)
		}
		goResult, tsResult := pair.verify(t, "unknown", "unknown", "-", "")
		assertBothMessage(t, "no cookie and no origin", goResult, tsResult, http.StatusBadRequest, "Invalid token")
	})

	t.Run("revoked session", func(t *testing.T) {
		pair := newOTTPair(t, oracle, "-ott", onetimetoken.Config{}, nil)
		pair.signUp(t, uniqueCompatibilityEmail("ott-revoked"))
		goToken, tsToken := pair.tokens(t)
		goSignOut := goResponse(pair.goClient.request(t, http.MethodPost, "/sign-out", nil, true))
		tsSignOut := pair.ts.request(t, http.MethodPost, "/sign-out", nil, "")
		assertBothStatus(t, "sign-out", goSignOut, tsSignOut, http.StatusOK)
		goResult, tsResult := pair.verify(t, goToken, tsToken, "", "")
		assertBothMessage(t, "verify revoked", goResult, tsResult, http.StatusBadRequest, "Session not found")
	})

	t.Run("hashed storage", func(t *testing.T) {
		pair := newOTTPair(t, oracle, "-ott-hashed",
			onetimetoken.Config{StoreToken: onetimetoken.TokenStorageHashed}, nil)
		email := uniqueCompatibilityEmail("ott-hashed")
		pair.signUp(t, email)
		goToken, tsToken := pair.tokens(t)
		goResult, tsResult := pair.verify(t, goToken, tsToken, "-", "")
		assertVerifiedSession(t, goResult, tsResult, email, true)
	})

	t.Run("disable set session cookie", func(t *testing.T) {
		pair := newOTTPair(t, oracle, "-ott-no-cookie",
			onetimetoken.Config{DisableSetSessionCookie: true}, nil)
		email := uniqueCompatibilityEmail("ott-no-cookie")
		pair.signUp(t, email)
		goToken, tsToken := pair.tokens(t)
		goResult, tsResult := pair.verify(t, goToken, tsToken, "-", "")
		assertVerifiedSession(t, goResult, tsResult, email, false)
	})

	t.Run("disable client request", func(t *testing.T) {
		pair := newOTTPair(t, oracle, "-ott-server-only",
			onetimetoken.Config{DisableClientRequest: true}, nil)
		pair.signUp(t, uniqueCompatibilityEmail("ott-server-only"))
		goResult, tsResult := pair.generate(t)
		assertBothMessage(t, "generate", goResult, tsResult, http.StatusBadRequest, "Client requests are disabled")
	})

	t.Run("set ott header on new session", func(t *testing.T) {
		pair := newOTTPair(t, oracle, "-ott-header",
			onetimetoken.Config{SetOTTHeaderOnNewSession: true}, nil)
		email := uniqueCompatibilityEmail("ott-header")
		goSignUp, tsSignUp := pair.signUp(t, email)
		body := map[string]any{"email": email, "password": "Correct-Horse-123!"}
		goSignIn := goResponse(pair.goClient.request(t, http.MethodPost, "/sign-in/email", body, false))
		tsSignIn := pair.ts.request(t, http.MethodPost, "/sign-in/email", body, "")
		assertBothStatus(t, "sign-in", goSignIn, tsSignIn, http.StatusOK)
		for implementation, result := range map[string]oracleResponse{
			"Go sign-up": goSignUp, "TypeScript sign-up": tsSignUp,
			"Go sign-in": goSignIn, "TypeScript sign-in": tsSignIn,
		} {
			if token := result.header.Get("set-ott"); len(token) != 32 {
				t.Fatalf("%s set-ott=%q", implementation, token)
			}
			if !strings.Contains(strings.ToLower(result.header.Get("Access-Control-Expose-Headers")), "set-ott") {
				t.Fatalf("%s expose headers=%q", implementation, result.header.Get("Access-Control-Expose-Headers"))
			}
		}
		goResult, tsResult := pair.verify(t, goSignIn.header.Get("set-ott"), tsSignIn.header.Get("set-ott"), "", "")
		assertVerifiedSession(t, goResult, tsResult, email, true)
		// Verify sets a session cookie, so both add a fresh header again.
		if len(goResult.header.Get("set-ott")) != 32 || len(tsResult.header.Get("set-ott")) != 32 {
			t.Fatalf("verify set-ott Go=%q TypeScript=%q", goResult.header.Get("set-ott"), tsResult.header.Get("set-ott"))
		}
		goGenerate, tsGenerate := pair.generate(t)
		if goGenerate.header.Get("set-ott") != "" || tsGenerate.header.Get("set-ott") != "" {
			t.Fatal("generate response carried a set-ott header")
		}
	})

	t.Run("expired token", func(t *testing.T) {
		pair := newOTTPair(t, oracle, "-ott-short-token",
			onetimetoken.Config{ExpiresIn: time.Second}, nil)
		pair.signUp(t, uniqueCompatibilityEmail("ott-short-token"))
		goToken, tsToken := pair.tokens(t)
		pair.goClock.advance(2 * time.Second)
		time.Sleep(1500 * time.Millisecond)
		goResult, tsResult := pair.verify(t, goToken, tsToken, "", "")
		assertBothMessage(t, "verify expired token", goResult, tsResult, http.StatusBadRequest, "Invalid token")
	})

	t.Run("expired session", func(t *testing.T) {
		// The oracle session lasts two seconds; Go's shortest allowed
		// session is five minutes, so the Go clock jumps past it instead.
		pair := newOTTPair(t, oracle, "-ott-short-session",
			onetimetoken.Config{ExpiresIn: 10 * time.Minute},
			func(server *betterauth.Config) { server.SessionDuration = 5 * time.Minute })
		pair.signUp(t, uniqueCompatibilityEmail("ott-short-session"))
		goToken, tsToken := pair.tokens(t)
		pair.goClock.advance(6 * time.Minute)
		time.Sleep(2500 * time.Millisecond)
		goResult, tsResult := pair.verify(t, goToken, tsToken, "", "")
		assertBothMessage(t, "verify expired session", goResult, tsResult, http.StatusBadRequest, "Session expired")
		// Deliberate difference: Better Auth sets the expired session's
		// cookie before it rejects the request. Go sets no cookie.
		if sessionCookieSet(goResult) {
			t.Fatal("Go set a session cookie for an expired session")
		}
		if !sessionCookieSet(tsResult) {
			t.Fatal("pinned Better Auth no longer sets a cookie on an expired-session verify")
		}
	})
}
