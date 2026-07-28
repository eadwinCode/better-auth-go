package betterauth_test

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	betterauth "github.com/eadwinCode/better-auth-go"
)

type stepClock struct {
	now time.Time
}

func (clock *stepClock) Now() time.Time {
	return clock.now
}

func TestCanonicalPasswordResetCallbackAndAllowlist(t *testing.T) {
	t.Parallel()
	const callbackURL = "https://app.example.com/recovery"
	client, mailer := newBlackBoxServerConfig(t, func(config *betterauth.Config) {
		config.AllowedRedirectURLs = []string{callbackURL}
	})
	if response := client.request(t, http.MethodPost, "/sign-up/email", map[string]any{
		"email":    "canonical-reset@example.com",
		"password": "correct horse battery staple",
		"name":     "Canonical Reset",
	}, false); response.Code != http.StatusOK {
		t.Fatal(response.Body.String())
	}
	request := client.request(t, http.MethodPost, "/request-password-reset", map[string]any{
		"email":      "canonical-reset@example.com",
		"redirectTo": callbackURL,
	}, false)
	if request.Code != http.StatusOK {
		t.Fatalf("request password reset: %d %s", request.Code, request.Body.String())
	}
	var responseBody map[string]any
	if err := json.Unmarshal(request.Body.Bytes(), &responseBody); err != nil {
		t.Fatal(err)
	}
	if responseBody["status"] != true ||
		responseBody["message"] != "If this email exists in our system, check your email for the reset link" {
		t.Fatalf("unexpected reset response: %#v", responseBody)
	}

	message := mailer.last()
	action, err := url.Parse(message.ActionURL)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(action.Path, "/reset-password/"+message.Token) ||
		action.Query().Get("callbackURL") != callbackURL {
		t.Fatalf("unexpected reset action URL: %s", action)
	}
	callbackPath := strings.TrimPrefix(action.Path, "/api/auth") + "?" + action.RawQuery
	callback := client.request(t, http.MethodGet, callbackPath, nil, false)
	if callback.Code != http.StatusFound {
		t.Fatalf("reset callback: %d %s", callback.Code, callback.Body.String())
	}
	location, err := url.Parse(callback.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if location.Scheme+"://"+location.Host+location.Path != callbackURL ||
		location.Query().Get("token") != message.Token {
		t.Fatalf("unexpected callback redirect: %s", location)
	}

	invalid := client.request(
		t,
		http.MethodGet,
		"/reset-password/invalid-reset-token-long-enough?callbackURL="+url.QueryEscape(callbackURL),
		nil,
		false,
	)
	if invalid.Code != http.StatusFound {
		t.Fatalf("invalid reset callback: %d %s", invalid.Code, invalid.Body.String())
	}
	invalidLocation, err := url.Parse(invalid.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if invalidLocation.Query().Get("error") != "INVALID_TOKEN" {
		t.Fatalf("invalid callback did not fail closed: %s", invalidLocation)
	}

	untrusted := client.request(
		t,
		http.MethodGet,
		"/reset-password/"+url.PathEscape(message.Token)+"?callbackURL="+
			url.QueryEscape("https://evil.example/recovery"),
		nil,
		false,
	)
	if untrusted.Code != http.StatusBadRequest {
		t.Fatalf("untrusted callback accepted: %d %s", untrusted.Code, untrusted.Body.String())
	}
}

func TestListSessionsRequiresFreshSession(t *testing.T) {
	t.Parallel()
	clock := &stepClock{now: time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)}
	client, _ := newBlackBoxServerConfig(t, func(config *betterauth.Config) {
		config.Clock = clock
		config.SessionFreshAge = time.Minute
	})
	if response := client.request(t, http.MethodPost, "/sign-up/email", map[string]any{
		"email":    "stale-session-list@example.com",
		"password": "correct horse battery staple",
		"name":     "Stale Session",
	}, false); response.Code != http.StatusOK {
		t.Fatal(response.Body.String())
	}
	clock.now = clock.now.Add(2 * time.Minute)
	list := client.request(t, http.MethodGet, "/list-sessions", nil, false)
	if list.Code != http.StatusForbidden {
		t.Fatalf("stale session listed sessions: %d %s", list.Code, list.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(list.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["code"] != "SESSION_NOT_FRESH" || body["message"] != "Session is not fresh" {
		t.Fatalf("unexpected stale-session error: %#v", body)
	}
}

func TestEmailVerificationCallbackAllowlist(t *testing.T) {
	t.Parallel()
	const callbackURL = "https://app.example.com/verified"
	client, mailer := newBlackBoxServerConfig(t, func(config *betterauth.Config) {
		config.AllowedRedirectURLs = []string{callbackURL}
	})
	if response := client.request(t, http.MethodPost, "/sign-up/email", map[string]any{
		"email":    "verification-callback@example.com",
		"password": "correct horse battery staple",
		"name":     "Verification Callback",
	}, false); response.Code != http.StatusOK {
		t.Fatal(response.Body.String())
	}
	send := client.request(t, http.MethodPost, "/send-verification-email", map[string]any{
		"email":       "verification-callback@example.com",
		"callbackURL": callbackURL,
	}, true)
	if send.Code != http.StatusOK {
		t.Fatalf("send verification: %d %s", send.Code, send.Body.String())
	}
	message := mailer.last()
	action, err := url.Parse(message.ActionURL)
	if err != nil {
		t.Fatal(err)
	}
	if action.Query().Get("callbackURL") != callbackURL {
		t.Fatalf("verification action omitted callback: %s", action)
	}
	verifyPath := strings.TrimPrefix(action.Path, "/api/auth") + "?" + action.RawQuery
	verify := client.request(t, http.MethodGet, verifyPath, nil, false)
	if verify.Code != http.StatusFound || verify.Header().Get("Location") != callbackURL {
		t.Fatalf("verification callback: %d location=%q body=%s",
			verify.Code, verify.Header().Get("Location"), verify.Body.String())
	}

	untrusted := client.request(t, http.MethodPost, "/send-verification-email", map[string]any{
		"email":       "verification-callback@example.com",
		"callbackURL": "https://evil.example/verified",
	}, true)
	if untrusted.Code != http.StatusBadRequest {
		t.Fatalf("untrusted verification callback accepted: %d %s",
			untrusted.Code, untrusted.Body.String())
	}
}
