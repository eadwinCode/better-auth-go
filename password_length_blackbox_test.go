package betterauth_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	betterauth "github.com/eadwinCode/better-auth-go"
	"github.com/eadwinCode/better-auth-go/adapter/memory"
)

// recordingPasswordVerifier counts every Hash and Verify call so tests can
// prove an over-long password never reaches the hasher.
type recordingPasswordVerifier struct {
	mu       sync.Mutex
	delegate betterauth.PasswordVerifier
	hashes   int
	verifies int
}

func (verifier *recordingPasswordVerifier) Hash(ctx context.Context, password string) (string, error) {
	verifier.mu.Lock()
	verifier.hashes++
	verifier.mu.Unlock()
	return verifier.delegate.Hash(ctx, password)
}

func (verifier *recordingPasswordVerifier) Verify(
	ctx context.Context,
	hash string,
	password string,
) (betterauth.PasswordVerification, error) {
	verifier.mu.Lock()
	verifier.verifies++
	verifier.mu.Unlock()
	return verifier.delegate.Verify(ctx, hash, password)
}

func (verifier *recordingPasswordVerifier) calls() (int, int) {
	verifier.mu.Lock()
	defer verifier.mu.Unlock()
	return verifier.hashes, verifier.verifies
}

// recordingRateLimiter records each action and can deny every request.
type recordingRateLimiter struct {
	mu      sync.Mutex
	actions []string
	deny    bool
}

func (limiter *recordingRateLimiter) Allow(
	_ context.Context,
	request betterauth.RateLimitRequest,
) (betterauth.RateLimitDecision, error) {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	limiter.actions = append(limiter.actions, request.Action)
	return betterauth.RateLimitDecision{Allowed: !limiter.deny}, nil
}

func (limiter *recordingRateLimiter) count(action string) int {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	total := 0
	for _, recorded := range limiter.actions {
		if recorded == action {
			total++
		}
	}
	return total
}

func (limiter *recordingRateLimiter) setDeny(deny bool) {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	limiter.deny = deny
}

const lengthTestPassword = "correct horse battery staple"

func TestOverLongPasswordsAreRejectedBeforeLookupOrHash(t *testing.T) {
	t.Parallel()
	tooLong := strings.Repeat("p", 129)
	for _, test := range []struct {
		name        string
		method      string
		path        string
		body        map[string]any
		csrf        bool
		wantStatus  int
		wantCode    string
		wantMessage string
	}{
		{
			name: "sign-in", method: http.MethodPost, path: "/sign-in/email",
			body:       map[string]any{"email": "length@example.com", "password": tooLong},
			wantStatus: http.StatusBadRequest, wantCode: "PASSWORD_TOO_LONG", wantMessage: "Password too long",
		},
		{
			name: "sign-in validates the email first", method: http.MethodPost, path: "/sign-in/email",
			body:       map[string]any{"email": "not-an-email", "password": tooLong},
			wantStatus: http.StatusBadRequest, wantCode: "INVALID_EMAIL", wantMessage: "Invalid email",
		},
		{
			name: "change-password current password", method: http.MethodPost, path: "/change-password",
			body:       map[string]any{"currentPassword": tooLong, "newPassword": "new password value"},
			csrf:       true,
			wantStatus: http.StatusBadRequest, wantCode: "PASSWORD_TOO_LONG", wantMessage: "Password too long",
		},
		{
			name: "change-password too-short new password wins", method: http.MethodPost, path: "/change-password",
			body:       map[string]any{"currentPassword": tooLong, "newPassword": "short"},
			csrf:       true,
			wantStatus: http.StatusBadRequest, wantCode: "PASSWORD_TOO_SHORT", wantMessage: "Password too short",
		},
		{
			name: "change-password too-long new password", method: http.MethodPost, path: "/change-password",
			body:       map[string]any{"currentPassword": lengthTestPassword, "newPassword": tooLong},
			csrf:       true,
			wantStatus: http.StatusBadRequest, wantCode: "PASSWORD_TOO_LONG", wantMessage: "Password too long",
		},
		{
			name: "delete-user", method: http.MethodPost, path: "/delete-user",
			body:       map[string]any{"password": tooLong},
			csrf:       true,
			wantStatus: http.StatusBadRequest, wantCode: "PASSWORD_TOO_LONG", wantMessage: "Password too long",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			verifier := &recordingPasswordVerifier{}
			client, _ := newBlackBoxServerConfig(t, func(config *betterauth.Config) {
				verifier.delegate = config.Passwords
				config.Passwords = verifier
				config.User.DeleteUserEnabled = true
			})
			signup := client.request(t, http.MethodPost, "/sign-up/email", map[string]any{
				"email": "length@example.com", "password": lengthTestPassword, "name": "Length",
			}, false)
			if signup.Code != http.StatusOK {
				t.Fatalf("sign up: %d %s", signup.Code, signup.Body.String())
			}
			hashesBefore, verifiesBefore := verifier.calls()
			response := client.request(t, test.method, test.path, test.body, test.csrf)
			if response.Code != test.wantStatus {
				t.Fatalf("status %d, want %d: %s", response.Code, test.wantStatus, response.Body.String())
			}
			if got := decodePublicError(t, response.Body.Bytes()); got.Code != test.wantCode ||
				got.Message != test.wantMessage {
				t.Fatalf("error %#v, want %s %q", got, test.wantCode, test.wantMessage)
			}
			if hashes, verifies := verifier.calls(); hashes != hashesBefore || verifies != verifiesBefore {
				t.Fatalf("password work ran: hashes %d->%d verifies %d->%d",
					hashesBefore, hashes, verifiesBefore, verifies)
			}
		})
	}
}

func TestOverLongPasswordsCountTowardRateLimits(t *testing.T) {
	t.Parallel()
	tooLong := strings.Repeat("p", 129)
	limiter := &recordingRateLimiter{}
	client, _ := newBlackBoxServerConfig(t, func(config *betterauth.Config) {
		config.RateLimiter = limiter
	})
	signup := client.request(t, http.MethodPost, "/sign-up/email", map[string]any{
		"email": "limits@example.com", "password": lengthTestPassword, "name": "Limits",
	}, false)
	if signup.Code != http.StatusOK {
		t.Fatalf("sign up: %d %s", signup.Code, signup.Body.String())
	}

	signIn := client.request(t, http.MethodPost, "/sign-in/email", map[string]any{
		"email": "limits@example.com", "password": tooLong,
	}, false)
	if signIn.Code != http.StatusBadRequest || limiter.count("sign-in/email") != 1 {
		t.Fatalf("over-long sign-in was not rate limited: %d count=%d",
			signIn.Code, limiter.count("sign-in/email"))
	}
	change := client.request(t, http.MethodPost, "/change-password", map[string]any{
		"currentPassword": tooLong, "newPassword": "new password value",
	}, true)
	if change.Code != http.StatusBadRequest || limiter.count("change-password") != 1 {
		t.Fatalf("over-long change-password was not rate limited: %d count=%d",
			change.Code, limiter.count("change-password"))
	}

	limiter.setDeny(true)
	for _, request := range []struct {
		path string
		body map[string]any
		csrf bool
	}{
		{"/sign-in/email", map[string]any{"email": "limits@example.com", "password": tooLong}, false},
		{"/change-password", map[string]any{"currentPassword": tooLong, "newPassword": "new password value"}, true},
	} {
		response := client.request(t, http.MethodPost, request.path, request.body, request.csrf)
		if response.Code != http.StatusTooManyRequests {
			t.Fatalf("%s with a denied limiter: %d %s", request.path, response.Code, response.Body.String())
		}
	}
}

func TestVerifyPasswordRejectsOverLongPasswords(t *testing.T) {
	t.Parallel()
	delegate, err := betterauth.NewArgon2idVerifier(betterauth.Argon2Params{
		Memory: 19 * 1024, Iterations: 2, Parallelism: 1, SaltLength: 16, KeyLength: 32,
	}, 1024)
	if err != nil {
		t.Fatal(err)
	}
	verifier := &recordingPasswordVerifier{delegate: delegate}
	server, err := betterauth.New(betterauth.Config{
		PublicURL: "https://auth.example.com", TrustedOrigins: []string{"https://app.example.com"},
		Database: memory.New(), Mailer: &captureMailer{}, ImpersonationAuthorizer: allowImpersonation{},
		Clock:  fixedClock{now: time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)},
		Tokens: &sequenceTokens{}, Passwords: verifier,
	})
	if err != nil {
		t.Fatal(err)
	}
	client := &testClient{handler: server.Handler()}
	signup := client.request(t, http.MethodPost, "/sign-up/email", map[string]any{
		"email": "verify@example.com", "password": lengthTestPassword, "name": "Verify",
	}, false)
	if signup.Code != http.StatusOK {
		t.Fatalf("sign up: %d %s", signup.Code, signup.Body.String())
	}
	var created struct {
		User struct {
			ID string `json:"id"`
		} `json:"user"`
	}
	if err := json.Unmarshal(signup.Body.Bytes(), &created); err != nil || created.User.ID == "" {
		t.Fatalf("sign up body %s: %v", signup.Body.String(), err)
	}
	hashesBefore, verifiesBefore := verifier.calls()

	valid, err := server.VerifyPassword(t.Context(), created.User.ID, strings.Repeat("p", 129))
	var authErr *betterauth.Error
	if valid || !errors.As(err, &authErr) || authErr.Code != betterauth.CodePasswordTooLong ||
		authErr.Status != http.StatusBadRequest || authErr.Message != "Password too long" {
		t.Fatalf("VerifyPassword(over-long) = %v, %v", valid, err)
	}
	if hashes, verifies := verifier.calls(); hashes != hashesBefore || verifies != verifiesBefore {
		t.Fatalf("password work ran: hashes %d->%d verifies %d->%d",
			hashesBefore, hashes, verifiesBefore, verifies)
	}
	valid, err = server.VerifyPassword(t.Context(), created.User.ID, lengthTestPassword)
	if !valid || err != nil {
		t.Fatalf("VerifyPassword(correct) = %v, %v", valid, err)
	}
}
