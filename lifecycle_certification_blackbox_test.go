package betterauth_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	betterauth "github.com/eadwinCode/better-auth-go"
)

type lifecycleLog struct {
	mu       sync.Mutex
	existing []betterauth.User
	before   []betterauth.User
	after    []betterauth.User
	reset    []betterauth.User
}

func (log *lifecycleLog) append(target *[]betterauth.User) betterauth.UserLifecycleHook {
	return func(_ context.Context, user betterauth.User) error {
		log.mu.Lock()
		defer log.mu.Unlock()
		*target = append(*target, user)
		return nil
	}
}

func TestEmailVerificationLifecycleOptions(t *testing.T) {
	t.Parallel()
	log := &lifecycleLog{}
	sendOnSignUp := false
	client, mailer := newBlackBoxServerConfig(t, func(config *betterauth.Config) {
		config.EmailPassword.RequireEmailVerification = true
		config.EmailPassword.OnExistingUserSignUp = log.append(&log.existing)
		config.EmailPassword.CustomSyntheticUser = func(input betterauth.SyntheticUserInput) betterauth.Record {
			return betterauth.Record{"id": input.ID, "role": "user", "banned": false}
		}
		config.EmailVerification.SendOnSignUp = &sendOnSignUp
		config.EmailVerification.SendOnSignIn = true
		config.EmailVerification.AutoSignInAfterVerification = true
		config.EmailVerification.BeforeVerification = log.append(&log.before)
		config.EmailVerification.AfterVerification = log.append(&log.after)
	})
	body := map[string]any{
		"email": "lifecycle@example.com", "password": "password", "name": "Lifecycle",
	}
	if response := client.request(t, http.MethodPost, "/sign-up/email", body, false); response.Code != http.StatusOK {
		t.Fatal(response.Body.String())
	}
	if mailer.count() != 0 {
		t.Fatal("sendOnSignUp=false sent verification mail")
	}
	duplicate := (&testClient{handler: client.handler, database: client.database}).request(
		t, http.MethodPost, "/sign-up/email", body, false,
	)
	if duplicate.Code != http.StatusOK {
		t.Fatal(duplicate.Body.String())
	}
	var synthetic struct {
		User map[string]any `json:"user"`
	}
	if err := json.Unmarshal(duplicate.Body.Bytes(), &synthetic); err != nil {
		t.Fatal(err)
	}
	if synthetic.User["role"] != "user" || synthetic.User["banned"] != false ||
		synthetic.User["email"] != "lifecycle@example.com" {
		t.Fatalf("custom synthetic user = %#v", synthetic.User)
	}
	log.mu.Lock()
	if len(log.existing) != 1 || log.existing[0].Email != "lifecycle@example.com" {
		t.Fatalf("existing-user hook = %#v", log.existing)
	}
	log.mu.Unlock()

	blocked := client.request(t, http.MethodPost, "/sign-in/email", map[string]any{
		"email": "lifecycle@example.com", "password": "password", "callbackURL": "/",
	}, false)
	if blocked.Code != http.StatusForbidden {
		t.Fatalf("sign-in status %d: %s", blocked.Code, blocked.Body.String())
	}
	message := mailer.last()
	if message.Kind != "email-verification" || message.Token == "" {
		t.Fatalf("sendOnSignIn message = %#v", message)
	}
	verified := client.request(
		t,
		http.MethodGet,
		"/verify-email?token="+url.QueryEscape(message.Token)+"&callbackURL=%2F",
		nil,
		false,
	)
	if verified.Code != http.StatusFound || verified.Header().Get("Location") != "/" {
		t.Fatalf("verification status %d location %q: %s", verified.Code, verified.Header().Get("Location"), verified.Body.String())
	}
	if client.session == nil || client.csrf == nil {
		t.Fatal("autoSignInAfterVerification did not issue session and CSRF cookies")
	}
	log.mu.Lock()
	defer log.mu.Unlock()
	if len(log.before) != 1 || log.before[0].EmailVerified {
		t.Fatalf("before-verification hook = %#v", log.before)
	}
	if len(log.after) != 1 || !log.after[0].EmailVerified {
		t.Fatalf("after-verification hook = %#v", log.after)
	}
}

func TestPasswordResetLifecycleHook(t *testing.T) {
	t.Parallel()
	log := &lifecycleLog{}
	client, mailer := newBlackBoxServerConfig(t, func(config *betterauth.Config) {
		config.EmailPassword.OnPasswordReset = log.append(&log.reset)
	})
	if response := client.request(t, http.MethodPost, "/sign-up/email", map[string]any{
		"email": "reset-hook@example.com", "password": "old-password", "name": "Reset",
	}, false); response.Code != http.StatusOK {
		t.Fatal(response.Body.String())
	}
	client.request(t, http.MethodPost, "/forget-password", map[string]any{
		"email": "reset-hook@example.com",
	}, false)
	reset := (&testClient{handler: client.handler, database: client.database}).request(
		t, http.MethodPost, "/reset-password", map[string]any{
			"token": mailer.last().Token, "newPassword": "new-password",
		}, false,
	)
	if reset.Code != http.StatusOK {
		t.Fatalf("reset status %d: %s", reset.Code, reset.Body.String())
	}
	log.mu.Lock()
	defer log.mu.Unlock()
	if len(log.reset) != 1 || log.reset[0].Email != "reset-hook@example.com" {
		t.Fatalf("password-reset hook = %#v", log.reset)
	}
}

func TestChangeEmailConfirmationAndUnverifiedUpdateModes(t *testing.T) {
	t.Parallel()
	t.Run("old inbox confirmation", func(t *testing.T) {
		client, mailer := newBlackBoxServerConfig(t, func(config *betterauth.Config) {
			config.User.ChangeEmailEnabled = true
			config.User.SendChangeEmailConfirmation = true
		})
		if response := client.request(t, http.MethodPost, "/sign-up/email", map[string]any{
			"email": "old@example.com", "password": "password", "name": "Old",
		}, false); response.Code != http.StatusOK {
			t.Fatal(response.Body.String())
		}
		client.request(t, http.MethodPost, "/send-verification-email", map[string]any{
			"email": "old@example.com",
		}, false)
		verify := mailer.last()
		if response := client.request(
			t, http.MethodGet, "/verify-email?token="+url.QueryEscape(verify.Token), nil, false,
		); response.Code != http.StatusOK {
			t.Fatal(response.Body.String())
		}
		change := client.request(t, http.MethodPost, "/change-email", map[string]any{
			"newEmail": "new@example.com", "callbackURL": "/",
		}, true)
		if change.Code != http.StatusOK {
			t.Fatalf("change status %d: %s", change.Code, change.Body.String())
		}
		confirmation := mailer.last()
		if confirmation.Kind != "email-change-confirmation" || confirmation.To != "old@example.com" {
			t.Fatalf("confirmation message = %#v", confirmation)
		}
		first := client.request(
			t, http.MethodGet, "/verify-email?token="+url.QueryEscape(confirmation.Token), nil, false,
		)
		if first.Code != http.StatusFound || first.Header().Get("Location") != "/" {
			t.Fatalf("confirmation status %d location %q: %s", first.Code, first.Header().Get("Location"), first.Body.String())
		}
		newInbox := mailer.last()
		if newInbox.Kind != "email-change" || newInbox.To != "new@example.com" {
			t.Fatalf("new-inbox message = %#v", newInbox)
		}
		second := client.request(
			t, http.MethodGet, "/verify-email?token="+url.QueryEscape(newInbox.Token), nil, false,
		)
		if second.Code != http.StatusFound || second.Header().Get("Location") != "/" {
			t.Fatalf("new-inbox status %d location %q: %s", second.Code, second.Header().Get("Location"), second.Body.String())
		}
		session := client.request(t, http.MethodGet, "/get-session", nil, false)
		if got := session.Body.String(); !containsAll(got, `"email":"new@example.com"`, `"emailVerified":true`) {
			t.Fatalf("updated session = %s", got)
		}
	})

	t.Run("unverified immediate update", func(t *testing.T) {
		client, mailer := newBlackBoxServerConfig(t, func(config *betterauth.Config) {
			config.User.ChangeEmailEnabled = true
			config.User.UpdateEmailWithoutVerification = true
		})
		client.request(t, http.MethodPost, "/sign-up/email", map[string]any{
			"email": "pending-old@example.com", "password": "password", "name": "Pending",
		}, false)
		change := client.request(t, http.MethodPost, "/change-email", map[string]any{
			"newEmail": "pending-new@example.com",
		}, true)
		if change.Code != http.StatusOK {
			t.Fatalf("change status %d: %s", change.Code, change.Body.String())
		}
		if message := mailer.last(); message.Kind != "email-verification" || message.To != "pending-new@example.com" {
			t.Fatalf("verification message = %#v", message)
		}
		session := client.request(t, http.MethodGet, "/get-session", nil, false)
		if got := session.Body.String(); !containsAll(got, `"email":"pending-new@example.com"`, `"emailVerified":false`) {
			t.Fatalf("updated session = %s", got)
		}
	})
}

func containsAll(value string, needles ...string) bool {
	for _, needle := range needles {
		if !strings.Contains(value, needle) {
			return false
		}
	}
	return true
}
