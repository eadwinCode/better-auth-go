package betterauth_test

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	betterauth "github.com/eadwinCode/better-auth-go"
)

type deletionHookLog struct {
	mu     sync.Mutex
	events []string
}

func (log *deletionHookLog) append(event string) {
	log.mu.Lock()
	defer log.mu.Unlock()
	log.events = append(log.events, event)
}

func (log *deletionHookLog) snapshot() []string {
	log.mu.Lock()
	defer log.mu.Unlock()
	return append([]string(nil), log.events...)
}

func TestVerifiedAccountDeletionIsHashedHookedAndRedirected(t *testing.T) {
	t.Parallel()
	const callbackURL = "https://app.example.com/account-deleted"
	clock := &stepClock{now: time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)}
	hooks := &deletionHookLog{}
	client, mailer := newBlackBoxServerConfig(t, func(config *betterauth.Config) {
		config.Clock = clock
		config.AllowedRedirectURLs = []string{callbackURL}
		config.User.DeleteUserEnabled = true
		config.User.SendDeleteAccountVerification = true
		config.DeleteUserTTL = 2 * time.Hour
		config.User.BeforeDelete = func(_ context.Context, user betterauth.User) error {
			hooks.append("before:" + user.Email)
			return nil
		}
		config.User.AfterDelete = func(_ context.Context, user betterauth.User) error {
			hooks.append("after:" + user.Email)
			return nil
		}
	})
	if response := client.request(t, http.MethodPost, "/sign-up/email", map[string]any{
		"email":    "verified-delete@example.com",
		"password": "correct horse battery staple",
		"name":     "Verified Delete",
	}, false); response.Code != http.StatusOK {
		t.Fatal(response.Body.String())
	}

	clock.now = clock.now.Add(2 * time.Minute)
	request := client.request(t, http.MethodPost, "/delete-user", map[string]any{
		"callbackURL": callbackURL,
	}, true)
	if request.Code != http.StatusOK ||
		!bytes.Contains(request.Body.Bytes(), []byte(`"message":"Verification email sent"`)) {
		t.Fatalf("delete verification request: %d %s", request.Code, request.Body.String())
	}
	if session := client.request(t, http.MethodGet, "/get-session", nil, false); session.Code != http.StatusOK || session.Body.String() == "null\n" {
		t.Fatalf("verification request deleted the user: %d %s", session.Code, session.Body.String())
	}

	message := mailer.last()
	if message.Kind != "account-deletion" ||
		message.To != "verified-delete@example.com" ||
		!message.ExpiresAt.Equal(clock.now.Add(2*time.Hour)) {
		t.Fatalf("unexpected deletion mail: %#v", message)
	}
	action, err := url.Parse(message.ActionURL)
	if err != nil {
		t.Fatal(err)
	}
	if action.Path != "/api/auth/delete-user/callback" ||
		action.Query().Get("token") != message.Token ||
		action.Query().Get("callbackURL") != callbackURL {
		t.Fatalf("unexpected deletion URL: %s", action)
	}

	rows, err := client.database.FindMany(context.Background(), betterauth.FindManyQuery{
		Model: betterauth.ModelVerification,
		Where: []betterauth.Where{
			betterauth.Eq("identifier", string(betterauth.PurposeUserDeletion)),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0]["value"] != betterauth.HashToken(message.Token) ||
		strings.Contains(stringRecord(rows[0]), message.Token) {
		t.Fatalf("deletion token was not hash-at-rest: %#v", rows)
	}

	callbackPath := strings.TrimPrefix(action.Path, "/api/auth") + "?" + action.RawQuery
	callback := client.request(t, http.MethodGet, callbackPath, nil, false)
	if callback.Code != http.StatusFound || callback.Header().Get("Location") != callbackURL {
		t.Fatalf("delete callback: %d location=%q body=%s",
			callback.Code, callback.Header().Get("Location"), callback.Body.String())
	}
	if events := hooks.snapshot(); len(events) != 2 ||
		events[0] != "before:verified-delete@example.com" ||
		events[1] != "after:verified-delete@example.com" {
		t.Fatalf("unexpected deletion hook order: %#v", events)
	}
	if session := client.request(t, http.MethodGet, "/get-session", nil, false); session.Code != http.StatusOK || session.Body.String() != "null\n" {
		t.Fatalf("deleted session remained active: %d %s", session.Code, session.Body.String())
	}
}

func TestDeletionTokenWrongOwnerIsBurned(t *testing.T) {
	t.Parallel()
	owner, mailer := newBlackBoxServerConfig(t, func(config *betterauth.Config) {
		config.User.DeleteUserEnabled = true
		config.User.SendDeleteAccountVerification = true
	})
	attacker := &testClient{handler: owner.handler, database: owner.database}
	if response := owner.request(t, http.MethodPost, "/sign-up/email", map[string]any{
		"email": "delete-owner@example.com", "password": "correct horse battery staple", "name": "Owner",
	}, false); response.Code != http.StatusOK {
		t.Fatal(response.Body.String())
	}
	if response := attacker.request(t, http.MethodPost, "/sign-up/email", map[string]any{
		"email": "delete-attacker@example.com", "password": "correct horse battery staple", "name": "Attacker",
	}, false); response.Code != http.StatusOK {
		t.Fatal(response.Body.String())
	}
	if response := owner.request(
		t, http.MethodPost, "/delete-user", map[string]any{}, true,
	); response.Code != http.StatusOK {
		t.Fatal(response.Body.String())
	}
	token := url.QueryEscape(mailer.last().Token)
	wrongOwner := attacker.request(
		t, http.MethodGet, "/delete-user/callback?token="+token, nil, false,
	)
	if wrongOwner.Code != http.StatusNotFound ||
		!bytes.Contains(wrongOwner.Body.Bytes(), []byte(`"code":"INVALID_TOKEN"`)) {
		t.Fatalf("wrong-owner callback: %d %s", wrongOwner.Code, wrongOwner.Body.String())
	}
	retry := owner.request(t, http.MethodGet, "/delete-user/callback?token="+token, nil, false)
	if retry.Code != http.StatusNotFound ||
		!bytes.Contains(retry.Body.Bytes(), []byte(`"code":"INVALID_TOKEN"`)) {
		t.Fatalf("wrong-owner token was not burned: %d %s", retry.Code, retry.Body.String())
	}
	for _, client := range []*testClient{owner, attacker} {
		if session := client.request(t, http.MethodGet, "/get-session", nil, false); session.Body.String() == "null\n" {
			t.Fatal("wrong-owner callback deleted an account")
		}
	}
}

func TestDeletionTokenConcurrentReplayHasOneSuccess(t *testing.T) {
	t.Parallel()
	client, mailer := newBlackBoxServerConfig(t, func(config *betterauth.Config) {
		config.User.DeleteUserEnabled = true
		config.User.SendDeleteAccountVerification = true
	})
	if response := client.request(t, http.MethodPost, "/sign-up/email", map[string]any{
		"email": "delete-race@example.com", "password": "correct horse battery staple", "name": "Race",
	}, false); response.Code != http.StatusOK {
		t.Fatal(response.Body.String())
	}
	if response := client.request(
		t, http.MethodPost, "/delete-user", map[string]any{}, true,
	); response.Code != http.StatusOK {
		t.Fatal(response.Body.String())
	}

	sessionOne := *client.session
	sessionTwo := *client.session
	clients := []*testClient{
		{handler: client.handler, database: client.database, session: &sessionOne},
		{handler: client.handler, database: client.database, session: &sessionTwo},
	}
	path := "/delete-user/callback?token=" + url.QueryEscape(mailer.last().Token)
	statuses := make(chan int, len(clients))
	var wait sync.WaitGroup
	for _, replayClient := range clients {
		wait.Add(1)
		go func() {
			defer wait.Done()
			statuses <- replayClient.request(t, http.MethodGet, path, nil, false).Code
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
		t.Fatalf("concurrent deletion successes=%d, want exactly one", successes)
	}
}

func TestDeletionVerificationExpiryBeforeHookAndPasswordFreshness(t *testing.T) {
	t.Parallel()
	clock := &stepClock{now: time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)}
	hookErr := betterauth.NewError(
		betterauth.CodeForbidden,
		"Deletion blocked.",
		http.StatusForbidden,
		errors.New("policy denied"),
	)
	client, mailer := newBlackBoxServerConfig(t, func(config *betterauth.Config) {
		config.Clock = clock
		config.User.DeleteUserEnabled = true
		config.User.SendDeleteAccountVerification = true
		config.DeleteUserTTL = time.Minute
		config.SessionFreshAge = time.Minute
		config.User.BeforeDelete = func(context.Context, betterauth.User) error {
			return hookErr
		}
	})
	if response := client.request(t, http.MethodPost, "/sign-up/email", map[string]any{
		"email": "expired-delete@example.com", "password": "correct horse battery staple", "name": "Expiry",
	}, false); response.Code != http.StatusOK {
		t.Fatal(response.Body.String())
	}
	clock.now = clock.now.Add(2 * time.Minute)
	if response := client.request(
		t, http.MethodPost, "/delete-user", map[string]any{}, true,
	); response.Code != http.StatusOK {
		t.Fatalf("stale session could not request verification: %d %s",
			response.Code, response.Body.String())
	}
	clock.now = clock.now.Add(2 * time.Minute)
	expired := client.request(
		t,
		http.MethodGet,
		"/delete-user/callback?token="+url.QueryEscape(mailer.last().Token),
		nil,
		false,
	)
	if expired.Code != http.StatusNotFound {
		t.Fatalf("expired deletion token status=%d body=%s", expired.Code, expired.Body.String())
	}

	if response := client.request(
		t, http.MethodPost, "/delete-user", map[string]any{}, true,
	); response.Code != http.StatusOK {
		t.Fatal(response.Body.String())
	}
	blocked := client.request(
		t,
		http.MethodGet,
		"/delete-user/callback?token="+url.QueryEscape(mailer.last().Token),
		nil,
		false,
	)
	if blocked.Code != http.StatusForbidden ||
		!bytes.Contains(blocked.Body.Bytes(), []byte(`"message":"Deletion blocked."`)) {
		t.Fatalf("before-delete hook did not stop deletion: %d %s", blocked.Code, blocked.Body.String())
	}
	if retry := client.request(
		t,
		http.MethodGet,
		"/delete-user/callback?token="+url.QueryEscape(mailer.last().Token),
		nil,
		false,
	); retry.Code != http.StatusNotFound {
		t.Fatalf("blocked deletion token was not consumed: %d %s", retry.Code, retry.Body.String())
	}

	direct, _ := newBlackBoxServerConfig(t, func(config *betterauth.Config) {
		config.Clock = clock
		config.User.DeleteUserEnabled = true
		config.SessionFreshAge = time.Minute
	})
	if response := direct.request(t, http.MethodPost, "/sign-up/email", map[string]any{
		"email": "password-delete@example.com", "password": "correct horse battery staple", "name": "Password",
	}, false); response.Code != http.StatusOK {
		t.Fatal(response.Body.String())
	}
	clock.now = clock.now.Add(2 * time.Minute)
	if response := direct.request(t, http.MethodPost, "/delete-user", map[string]any{
		"password": "correct horse battery staple",
	}, true); response.Code != http.StatusOK {
		t.Fatalf("password-authorized stale deletion: %d %s", response.Code, response.Body.String())
	}
}

func stringRecord(record betterauth.Record) string {
	var builder strings.Builder
	for key, value := range record {
		builder.WriteString(key)
		builder.WriteString("=")
		builder.WriteString(strings.TrimSpace(toString(value)))
		builder.WriteString(";")
	}
	return builder.String()
}

func toString(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	default:
		return ""
	}
}
