package betterauth_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	betterauth "github.com/eadwinCode/better-auth-go"
)

func TestCoreUserAccountAndPasswordManagement(t *testing.T) {
	t.Parallel()
	client, _ := newBlackBoxServer(t)
	signup := client.request(t, http.MethodPost, "/sign-up/email", map[string]any{
		"email": "manage@example.com", "password": "correct horse battery staple", "name": "Before",
	}, false)
	if signup.Code != http.StatusOK {
		t.Fatal(signup.Body.String())
	}
	update := client.request(t, http.MethodPost, "/update-user", map[string]any{
		"name": "After", "image": "https://images.example.com/avatar.png",
	}, true)
	if update.Code != http.StatusOK || !bytes.Contains(update.Body.Bytes(), []byte(`"status":true`)) {
		t.Fatalf("update-user: %d %s", update.Code, update.Body.String())
	}
	updatedSession := client.request(t, http.MethodGet, "/get-session", nil, false)
	if !bytes.Contains(updatedSession.Body.Bytes(), []byte(`"name":"After"`)) ||
		!bytes.Contains(updatedSession.Body.Bytes(), []byte(`"image":"https://images.example.com/avatar.png"`)) {
		t.Fatalf("updated user was not observable through the session: %s", updatedSession.Body.String())
	}
	forbidden := client.request(t, http.MethodPost, "/update-user", map[string]any{
		"email": "takeover@example.com",
	}, true)
	if forbidden.Code != http.StatusBadRequest {
		t.Fatalf("security field was writable: %d %s", forbidden.Code, forbidden.Body.String())
	}
	accounts := client.request(t, http.MethodGet, "/list-accounts", nil, false)
	if accounts.Code != http.StatusOK ||
		!bytes.Contains(accounts.Body.Bytes(), []byte(`"providerId":"credential"`)) ||
		bytes.Contains(accounts.Body.Bytes(), []byte("password")) ||
		bytes.Contains(accounts.Body.Bytes(), []byte("accessToken")) {
		t.Fatalf("account list leaked credentials: %d %s", accounts.Code, accounts.Body.String())
	}
	unlink := client.request(t, http.MethodPost, "/unlink-account", map[string]any{
		"providerId": "credential",
	}, true)
	if unlink.Code != http.StatusConflict {
		t.Fatalf("last account unlink was not blocked: %d %s", unlink.Code, unlink.Body.String())
	}
	oldSession := client.session.Value
	change := client.request(t, http.MethodPost, "/change-password", map[string]any{
		"currentPassword": "correct horse battery staple",
		"newPassword":     "new correct horse battery staple",
	}, true)
	if change.Code != http.StatusOK {
		t.Fatalf("change-password: %d %s", change.Code, change.Body.String())
	}
	if client.session.Value == oldSession {
		t.Fatal("password change did not rotate the session")
	}
	other := &testClient{handler: client.handler, database: client.database}
	oldPassword := other.request(t, http.MethodPost, "/sign-in/email", map[string]any{
		"email": "manage@example.com", "password": "correct horse battery staple",
	}, false)
	if oldPassword.Code != http.StatusUnauthorized {
		t.Fatalf("old password remained valid: %d %s", oldPassword.Code, oldPassword.Body.String())
	}
	newPassword := other.request(t, http.MethodPost, "/sign-in/email", map[string]any{
		"email": "manage@example.com", "password": "new correct horse battery staple",
	}, false)
	if newPassword.Code != http.StatusOK {
		t.Fatalf("new password was rejected: %d %s", newPassword.Code, newPassword.Body.String())
	}
}

func TestSessionManagementUsesOwnedSessionIDs(t *testing.T) {
	t.Parallel()
	first, _ := newBlackBoxServer(t)
	signup := first.request(t, http.MethodPost, "/sign-up/email", map[string]any{
		"email": "sessions@example.com", "password": "correct horse battery staple", "name": "Sessions",
	}, false)
	if signup.Code != http.StatusOK {
		t.Fatal(signup.Body.String())
	}
	second := &testClient{handler: first.handler, database: first.database}
	signin := second.request(t, http.MethodPost, "/sign-in/email", map[string]any{
		"email": "sessions@example.com", "password": "correct horse battery staple",
	}, false)
	if signin.Code != http.StatusOK {
		t.Fatal(signin.Body.String())
	}
	list := first.request(t, http.MethodGet, "/list-sessions", nil, false)
	if list.Code != http.StatusOK ||
		bytes.Contains(list.Body.Bytes(), []byte(`"token"`)) ||
		bytes.Contains(list.Body.Bytes(), []byte(`"tokenHash"`)) {
		t.Fatalf("invalid session list: %d %s", list.Code, list.Body.String())
	}
	var sessions []struct {
		ID      string `json:"id"`
		Current bool   `json:"current"`
	}
	if err := json.Unmarshal(list.Body.Bytes(), &sessions); err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 2 {
		t.Fatalf("expected two sessions, got %#v", sessions)
	}
	var otherID string
	for _, session := range sessions {
		if !session.Current {
			otherID = session.ID
		}
	}
	revoke := first.request(t, http.MethodPost, "/revoke-session", map[string]any{
		"sessionId": otherID,
	}, true)
	if revoke.Code != http.StatusOK || !bytes.Contains(revoke.Body.Bytes(), []byte(`"status":true`)) {
		t.Fatalf("revoke-session: %d %s", revoke.Code, revoke.Body.String())
	}
	stale := second.request(t, http.MethodGet, "/get-session", nil, false)
	if stale.Code != http.StatusOK || stale.Body.String() != "null\n" {
		t.Fatalf("revoked session remained valid: %d %s", stale.Code, stale.Body.String())
	}
	revokeAll := first.request(t, http.MethodPost, "/revoke-sessions", map[string]any{}, true)
	if revokeAll.Code != http.StatusOK || !bytes.Contains(revokeAll.Body.Bytes(), []byte(`"status":true`)) {
		t.Fatalf("revoke-sessions: %d %s", revokeAll.Code, revokeAll.Body.String())
	}
}

func TestSessionRevocationCannotCrossUsers(t *testing.T) {
	t.Parallel()
	first, _ := newBlackBoxServer(t)
	second := &testClient{handler: first.handler, database: first.database}
	if response := first.request(t, http.MethodPost, "/sign-up/email", map[string]any{
		"email": "first@example.com", "password": "correct horse battery staple", "name": "First",
	}, false); response.Code != http.StatusOK {
		t.Fatal(response.Body.String())
	}
	if response := second.request(t, http.MethodPost, "/sign-up/email", map[string]any{
		"email": "second@example.com", "password": "correct horse battery staple", "name": "Second",
	}, false); response.Code != http.StatusOK {
		t.Fatal(response.Body.String())
	}
	list := second.request(t, http.MethodGet, "/list-sessions", nil, false)
	var sessions []struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(list.Body.Bytes(), &sessions); err != nil {
		t.Fatal(err)
	}
	response := first.request(t, http.MethodPost, "/revoke-session", map[string]any{
		"sessionId": sessions[0].ID,
	}, true)
	if response.Code != http.StatusOK {
		t.Fatal(response.Body.String())
	}
	stillValid := second.request(t, http.MethodGet, "/get-session", nil, false)
	if stillValid.Code != http.StatusOK || stillValid.Body.String() == "null\n" {
		t.Fatal("one user revoked another user's session")
	}
}

func TestVerifiedEmailChangeAndUserDeletion(t *testing.T) {
	t.Parallel()
	client, mailer := newBlackBoxServerConfig(t, func(config *betterauth.Config) {
		config.AllowedRedirectURLs = []string{"https://app.example.com/settings"}
		config.User.ChangeEmailEnabled = true
		config.User.DeleteUserEnabled = true
	})
	signup := client.request(t, http.MethodPost, "/sign-up/email", map[string]any{
		"email": "original@example.com", "password": "correct horse battery staple", "name": "Lifecycle",
	}, false)
	if signup.Code != http.StatusOK {
		t.Fatal(signup.Body.String())
	}
	change := client.request(t, http.MethodPost, "/change-email", map[string]any{
		"newEmail": "changed@example.com", "callbackURL": "https://app.example.com/settings",
	}, true)
	if change.Code != http.StatusOK {
		t.Fatalf("change-email: %d %s", change.Code, change.Body.String())
	}
	message := mailer.last()
	if message.To != "changed@example.com" || message.Kind != "email-change" {
		t.Fatalf("unexpected email-change message: %#v", message)
	}
	verify := client.request(
		t, http.MethodGet, "/verify-email?token="+url.QueryEscape(message.Token), nil, false,
	)
	if verify.Code != http.StatusFound || verify.Header().Get("Location") != "https://app.example.com/settings" {
		t.Fatalf("verify email change: %d %s", verify.Code, verify.Body.String())
	}
	session := client.request(t, http.MethodGet, "/get-session", nil, false)
	if !bytes.Contains(session.Body.Bytes(), []byte(`"email":"changed@example.com"`)) ||
		!bytes.Contains(session.Body.Bytes(), []byte(`"emailVerified":true`)) {
		t.Fatalf("email change was not persisted: %s", session.Body.String())
	}
	wrong := client.request(t, http.MethodPost, "/delete-user", map[string]any{
		"password": "wrong password",
	}, true)
	if wrong.Code != http.StatusUnauthorized {
		t.Fatalf("delete accepted wrong password: %d %s", wrong.Code, wrong.Body.String())
	}
	deleted := client.request(t, http.MethodPost, "/delete-user", map[string]any{
		"password": "correct horse battery staple",
	}, true)
	if deleted.Code != http.StatusOK {
		t.Fatalf("delete-user: %d %s", deleted.Code, deleted.Body.String())
	}
	session = client.request(t, http.MethodGet, "/get-session", nil, false)
	if session.Body.String() != "null\n" {
		t.Fatalf("deleted user session remained valid: %s", session.Body.String())
	}
}
