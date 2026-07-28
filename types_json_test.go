package betterauth_test

import (
	"encoding/json"
	"testing"
	"time"

	betterauth "github.com/eadwinCode/better-auth-go"
)

func TestCoreTypesMarshalBetterAuthWireFields(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	userPayload, err := json.Marshal(betterauth.User{
		ID: "user-1", Email: "user@example.com", Name: "User",
		EmailVerified: true, CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	var user map[string]any
	if err := json.Unmarshal(userPayload, &user); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"id", "email", "name", "image", "emailVerified", "createdAt", "updatedAt"} {
		if _, exists := user[field]; !exists {
			t.Fatalf("user has no %s: %s", field, userPayload)
		}
	}
	if user["image"] != nil {
		t.Fatalf("empty image must be null: %s", userPayload)
	}
	for _, legacy := range []string{"image_url", "email_verified", "created_at", "updated_at"} {
		if _, exists := user[legacy]; exists {
			t.Fatalf("user exposed legacy field %s: %s", legacy, userPayload)
		}
	}

	sessionPayload, err := json.Marshal(betterauth.Session{
		ID: "session-1", UserID: "user-1", ExpiresAt: now.Add(time.Hour),
		CreatedAt: now, UpdatedAt: now, LastSeenAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	var session map[string]any
	if err := json.Unmarshal(sessionPayload, &session); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"id", "userId", "expiresAt", "createdAt", "updatedAt", "lastSeenAt"} {
		if _, exists := session[field]; !exists {
			t.Fatalf("session has no %s: %s", field, sessionPayload)
		}
	}
	for _, legacy := range []string{"user_id", "expires_at", "created_at", "updated_at", "last_seen_at"} {
		if _, exists := session[legacy]; exists {
			t.Fatalf("session exposed legacy field %s: %s", legacy, sessionPayload)
		}
	}
}
