package adaptertest

import (
	"context"
	"fmt"
	"testing"
	"time"

	betterauth "github.com/eadwinCode/better-auth-go"
)

// ReleaseUpgradeBaseline identifies the first adapter-bearing revision. The
// repository did not have semantic release tags when this fixture was added.
const ReleaseUpgradeBaseline = "ecf48ac"

// LegacyCoreSchema returns the frozen schema shape shipped at
// ReleaseUpgradeBaseline. That revision predates declarative non-unique and
// compound indexes but otherwise has the current core fields.
func LegacyCoreSchema() betterauth.Schema {
	schema := betterauth.CoreSchema()
	account := schema[betterauth.ModelAccount]
	delete(account.Fields, "issuer")
	schema[betterauth.ModelAccount] = account
	for modelName, model := range schema {
		model.Indexes = nil
		for fieldName, field := range model.Fields {
			field.Index = false
			model.Fields[fieldName] = field
		}
		schema[modelName] = model
	}
	return schema
}

// SeedReleaseBaseline stores representative data in every core model using
// only the schema available at ReleaseUpgradeBaseline.
func SeedReleaseBaseline(t *testing.T, database betterauth.DatabaseAdapter) {
	t.Helper()
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	records := []struct {
		model string
		data  betterauth.Record
	}{
		{betterauth.ModelUser, betterauth.Record{
			"id": "upgrade-user", "email": "upgrade@example.com", "emailVerified": true,
			"name": "Upgrade Fixture", "image": nil, "createdAt": now, "updatedAt": now,
			"disabledAt": nil,
		}},
		{betterauth.ModelSession, betterauth.Record{
			"id": "upgrade-session", "userId": "upgrade-user", "tokenHash": "upgrade-token-hash",
			"expiresAt": now.Add(24 * time.Hour), "createdAt": now, "updatedAt": now,
			"lastSeenAt": now, "revokedAt": nil, "impersonatedBy": nil, "impersonationId": nil,
		}},
		{betterauth.ModelAccount, betterauth.Record{
			"id": "upgrade-account", "userId": "upgrade-user", "providerId": "credential",
			"accountId": "upgrade-user", "password": "fixture-hash", "accessToken": nil,
			"refreshToken": nil, "idToken": nil, "accessTokenExpiresAt": nil,
			"refreshTokenExpiresAt": nil, "scope": nil, "createdAt": now, "updatedAt": now,
		}},
		{betterauth.ModelVerification, betterauth.Record{
			"id": "upgrade-verification", "identifier": "fixture", "value": "upgrade-value-hash",
			"expiresAt": now.Add(time.Hour), "createdAt": now,
			"metadata": `{"userId":"upgrade-user"}`,
		}},
		{betterauth.ModelAuditEvent, betterauth.Record{
			"id": "upgrade-audit", "schemaVersion": float64(1), "action": "fixture.upgrade",
			"actorUserId": "upgrade-user", "subjectUserId": "upgrade-user",
			"sessionId": "upgrade-session", "occurredAt": now,
			"request": `{"source":"release-upgrade"}`,
			"details": `{"baseline":"ecf48ac"}`,
		}},
		{betterauth.ModelOutboxEvent, betterauth.Record{
			"id": "upgrade-outbox", "schemaVersion": float64(1), "name": "fixture.upgraded",
			"aggregateId": "upgrade-user", "occurredAt": now,
			"payload": `{"baseline":"ecf48ac"}`, "publishedAt": nil,
		}},
	}
	for _, fixture := range records {
		if _, err := database.Create(t.Context(), betterauth.CreateQuery{
			Model: fixture.model, Data: fixture.data, ForceAllowID: true,
		}); err != nil {
			t.Fatalf("seed %s: %v", fixture.model, err)
		}
	}
}

// AssertReleaseUpgrade proves baseline data remains available through current
// indexed authentication queries and current mutations.
func AssertReleaseUpgrade(t *testing.T, database betterauth.DatabaseAdapter) {
	t.Helper()
	ctx := context.Background()
	for _, fixture := range []struct {
		model string
		id    string
	}{
		{betterauth.ModelUser, "upgrade-user"},
		{betterauth.ModelSession, "upgrade-session"},
		{betterauth.ModelAccount, "upgrade-account"},
		{betterauth.ModelVerification, "upgrade-verification"},
		{betterauth.ModelAuditEvent, "upgrade-audit"},
		{betterauth.ModelOutboxEvent, "upgrade-outbox"},
	} {
		record, err := database.FindOne(ctx, betterauth.FindOneQuery{
			Model: fixture.model, Where: []betterauth.Where{betterauth.Eq("id", fixture.id)},
		})
		if err != nil || record == nil {
			t.Fatalf("read upgraded %s: %#v, %v", fixture.model, record, err)
		}
	}
	session, err := database.FindOne(ctx, betterauth.FindOneQuery{
		Model: betterauth.ModelSession,
		Where: []betterauth.Where{
			betterauth.Eq("userId", "upgrade-user"),
			betterauth.Eq("tokenHash", "upgrade-token-hash"),
		},
	})
	if err != nil || session["id"] != "upgrade-session" {
		t.Fatalf("current session lookup after upgrade: %#v, %v", session, err)
	}
	updated, err := database.Update(ctx, betterauth.UpdateQuery{
		Model: betterauth.ModelAccount,
		Where: []betterauth.Where{
			betterauth.Eq("issuer", betterauth.CredentialAccountIssuer),
			betterauth.Eq("accountId", "upgrade-user"),
		},
		Update: betterauth.Record{
			"scope":     "upgraded",
			"updatedAt": time.Date(2026, 7, 28, 13, 0, 0, 0, time.UTC),
		},
	})
	if err != nil || fmt.Sprint(updated["scope"]) != "upgraded" {
		t.Fatalf("current account mutation after upgrade: %#v, %v", updated, err)
	}
}
