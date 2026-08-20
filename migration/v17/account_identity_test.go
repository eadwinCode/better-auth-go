package v17_test

import (
	"context"
	"errors"
	"testing"
	"time"

	betterauth "github.com/eadwinCode/better-auth-go"
	"github.com/eadwinCode/better-auth-go/adapter/memory"
	v17 "github.com/eadwinCode/better-auth-go/migration/v17"
)

func TestBackfillIsAllOrNothingOnIssuerSubjectCollision(t *testing.T) {
	db := memory.New()
	now := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)
	for _, fixture := range []betterauth.Record{
		{"id": "a", "userId": "user-a", "providerId": "alias-a", "accountId": "subject", "createdAt": now},
		{"id": "b", "userId": "user-b", "providerId": "alias-b", "accountId": "subject", "createdAt": now.Add(time.Second)},
	} {
		if _, err := db.Create(t.Context(), betterauth.CreateQuery{
			Model: betterauth.ModelAccount, Data: fixture, ForceAllowID: true,
		}); err != nil {
			t.Fatal(err)
		}
	}
	report, err := v17.Backfill(t.Context(), db, v17.Options{ProviderIssuers: map[string]string{
		"alias-a": "https://issuer.example", "alias-b": "https://issuer.example",
	}})
	if err == nil || len(report.Collisions) != 1 || report.Updated != 0 {
		t.Fatalf("collision was not rejected before writes: %#v, %v", report, err)
	}
	for _, id := range []string{"a", "b"} {
		row, findErr := db.FindOne(t.Context(), betterauth.FindOneQuery{
			Model: betterauth.ModelAccount, Where: []betterauth.Where{betterauth.Eq("id", id)},
		})
		if findErr != nil || row["issuer"] != nil {
			t.Fatalf("partial backfill for %s: %#v, %v", id, row, findErr)
		}
	}
}

func TestBackfillRequiresReviewedProviderMappingAndMigratesCredentials(t *testing.T) {
	db := memory.New()
	now := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)
	_, _ = db.Create(t.Context(), betterauth.CreateQuery{Model: betterauth.ModelAccount,
		ForceAllowID: true, Data: betterauth.Record{
			"id": "credential", "userId": "user", "providerId": "credential",
			"accountId": "legacy-email@example.com", "createdAt": now,
		}})
	_, _ = db.Create(t.Context(), betterauth.CreateQuery{Model: betterauth.ModelAccount,
		ForceAllowID: true, Data: betterauth.Record{
			"id": "oauth", "userId": "user", "providerId": "custom",
			"accountId": "subject", "createdAt": now.Add(time.Second),
		}})
	if _, err := v17.Backfill(t.Context(), db, v17.Options{}); err == nil {
		t.Fatal("unreviewed provider mapping was accepted")
	}
	report, err := v17.Backfill(t.Context(), db, v17.Options{
		ProviderIssuers: map[string]string{"custom": "local:oauth:custom"},
	})
	if err != nil || report.Updated != 2 {
		t.Fatalf("backfill = %#v, %v", report, err)
	}
	credential, _ := db.FindOne(t.Context(), betterauth.FindOneQuery{
		Model: betterauth.ModelAccount, Where: []betterauth.Where{betterauth.Eq("id", "credential")},
	})
	if credential["issuer"] != betterauth.CredentialAccountIssuer || credential["accountId"] != "user" {
		t.Fatalf("credential identity = %#v", credential)
	}
}

func TestBackfillRollsBackResolverFailure(t *testing.T) {
	db := memory.New()
	_, _ = db.Create(t.Context(), betterauth.CreateQuery{Model: betterauth.ModelAccount,
		ForceAllowID: true, Data: betterauth.Record{
			"id": "microsoft", "userId": "user", "providerId": "microsoft",
			"accountId": "old-sub", "createdAt": time.Now().UTC(),
		}})
	_, err := v17.Backfill(t.Context(), db, v17.Options{Resolve: func(
		_ context.Context, _ betterauth.Record,
	) (v17.AccountIdentity, error) {
		return v17.AccountIdentity{}, errors.New("trusted export missing")
	}})
	if err == nil {
		t.Fatal("resolver failure was accepted")
	}
}

func TestOAuthAccountIssuerPercentEncodesNamespaceBoundaries(t *testing.T) {
	issuer, err := betterauth.OAuthAccountIssuer("tenant/provider:日本")
	if err != nil {
		t.Fatal(err)
	}
	if issuer != "local:oauth:tenant%2Fprovider%3A%E6%97%A5%E6%9C%AC" {
		t.Fatalf("issuer = %q", issuer)
	}
}
