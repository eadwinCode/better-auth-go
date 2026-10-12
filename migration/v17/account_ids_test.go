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

func seedAccounts(t *testing.T, db betterauth.DatabaseAdapter, rows ...betterauth.Record) {
	t.Helper()
	now := time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC)
	for _, row := range rows {
		row["createdAt"], row["updatedAt"] = now, now
		if _, err := db.Create(t.Context(), betterauth.CreateQuery{
			Model: betterauth.ModelAccount, Data: row, ForceAllowID: true,
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func accountID(t *testing.T, db betterauth.DatabaseAdapter, id string) any {
	t.Helper()
	row, err := db.FindOne(t.Context(), betterauth.FindOneQuery{
		Model: betterauth.ModelAccount, Where: []betterauth.Where{betterauth.Eq("id", id)},
	})
	if err != nil || row == nil {
		t.Fatalf("find %s: %#v, %v", id, row, err)
	}
	return row["accountId"]
}

func TestRewriteAccountIDsMovesMicrosoftSubjectsToOID(t *testing.T) {
	db := memory.New()
	seedAccounts(t, db,
		betterauth.Record{"id": "ms", "userId": "user-a", "providerId": "microsoft", "accountId": "old-sub"},
		betterauth.Record{"id": "gh", "userId": "user-a", "providerId": "github", "accountId": "42"},
	)
	report, err := v17.RewriteAccountIDs(t.Context(), db, v17.Options{Resolve: func(
		_ context.Context, row betterauth.Record,
	) (string, error) {
		if row["providerId"] == "microsoft" {
			return "verified-oid", nil
		}
		return "", nil
	}})
	if err != nil || report.Scanned != 2 || report.Updated != 1 {
		t.Fatalf("rewrite = %#v, %v", report, err)
	}
	if accountID(t, db, "ms") != "verified-oid" || accountID(t, db, "gh") != "42" {
		t.Fatal("account IDs were not rewritten as planned")
	}
}

func TestRewriteAccountIDsIsAllOrNothingOnCollision(t *testing.T) {
	db := memory.New()
	seedAccounts(t, db,
		betterauth.Record{"id": "a", "userId": "user-a", "providerId": "microsoft", "accountId": "sub-a"},
		betterauth.Record{"id": "b", "userId": "user-b", "providerId": "microsoft", "accountId": "sub-b"},
	)
	report, err := v17.RewriteAccountIDs(t.Context(), db, v17.Options{Resolve: func(
		context.Context, betterauth.Record,
	) (string, error) {
		return "same-oid", nil
	}})
	if err == nil || len(report.Collisions) != 1 || report.Updated != 0 {
		t.Fatalf("collision was not rejected before writes: %#v, %v", report, err)
	}
	if accountID(t, db, "a") != "sub-a" || accountID(t, db, "b") != "sub-b" {
		t.Fatal("collision left a partial rewrite")
	}
}

func TestRewriteAccountIDsRejectsResolverFailure(t *testing.T) {
	db := memory.New()
	seedAccounts(t, db, betterauth.Record{
		"id": "ms", "userId": "user", "providerId": "microsoft", "accountId": "old-sub",
	})
	_, err := v17.RewriteAccountIDs(t.Context(), db, v17.Options{Resolve: func(
		context.Context, betterauth.Record,
	) (string, error) {
		return "", errors.New("trusted export missing")
	}})
	if err == nil {
		t.Fatal("resolver failure was accepted")
	}
	if _, err = v17.RewriteAccountIDs(t.Context(), db, v17.Options{}); err == nil {
		t.Fatal("missing resolver was accepted")
	}
	if accountID(t, db, "ms") != "old-sub" {
		t.Fatal("failed rewrite changed data")
	}
}
