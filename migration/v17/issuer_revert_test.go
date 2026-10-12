package v17_test

import (
	"context"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	betterauth "github.com/eadwinCode/better-auth-go"
	"github.com/eadwinCode/better-auth-go/adapter/sqladapter"
	sqliteadapter "github.com/eadwinCode/better-auth-go/adapter/sqlite"
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

//go:embed issuer_revert_sqlite.sql
var sqliteIssuerRevert string

//go:embed issuer_revert_postgresql.sql
var postgresqlIssuerRevert string

// mainIssuerSchema is the account schema that unreleased main shipped: a
// required issuer column and a unique (issuer, accountId) index.
func mainIssuerSchema() betterauth.Schema {
	schema := betterauth.CoreSchema()
	account := schema[betterauth.ModelAccount]
	account.Fields["issuer"] = betterauth.FieldSchema{Type: betterauth.FieldString, Required: true}
	account.Indexes = []betterauth.IndexSchema{{
		Name: "account_issuer_accountId_uidx", Fields: []string{"issuer", "accountId"}, Unique: true,
	}}
	schema[betterauth.ModelAccount] = account
	return schema
}

func mainAccountRow(id, user, provider, issuer, accountID string) betterauth.Record {
	now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	return betterauth.Record{
		"id": id, "userId": user, "providerId": provider, "issuer": issuer,
		"accountId": accountID, "createdAt": now, "updatedAt": now,
	}
}

func openMainBuiltSQLite(t *testing.T, rows ...betterauth.Record) (*sql.DB, *sqladapter.Adapter) {
	t.Helper()
	database, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "main.db"))
	if err != nil {
		t.Fatal(err)
	}
	database.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = database.Close() })
	adapter, err := sqliteadapter.New(database)
	if err != nil {
		t.Fatal(err)
	}
	schema := mainIssuerSchema()
	if err = adapter.Migrate(t.Context(), schema); err != nil {
		t.Fatal(err)
	}
	// Main's SQL adapter also added this index on its own.
	if _, err = database.ExecContext(t.Context(),
		`CREATE UNIQUE INDEX "account_issuer_account_unique" ON "account" ("issuer", "accountId")`,
	); err != nil {
		t.Fatal(err)
	}
	configured, err := adapter.WithSchema(schema)
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := betterauth.WrapDatabaseAdapter(configured, schema)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if _, err = wrapped.Create(t.Context(), betterauth.CreateQuery{
			Model: betterauth.ModelAccount, Data: row, ForceAllowID: true,
		}); err != nil {
			t.Fatal(err)
		}
	}
	return database, adapter
}

func sqliteIndexes(t *testing.T, database *sql.DB) []string {
	t.Helper()
	rows, err := database.QueryContext(t.Context(),
		`SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'account' AND sql IS NOT NULL`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	names := make([]string, 0)
	for rows.Next() {
		var name string
		if err = rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		names = append(names, name)
	}
	return names
}

func TestSQLiteIssuerRevertRestoresProviderKey(t *testing.T) {
	database, adapter := openMainBuiltSQLite(t,
		mainAccountRow("a", "user-a", "github", "local:oauth:github", "same-subject"),
		mainAccountRow("b", "user-b", "gitlab", "local:oauth:gitlab", "same-subject"),
	)
	if _, err := database.ExecContext(t.Context(), sqliteIssuerRevert); err != nil {
		t.Fatalf("revert SQL failed: %v", err)
	}
	indexes := sqliteIndexes(t, database)
	if slices.Contains(indexes, "account_issuer_accountId_uidx") ||
		slices.Contains(indexes, "account_issuer_account_unique") ||
		!slices.Contains(indexes, "uniq_provider_account") {
		t.Fatalf("account indexes after revert: %v", indexes)
	}
	current := betterauth.CoreSchema()
	if err := adapter.Migrate(t.Context(), current); err != nil {
		t.Fatalf("current migration after revert: %v", err)
	}
	configured, err := adapter.WithSchema(current)
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := betterauth.WrapDatabaseAdapter(configured, current)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	create := func(id, provider string) error {
		_, err := wrapped.Create(t.Context(), betterauth.CreateQuery{
			Model: betterauth.ModelAccount, ForceAllowID: true, Data: betterauth.Record{
				"id": id, "userId": "user-c", "providerId": provider,
				"accountId": "new-subject", "createdAt": now, "updatedAt": now,
			},
		})
		return err
	}
	if err = create("c", "github"); err != nil {
		t.Fatalf("account without issuer was rejected after revert: %v", err)
	}
	if err = create("d", "github"); !errors.Is(err, betterauth.ErrConflict) {
		t.Fatalf("duplicate provider key after revert: %v", err)
	}
}

func TestSQLiteIssuerRevertStopsOnDuplicateProviderKey(t *testing.T) {
	database, _ := openMainBuiltSQLite(t,
		mainAccountRow("a", "user-a", "oidc", "https://tenant-a.example", "same-subject"),
		mainAccountRow("b", "user-b", "oidc", "https://tenant-b.example", "same-subject"),
	)
	var duplicates int
	if err := database.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM (
		SELECT 1 FROM "account" GROUP BY "providerId", "accountId" HAVING COUNT(*) > 1)`,
	).Scan(&duplicates); err != nil || duplicates != 1 {
		t.Fatalf("duplicate check = %d, %v", duplicates, err)
	}
	if _, err := database.ExecContext(t.Context(), sqliteIssuerRevert); err == nil {
		t.Fatal("revert SQL accepted a duplicate provider key")
	}
	_, _ = database.ExecContext(t.Context(), "ROLLBACK")
	indexes := sqliteIndexes(t, database)
	if !slices.Contains(indexes, "account_issuer_accountId_uidx") ||
		slices.Contains(indexes, "uniq_provider_account") {
		t.Fatalf("failed revert changed the schema: %v", indexes)
	}
}

func TestPostgreSQLIssuerRevertRestoresProviderKey(t *testing.T) {
	dsn := os.Getenv("POSTGRES_DSN")
	if dsn == "" {
		t.Skip("POSTGRES_DSN is not set")
	}
	database, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	ctx := t.Context()
	connection, err := database.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	schemaName := fmt.Sprintf("issuer_revert_%d", time.Now().UnixNano())
	exec := func(statement string) error {
		_, err := connection.ExecContext(ctx, statement)
		return err
	}
	if err = exec(`CREATE SCHEMA "` + schemaName + `"`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = database.ExecContext(context.Background(), `DROP SCHEMA "`+schemaName+`" CASCADE`)
	})
	for _, statement := range []string{
		`SET search_path TO "` + schemaName + `"`,
		`CREATE TABLE "account" ("id" TEXT NOT NULL UNIQUE, "userId" TEXT NOT NULL,
			"providerId" TEXT NOT NULL, "issuer" TEXT NOT NULL, "accountId" TEXT NOT NULL)`,
		`CREATE UNIQUE INDEX "account_issuer_accountId_uidx" ON "account" ("issuer", "accountId")`,
		`CREATE UNIQUE INDEX "account_issuer_account_unique" ON "account" ("issuer", "accountId")`,
		`INSERT INTO "account" VALUES ('a', 'user-a', 'oidc', 'https://tenant-a.example', 'same')`,
		`INSERT INTO "account" VALUES ('b', 'user-b', 'oidc', 'https://tenant-b.example', 'same')`,
	} {
		if err = exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	if err = exec(postgresqlIssuerRevert); err == nil {
		t.Fatal("revert SQL accepted a duplicate provider key")
	}
	_ = exec("ROLLBACK")
	if err = exec(`DELETE FROM "account" WHERE "id" = 'b'`); err != nil {
		t.Fatal(err)
	}
	if err = exec(postgresqlIssuerRevert); err != nil {
		t.Fatalf("revert SQL failed: %v", err)
	}
	if err = exec(`INSERT INTO "account" ("id", "userId", "providerId", "accountId")
		VALUES ('c', 'user-c', 'github', 'same')`); err != nil {
		t.Fatalf("account without issuer was rejected after revert: %v", err)
	}
	if err = exec(`INSERT INTO "account" ("id", "userId", "providerId", "accountId")
		VALUES ('d', 'user-d', 'github', 'same')`); err == nil {
		t.Fatal("duplicate provider key was accepted after revert")
	}
}
