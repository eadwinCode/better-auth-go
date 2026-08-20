package postgresql_test

import (
	"database/sql"
	"os"
	"testing"

	betterauth "github.com/eadwinCode/better-auth-go"
	"github.com/eadwinCode/better-auth-go/adapter/postgresql"
	"github.com/eadwinCode/better-auth-go/adaptertest"
	v17 "github.com/eadwinCode/better-auth-go/migration/v17"
	_ "github.com/jackc/pgx/v5/stdlib"
)

func TestConformance(t *testing.T) {
	database := databaseForTest(t)
	adapter, err := postgresql.New(database)
	if err != nil {
		t.Fatal(err)
	}
	schema := conformanceSchema()
	if err := adapter.Migrate(t.Context(), schema); err != nil {
		t.Fatal(err)
	}
	configured, err := adapter.WithSchema(schema)
	if err != nil {
		t.Fatal(err)
	}
	adaptertest.Run(t, func(t *testing.T) betterauth.DatabaseAdapter {
		t.Helper()
		return configured
	})
}

func TestMappedSchemaMigration(t *testing.T) {
	database := databaseForTest(t)
	adapter, err := postgresql.New(database)
	if err != nil {
		t.Fatal(err)
	}
	schema := betterauth.Schema{
		betterauth.ModelUser: {
			ModelName: "auth_users_mapped",
			Fields: map[string]betterauth.FieldSchema{
				"id": {
					Type: betterauth.FieldString, Required: true, Unique: true, FieldName: "user_id",
				},
				"email": {
					Type: betterauth.FieldString, Required: true, Unique: true, FieldName: "email_address",
				},
			},
		},
	}
	if err := adapter.Migrate(t.Context(), schema); err != nil {
		t.Fatal(err)
	}
	configured, err := adapter.WithSchema(schema)
	if err != nil {
		t.Fatal(err)
	}
	created, err := configured.Create(t.Context(), betterauth.CreateQuery{
		Model: "auth_users_mapped", ForceAllowID: true,
		Data: betterauth.Record{"user_id": "user-1", "email_address": "a@example.com"},
	})
	if err != nil || created["email_address"] != "a@example.com" {
		t.Fatalf("mapped create failed: %#v, %v", created, err)
	}
	userModel := schema[betterauth.ModelUser]
	userModel.Fields["name"] = betterauth.FieldSchema{
		Type: betterauth.FieldString, FieldName: "display_name",
	}
	schema[betterauth.ModelUser] = userModel
	if err := adapter.Migrate(t.Context(), schema); err != nil {
		t.Fatalf("additive migration failed: %v", err)
	}
	configured, err = adapter.WithSchema(schema)
	if err != nil {
		t.Fatal(err)
	}
	updated, err := configured.Update(t.Context(), betterauth.UpdateQuery{
		Model: "auth_users_mapped", Where: []betterauth.Where{betterauth.Eq("user_id", "user-1")},
		Update: betterauth.Record{"display_name": "Ada"},
	})
	if err != nil || updated["display_name"] != "Ada" {
		t.Fatalf("migrated field update failed: %#v, %v", updated, err)
	}
}

func TestReleaseUpgradeFromEcf48ac(t *testing.T) {
	database := databaseForTest(t)
	adapter, err := postgresql.New(database)
	if err != nil {
		t.Fatal(err)
	}
	legacy := releaseUpgradeSchema(adaptertest.LegacyCoreSchema())
	if err := adapter.Migrate(t.Context(), legacy); err != nil {
		t.Fatal(err)
	}
	configured, err := adapter.WithSchema(legacy)
	if err != nil {
		t.Fatal(err)
	}
	configured, err = betterauth.WrapDatabaseAdapter(configured, legacy)
	if err != nil {
		t.Fatal(err)
	}
	adaptertest.SeedReleaseBaseline(t, configured)

	staging := releaseUpgradeSchema(v17.StagingSchema())
	if err := adapter.Migrate(t.Context(), staging); err != nil {
		t.Fatalf("add nullable issuer: %v", err)
	}
	configured, err = adapter.WithSchema(staging)
	if err != nil {
		t.Fatal(err)
	}
	configured, err = betterauth.WrapDatabaseAdapter(configured, staging)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = v17.Backfill(t.Context(), configured, v17.Options{}); err != nil {
		t.Fatalf("backfill account issuer: %v", err)
	}
	current := releaseUpgradeSchema(betterauth.CoreSchema())
	if err := adapter.Migrate(t.Context(), current); err != nil {
		t.Fatalf("upgrade current schema: %v", err)
	}
	if err := v17.FinalizeSQL(t.Context(), database, v17.PostgreSQL, current); err != nil {
		t.Fatalf("finalize account issuer: %v", err)
	}
	if _, err := database.ExecContext(
		t.Context(), `UPDATE "release_upgrade_account" SET "issuer" = NULL WHERE "id" = 'upgrade-account'`,
	); err == nil {
		t.Fatal("finalized PostgreSQL account issuer remained nullable")
	}
	var legacyIndexes int
	if err := database.QueryRowContext(t.Context(),
		`SELECT COUNT(*) FROM pg_indexes WHERE schemaname = current_schema() AND indexname IN (`+
			`'uniq_provider_account', 'account_provider_account_unique')`,
	).Scan(&legacyIndexes); err != nil || legacyIndexes != 0 {
		t.Fatalf("legacy PostgreSQL account indexes remain: %d %v", legacyIndexes, err)
	}
	if err := adapter.Migrate(t.Context(), current); err != nil {
		t.Fatalf("idempotent current migration: %v", err)
	}
	configured, err = adapter.WithSchema(current)
	if err != nil {
		t.Fatal(err)
	}
	configured, err = betterauth.WrapDatabaseAdapter(configured, current)
	if err != nil {
		t.Fatal(err)
	}
	adaptertest.AssertReleaseUpgrade(t, configured)
	for _, expected := range []string{
		"release_upgrade_session_userId_index",
		"release_upgrade_account_userId_index",
	} {
		var found int
		if err := database.QueryRowContext(
			t.Context(),
			"SELECT COUNT(*) FROM pg_indexes WHERE schemaname = current_schema() AND indexname = $1",
			expected,
		).Scan(&found); err != nil {
			t.Fatal(err)
		}
		if found != 1 {
			t.Fatalf("current index %q was not created", expected)
		}
	}
}

func releaseUpgradeSchema(schema betterauth.Schema) betterauth.Schema {
	for logicalName, model := range schema {
		model.ModelName = "release_upgrade_" + logicalName
		for index := range model.Indexes {
			model.Indexes[index].Name = "release_upgrade_" + model.Indexes[index].Name
		}
		schema[logicalName] = model
	}
	return schema
}

func databaseForTest(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("POSTGRES_DSN")
	if dsn == "" {
		t.Skip("POSTGRES_DSN is not set")
	}
	database, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	database.SetMaxOpenConns(16)
	t.Cleanup(func() { _ = database.Close() })
	if err := database.PingContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	return database
}

func conformanceSchema() betterauth.Schema {
	schema := betterauth.Schema{
		"conformance": {Fields: map[string]betterauth.FieldSchema{
			"id": {Type: betterauth.FieldString, Required: true, Unique: true}, "group": {Type: betterauth.FieldString},
			"sequence": {Type: betterauth.FieldNumber}, "name": {Type: betterauth.FieldString},
			"danger": {Type: betterauth.FieldBoolean},
		}},
		"single_use": {Fields: map[string]betterauth.FieldSchema{
			"id": {Type: betterauth.FieldString, Required: true, Unique: true}, "value": {Type: betterauth.FieldString},
		}},
		"counter": {Fields: map[string]betterauth.FieldSchema{
			"id": {Type: betterauth.FieldString, Required: true, Unique: true}, "remaining": {Type: betterauth.FieldNumber},
		}},
		"transaction": {Fields: map[string]betterauth.FieldSchema{
			"id": {Type: betterauth.FieldString, Required: true, Unique: true},
		}},
	}
	schema[betterauth.ModelAccount] = betterauth.CoreSchema()[betterauth.ModelAccount]
	return schema
}
