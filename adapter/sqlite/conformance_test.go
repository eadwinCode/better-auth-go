package sqlite_test

import (
	"database/sql"
	"path/filepath"
	"testing"

	betterauth "github.com/eadwinCode/better-auth-go"
	sqliteadapter "github.com/eadwinCode/better-auth-go/adapter/sqlite"
	"github.com/eadwinCode/better-auth-go/adaptertest"
	_ "modernc.org/sqlite"
)

func TestConformance(t *testing.T) {
	t.Parallel()
	adaptertest.Run(t, func(t *testing.T) betterauth.DatabaseAdapter {
		t.Helper()
		dsn := "file:" + filepath.Join(t.TempDir(), "adapter.db") +
			"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)"
		database, err := sql.Open("sqlite", dsn)
		if err != nil {
			t.Fatal(err)
		}
		database.SetMaxOpenConns(8)
		t.Cleanup(func() { _ = database.Close() })
		adapter, err := sqliteadapter.New(database)
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
		return configured
	})
}

func TestMappedSchemaMigration(t *testing.T) {
	t.Parallel()
	database, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "mapped.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	adapter, err := sqliteadapter.New(database)
	if err != nil {
		t.Fatal(err)
	}
	schema := betterauth.Schema{
		betterauth.ModelUser: {
			ModelName: "auth_users",
			Fields: map[string]betterauth.FieldSchema{
				"id":    {Type: betterauth.FieldString, Required: true, Unique: true, FieldName: "user_id"},
				"email": {Type: betterauth.FieldString, Required: true, Unique: true, FieldName: "email_address"},
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
		Model: "auth_users", ForceAllowID: true,
		Data: betterauth.Record{"user_id": "user-1", "email_address": "a@example.com"},
	})
	if err != nil || created["email_address"] != "a@example.com" {
		t.Fatalf("mapped create failed: %#v, %v", created, err)
	}
	updated, err := configured.Update(t.Context(), betterauth.UpdateQuery{
		Model: "auth_users", Where: []betterauth.Where{betterauth.Eq("user_id", "user-1")},
		Update: betterauth.Record{"email_address": "b@example.com"},
	})
	if err != nil || updated["email_address"] != "b@example.com" {
		t.Fatalf("mapped update failed: %#v, %v", updated, err)
	}
	userModel := schema[betterauth.ModelUser]
	userModel.Fields["name"] = betterauth.FieldSchema{Type: betterauth.FieldString, FieldName: "display_name"}
	schema[betterauth.ModelUser] = userModel
	if err := adapter.Migrate(t.Context(), schema); err != nil {
		t.Fatalf("additive migration failed: %v", err)
	}
	configured, err = adapter.WithSchema(schema)
	if err != nil {
		t.Fatal(err)
	}
	updated, err = configured.Update(t.Context(), betterauth.UpdateQuery{
		Model: "auth_users", Where: []betterauth.Where{betterauth.Eq("user_id", "user-1")},
		Update: betterauth.Record{"display_name": "Ada"},
	})
	if err != nil || updated["display_name"] != "Ada" {
		t.Fatalf("migrated field update failed: %#v, %v", updated, err)
	}
}

func TestReleaseUpgradeFromEcf48ac(t *testing.T) {
	t.Parallel()
	database, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "release-upgrade.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	adapter, err := sqliteadapter.New(database)
	if err != nil {
		t.Fatal(err)
	}
	legacy := adaptertest.LegacyCoreSchema()
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

	current := betterauth.CoreSchema()
	if err := adapter.Migrate(t.Context(), current); err != nil {
		t.Fatalf("upgrade current schema: %v", err)
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
	for _, expected := range []string{"session_userId_index", "account_userId_index"} {
		var found int
		if err := database.QueryRowContext(
			t.Context(),
			"SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = ?",
			expected,
		).Scan(&found); err != nil {
			t.Fatal(err)
		}
		if found != 1 {
			t.Fatalf("current index %q was not created", expected)
		}
	}
}

func conformanceSchema() betterauth.Schema {
	return betterauth.Schema{
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
}
