package sqlite_test

import (
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	betterauth "github.com/eadwinCode/better-auth-go"
	"github.com/eadwinCode/better-auth-go/adapter/sqladapter"
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

func TestMigrationRefusesRequiredColumnWithoutDefaultOnPopulatedTable(t *testing.T) {
	t.Parallel()
	database, adapter := migrationAdapter(t, "unsafe-migration.db")
	legacy := migrationSafetySchema()
	if err := adapter.Migrate(t.Context(), legacy); err != nil {
		t.Fatal(err)
	}
	configured, err := adapter.WithSchema(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = configured.Create(t.Context(), betterauth.CreateQuery{
		Model: "people", ForceAllowID: true, Data: betterauth.Record{"id": "person-1"},
	}); err != nil {
		t.Fatal(err)
	}
	target := migrationSafetySchema()
	people := target["people"]
	people.Fields["tenantId"] = betterauth.FieldSchema{
		Type: betterauth.FieldString, Required: true,
	}
	target["people"] = people
	target["would_have_been_created"] = betterauth.ModelSchema{
		Fields: map[string]betterauth.FieldSchema{
			"id": {Type: betterauth.FieldString, Required: true},
		},
	}
	err = adapter.Migrate(t.Context(), target)
	var unsafe *sqladapter.UnsafeMigrationError
	if !errors.As(err, &unsafe) || unsafe.Model != "people" || unsafe.Field != "tenantId" {
		t.Fatalf("Migrate() error = %#v", err)
	}
	assertSQLiteColumn(t, database, "people", "tenantId", false)
	var created int
	if err = database.QueryRowContext(
		t.Context(), "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?",
		"would_have_been_created",
	).Scan(&created); err != nil {
		t.Fatal(err)
	}
	if created != 0 {
		t.Fatal("migration executed DDL before completing the safety preflight")
	}
}

func TestMigrationAllowsRequiredColumnWithStaticDefault(t *testing.T) {
	t.Parallel()
	database, adapter := migrationAdapter(t, "default-migration.db")
	legacy := migrationSafetySchema()
	if err := adapter.Migrate(t.Context(), legacy); err != nil {
		t.Fatal(err)
	}
	configured, err := adapter.WithSchema(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = configured.Create(t.Context(), betterauth.CreateQuery{
		Model: "people", ForceAllowID: true, Data: betterauth.Record{"id": "person-1"},
	}); err != nil {
		t.Fatal(err)
	}
	target := migrationSafetySchema()
	people := target["people"]
	people.Fields["tenantId"] = betterauth.FieldSchema{
		Type: betterauth.FieldString, Required: true, DefaultValue: "reviewed-backfill",
	}
	target["people"] = people
	if err = adapter.Migrate(t.Context(), target); err != nil {
		t.Fatal(err)
	}
	var tenantID string
	if err = database.QueryRowContext(
		t.Context(), `SELECT "tenantId" FROM "people" WHERE "id" = ?`, "person-1",
	).Scan(&tenantID); err != nil {
		t.Fatal(err)
	}
	if tenantID != "reviewed-backfill" {
		t.Fatalf("backfilled tenantId = %q", tenantID)
	}
}

func TestMigrationAllowsRequiredColumnOnEmptyTable(t *testing.T) {
	t.Parallel()
	database, adapter := migrationAdapter(t, "empty-migration.db")
	legacy := migrationSafetySchema()
	if err := adapter.Migrate(t.Context(), legacy); err != nil {
		t.Fatal(err)
	}
	target := migrationSafetySchema()
	people := target["people"]
	people.Fields["tenantId"] = betterauth.FieldSchema{
		Type: betterauth.FieldString, Required: true,
	}
	target["people"] = people
	if err := adapter.Migrate(t.Context(), target); err != nil {
		t.Fatal(err)
	}
	assertSQLiteColumn(t, database, "people", "tenantId", true)
}

func TestMigrationRollsBackDDLOnIndexFailure(t *testing.T) {
	t.Parallel()
	database, adapter := migrationAdapter(t, "rollback-migration.db")
	legacy := migrationSafetySchema()
	if err := adapter.Migrate(t.Context(), legacy); err != nil {
		t.Fatal(err)
	}
	configured, err := adapter.WithSchema(legacy)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"person-1", "person-2"} {
		if _, err = configured.Create(t.Context(), betterauth.CreateQuery{
			Model: "people", ForceAllowID: true, Data: betterauth.Record{"id": id},
		}); err != nil {
			t.Fatal(err)
		}
	}
	target := migrationSafetySchema()
	people := target["people"]
	people.Fields["displayName"] = betterauth.FieldSchema{Type: betterauth.FieldString}
	people.Fields["tenantId"] = betterauth.FieldSchema{
		Type: betterauth.FieldString, Required: true, DefaultValue: "same", Unique: true,
	}
	target["people"] = people
	if err = adapter.Migrate(t.Context(), target); err == nil {
		t.Fatal("migration with a duplicate unique backfill unexpectedly succeeded")
	}
	assertSQLiteColumn(t, database, "people", "displayName", false)
	assertSQLiteColumn(t, database, "people", "tenantId", false)
}

func migrationAdapter(
	t *testing.T,
	filename string,
) (*sql.DB, *sqladapter.Adapter) {
	t.Helper()
	database, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), filename))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	adapter, err := sqliteadapter.New(database)
	if err != nil {
		t.Fatal(err)
	}
	return database, adapter
}

func migrationSafetySchema() betterauth.Schema {
	return betterauth.Schema{"people": {Fields: map[string]betterauth.FieldSchema{
		"id": {Type: betterauth.FieldString, Required: true, Unique: true},
	}}}
}

func assertSQLiteColumn(
	t *testing.T,
	database *sql.DB,
	table, column string,
	want bool,
) {
	t.Helper()
	rows, err := database.QueryContext(t.Context(), `PRAGMA table_info("`+table+`")`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	found := false
	for rows.Next() {
		var position, notNull, primaryKey int
		var name, dataType string
		var defaultValue any
		if err = rows.Scan(&position, &name, &dataType, &notNull, &defaultValue, &primaryKey); err != nil {
			t.Fatal(err)
		}
		found = found || name == column
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	if found != want {
		t.Fatalf("column %s.%s existence = %v, want %v", table, column, found, want)
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
