package postgresql_test

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"reflect"
	"slices"
	"strings"
	"testing"

	betterauth "github.com/eadwinCode/better-auth-go"
	"github.com/eadwinCode/better-auth-go/adapter/postgresql"
	"github.com/eadwinCode/better-auth-go/adaptertest"
)

// randomSchema returns a new schema name and drops that schema (with every
// table in it) when the test ends. It does not create the schema.
func randomSchema(t *testing.T, database *sql.DB) string {
	t.Helper()
	suffix := make([]byte, 6)
	if _, err := rand.Read(suffix); err != nil {
		t.Fatal(err)
	}
	name := "ba_test_" + hex.EncodeToString(suffix)
	t.Cleanup(func() {
		_, _ = database.Exec(`DROP SCHEMA IF EXISTS "` + name + `" CASCADE`)
	})
	return name
}

func execSQL(t *testing.T, database *sql.DB, statement string) {
	t.Helper()
	if _, err := database.ExecContext(t.Context(), statement); err != nil {
		t.Fatalf("%s: %v", statement, err)
	}
}

func tablesIn(t *testing.T, database *sql.DB, schema string) []string {
	t.Helper()
	rows, err := database.QueryContext(t.Context(),
		"SELECT tablename FROM pg_catalog.pg_tables WHERE schemaname = $1 ORDER BY tablename", schema,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		names = append(names, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return names
}

func TestSchemaNameConformance(t *testing.T) {
	database := databaseForTest(t)
	schemaName := randomSchema(t, database)
	var current sql.NullString
	if err := database.QueryRowContext(t.Context(), "SELECT current_schema()").Scan(&current); err != nil {
		t.Fatal(err)
	}
	if current.String == schemaName {
		t.Fatal("search_path already points at the test schema")
	}
	adapter, err := postgresql.NewWithOptions(database, postgresql.Options{SchemaName: schemaName})
	if err != nil {
		t.Fatal(err)
	}
	schema := conformanceSchema()
	if err := adapter.Migrate(t.Context(), schema); err != nil {
		t.Fatal(err)
	}
	if err := adapter.Migrate(t.Context(), schema); err != nil {
		t.Fatalf("idempotent migration: %v", err)
	}
	want := []string{"account", "conformance", "counter", "single_use", "transaction"}
	if got := tablesIn(t, database, schemaName); !reflect.DeepEqual(got, want) {
		t.Fatalf("tables in %s = %v, want %v", schemaName, got, want)
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

func TestSchemaNameLeavesSameNamedPublicTableAlone(t *testing.T) {
	database := databaseForTest(t)
	schemaName := randomSchema(t, database)
	// A table with the same name in the connection's own schema. The adapter
	// must never read or change it.
	probe := schemaName + "_probe"
	execSQL(t, database, `CREATE TABLE "`+probe+`" ("other" TEXT NOT NULL)`)
	t.Cleanup(func() { _, _ = database.Exec(`DROP TABLE IF EXISTS "` + probe + `"`) })
	execSQL(t, database, `INSERT INTO "`+probe+`" ("other") VALUES ('untouched')`)

	adapter, err := postgresql.NewWithOptions(database, postgresql.Options{SchemaName: schemaName})
	if err != nil {
		t.Fatal(err)
	}
	schema := betterauth.Schema{probe: {Fields: map[string]betterauth.FieldSchema{
		"id":   {Type: betterauth.FieldString, Required: true, Unique: true},
		"name": {Type: betterauth.FieldString, Index: true},
	}}}
	if err := adapter.Migrate(t.Context(), schema); err != nil {
		t.Fatal(err)
	}
	if findings, err := adapter.CheckSchema(t.Context(), schema); err != nil || len(findings) != 0 {
		t.Fatalf("CheckSchema() = %#v, %v", findings, err)
	}
	configured, err := adapter.WithSchema(schema)
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	if _, err := configured.Create(ctx, betterauth.CreateQuery{
		Model: probe, Data: betterauth.Record{"id": "probe-1", "name": "Ada"},
	}); err != nil {
		t.Fatal(err)
	}
	where := []betterauth.Where{betterauth.Eq("id", "probe-1")}
	if _, err := configured.Update(ctx, betterauth.UpdateQuery{
		Model: probe, Where: where, Update: betterauth.Record{"name": "Grace"},
	}); err != nil {
		t.Fatal(err)
	}
	found, err := configured.FindOne(ctx, betterauth.FindOneQuery{Model: probe, Where: where})
	if err != nil || found["name"] != "Grace" {
		t.Fatalf("FindOne() = %#v, %v", found, err)
	}
	if count, err := configured.Count(ctx, betterauth.CountQuery{Model: probe}); err != nil || count != 1 {
		t.Fatalf("Count() = %d, %v", count, err)
	}
	if err := configured.Delete(ctx, betterauth.DeleteQuery{Model: probe, Where: where}); err != nil {
		t.Fatal(err)
	}

	var other string
	var rows int
	if err := database.QueryRowContext(ctx,
		`SELECT MIN("other"), COUNT(*) FROM "`+probe+`"`,
	).Scan(&other, &rows); err != nil {
		t.Fatal(err)
	}
	if other != "untouched" || rows != 1 {
		t.Fatalf("public table changed: %q, %d rows", other, rows)
	}
	var columns int
	if err := database.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = $1",
		probe,
	).Scan(&columns); err != nil || columns != 1 {
		t.Fatalf("public table columns = %d, %v", columns, err)
	}
	if got := tablesIn(t, database, schemaName); !slices.Equal(got, []string{probe}) {
		t.Fatalf("tables in %s = %v", schemaName, got)
	}
}

func TestSchemaCheck(t *testing.T) {
	database := databaseForTest(t)
	adaptertest.RunSchemaCheck(t, func(t *testing.T) adaptertest.SchemaCheckTarget {
		t.Helper()
		schemaName := randomSchema(t, database)
		adapter, err := postgresql.NewWithOptions(database, postgresql.Options{SchemaName: schemaName})
		if err != nil {
			t.Fatal(err)
		}
		return adaptertest.SchemaCheckTarget{
			Adapter: adapter,
			Exec: func(t *testing.T, statement string) {
				t.Helper()
				execSQL(t, database, `CREATE SCHEMA IF NOT EXISTS "`+schemaName+`"`)
				execSQL(t, database, statement)
			},
			Table: func(name string) string { return `"` + schemaName + `"."` + name + `"` },
		}
	})
}

// searchPathDatabase returns a one-connection pool whose search_path is
// schemaName, so unqualified statements and current_schema() use it.
func searchPathDatabase(t *testing.T, schemaName string) *sql.DB {
	t.Helper()
	database := databaseForTest(t)
	database.SetMaxOpenConns(1)
	database.SetMaxIdleConns(1)
	database.SetConnMaxLifetime(0)
	database.SetConnMaxIdleTime(0)
	execSQL(t, database, `CREATE SCHEMA IF NOT EXISTS "`+schemaName+`"`)
	execSQL(t, database, `SET search_path TO "`+schemaName+`"`)
	return database
}

func TestMigrationRejectsViewsAndOtherRelations(t *testing.T) {
	schemaName := randomSchema(t, databaseForTest(t))
	database := searchPathDatabase(t, schemaName)
	schema := betterauth.Schema{
		"rel_user": {Fields: map[string]betterauth.FieldSchema{
			"id": {Type: betterauth.FieldString, Required: true, Unique: true},
		}},
	}
	for _, relation := range []struct {
		create string
		kind   string
	}{
		{`CREATE VIEW "rel_user" AS SELECT 'x'::text AS "id"`, "view"},
		{`CREATE MATERIALIZED VIEW "rel_user" AS SELECT 'x'::text AS "id"`, "materialized view"},
		{`CREATE SEQUENCE "rel_user"`, "sequence"},
	} {
		execSQL(t, database, relation.create)
		for _, options := range []postgresql.Options{{}, {SchemaName: schemaName}} {
			adapter, err := postgresql.NewWithOptions(database, options)
			if err != nil {
				t.Fatal(err)
			}
			err = adapter.Migrate(t.Context(), schema)
			if err == nil || !strings.Contains(err.Error(), "is a "+relation.kind+", not a table") {
				t.Fatalf("Migrate() with a %s (schema %q) = %v", relation.kind, options.SchemaName, err)
			}
		}
		execSQL(t, database, `DROP `+strings.ToUpper(relation.kind)+` "rel_user"`)
	}

	// A partitioned table is a real table.
	execSQL(t, database, `CREATE TABLE "rel_user" ("id" TEXT NOT NULL) PARTITION BY LIST ("id")`)
	adapter, err := postgresql.New(database)
	if err != nil {
		t.Fatal(err)
	}
	if err := adapter.Migrate(t.Context(), schema); err != nil {
		t.Fatalf("Migrate() with a partitioned table = %v", err)
	}
	if findings, err := adapter.CheckSchema(t.Context(), schema); err != nil || len(findings) != 0 {
		t.Fatalf("CheckSchema() on the search_path = %#v, %v", findings, err)
	}
}

func TestMigrationIgnoresTablesInOtherSchemas(t *testing.T) {
	root := databaseForTest(t)
	other := randomSchema(t, root)
	execSQL(t, root, `CREATE SCHEMA "`+other+`"`)
	execSQL(t, root, `CREATE TABLE "`+other+`"."elsewhere" ("id" TEXT)`)
	schemaName := randomSchema(t, root)
	database := searchPathDatabase(t, schemaName)
	adapter, err := postgresql.New(database)
	if err != nil {
		t.Fatal(err)
	}
	schema := betterauth.Schema{"elsewhere": {Fields: map[string]betterauth.FieldSchema{
		"id":   {Type: betterauth.FieldString, Required: true, Unique: true},
		"name": {Type: betterauth.FieldString},
	}}}
	if err := adapter.Migrate(t.Context(), schema); err != nil {
		t.Fatal(err)
	}
	if got := tablesIn(t, root, schemaName); !slices.Equal(got, []string{"elsewhere"}) {
		t.Fatalf("tables in %s = %v", schemaName, got)
	}
}
