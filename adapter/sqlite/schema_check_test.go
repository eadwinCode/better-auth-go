package sqlite_test

import (
	"database/sql"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	betterauth "github.com/eadwinCode/better-auth-go"
	"github.com/eadwinCode/better-auth-go/adapter/sqladapter"
	sqliteadapter "github.com/eadwinCode/better-auth-go/adapter/sqlite"
	"github.com/eadwinCode/better-auth-go/adaptertest"
)

func openSQLite(t *testing.T, name string) *sql.DB {
	t.Helper()
	database, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), name))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return database
}

func TestSchemaCheck(t *testing.T) {
	t.Parallel()
	adaptertest.RunSchemaCheck(t, func(t *testing.T) adaptertest.SchemaCheckTarget {
		t.Helper()
		database := openSQLite(t, "schema-check.db")
		adapter, err := sqliteadapter.New(database)
		if err != nil {
			t.Fatal(err)
		}
		return adaptertest.SchemaCheckTarget{
			Adapter: adapter,
			Exec: func(t *testing.T, statement string) {
				t.Helper()
				if _, err := database.ExecContext(t.Context(), statement); err != nil {
					t.Fatalf("%s: %v", statement, err)
				}
			},
			Table: func(name string) string { return `"` + name + `"` },
		}
	})
}

func TestSchemaCheckTreatsIntegerPrimaryKeyAsFilled(t *testing.T) {
	t.Parallel()
	database := openSQLite(t, "rowid.db")
	adapter, err := sqliteadapter.New(database)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(t.Context(),
		`CREATE TABLE "member" ("row_key" INTEGER PRIMARY KEY, "id" TEXT NOT NULL, "legacy" TEXT NOT NULL)`,
	); err != nil {
		t.Fatal(err)
	}
	findings, err := adapter.CheckSchema(t.Context(), betterauth.Schema{
		"member": {Fields: map[string]betterauth.FieldSchema{"id": {Type: betterauth.FieldString}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []betterauth.SchemaFinding{{
		Kind: betterauth.SchemaFindingUnexpectedRequiredColumn, Table: "member", Column: "legacy",
	}}
	if !reflect.DeepEqual(findings, want) {
		t.Fatalf("findings = %#v, want %#v", findings, want)
	}
}

func TestSQLiteRejectsSchemaName(t *testing.T) {
	t.Parallel()
	database := openSQLite(t, "schema-name.db")
	_, err := sqladapter.NewWithOptions(database, sqladapter.SQLite, sqladapter.Options{SchemaName: "auth"})
	if err == nil || !strings.Contains(err.Error(), "only supported on PostgreSQL") {
		t.Fatalf("NewWithOptions() error = %v", err)
	}
}
