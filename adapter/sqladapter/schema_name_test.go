package sqladapter

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"io"
	"reflect"
	"strings"
	"sync"
	"testing"

	betterauth "github.com/eadwinCode/better-auth-go"
)

// recordingDriver is a database/sql driver that runs nothing. It records
// each statement and its arguments, answers every query with no rows, and
// reports no rows changed. It lets the tests read the SQL the adapter sends.
type recordingDriver struct {
	mu         sync.Mutex
	statements []recordedStatement
	// respond, when set, may answer a query with rows instead of none.
	respond func(query string) [][]driver.Value
}

type recordedStatement struct {
	query string
	args  []driver.NamedValue
}

func (recorder *recordingDriver) record(query string, args []driver.NamedValue) {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	recorder.statements = append(recorder.statements, recordedStatement{query: query, args: args})
}

func (recorder *recordingDriver) all() []recordedStatement {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	return append([]recordedStatement(nil), recorder.statements...)
}

func (recorder *recordingDriver) Open(string) (driver.Conn, error) {
	return recordingConn{recorder: recorder}, nil
}

type recordingConn struct{ recorder *recordingDriver }

func (conn recordingConn) Prepare(string) (driver.Stmt, error) {
	return nil, driver.ErrSkip
}
func (conn recordingConn) Close() error              { return nil }
func (conn recordingConn) Begin() (driver.Tx, error) { return recordingTx{}, nil }

func (conn recordingConn) ExecContext(
	_ context.Context, query string, args []driver.NamedValue,
) (driver.Result, error) {
	conn.recorder.record(query, args)
	return driver.RowsAffected(0), nil
}

func (conn recordingConn) QueryContext(
	_ context.Context, query string, args []driver.NamedValue,
) (driver.Rows, error) {
	conn.recorder.record(query, args)
	if conn.recorder.respond != nil {
		if rows := conn.recorder.respond(query); rows != nil {
			return &scriptedRows{rows: rows}, nil
		}
	}
	return emptyRows{}, nil
}

type scriptedRows struct{ rows [][]driver.Value }

func (rows *scriptedRows) Columns() []string {
	columns := make([]string, len(rows.rows[0]))
	for index := range columns {
		columns[index] = "column"
	}
	return columns
}
func (rows *scriptedRows) Close() error { return nil }
func (rows *scriptedRows) Next(destination []driver.Value) error {
	if len(rows.rows) == 0 {
		return io.EOF
	}
	copy(destination, rows.rows[0])
	rows.rows = rows.rows[1:]
	return nil
}

type recordingTx struct{}

func (recordingTx) Commit() error   { return nil }
func (recordingTx) Rollback() error { return nil }

type emptyRows struct{}

func (emptyRows) Columns() []string         { return []string{"value"} }
func (emptyRows) Close() error              { return nil }
func (emptyRows) Next([]driver.Value) error { return io.EOF }

func recordingDatabase(t *testing.T) (*sql.DB, *recordingDriver) {
	t.Helper()
	return scriptedDatabase(t, nil)
}

func scriptedDatabase(
	t *testing.T,
	respond func(query string) [][]driver.Value,
) (*sql.DB, *recordingDriver) {
	t.Helper()
	recorder := &recordingDriver{respond: respond}
	database := sql.OpenDB(connector{recorder: recorder})
	t.Cleanup(func() { _ = database.Close() })
	return database, recorder
}

type connector struct{ recorder *recordingDriver }

func (c connector) Connect(context.Context) (driver.Conn, error) { return c.recorder.Open("") }
func (c connector) Driver() driver.Driver                        { return c.recorder }

func memberSchema() betterauth.Schema {
	return betterauth.Schema{
		"member": {
			Fields: map[string]betterauth.FieldSchema{
				"id":    {Type: betterauth.FieldString, Required: true, Unique: true},
				"name":  {Type: betterauth.FieldString, Index: true},
				"count": {Type: betterauth.FieldNumber},
			},
			Indexes: []betterauth.IndexSchema{{Name: "member_name_count", Fields: []string{"name", "count"}}},
		},
	}
}

// assertQualified fails when a statement names the member table without
// the configured schema.
func assertQualified(t *testing.T, statement string) {
	t.Helper()
	if strings.Count(statement, `"member"`) != strings.Count(statement, `"auth"."member"`) {
		t.Fatalf("statement names the table without its schema: %s", statement)
	}
}

func TestSchemaNameQualifiesEveryStatement(t *testing.T) {
	t.Parallel()
	database, recorder := recordingDatabase(t)
	adapter, err := NewWithOptions(database, PostgreSQL, Options{SchemaName: "auth"})
	if err != nil {
		t.Fatal(err)
	}
	if adapter.SchemaName() != "auth" {
		t.Fatalf("SchemaName() = %q", adapter.SchemaName())
	}
	schema := memberSchema()
	if err := adapter.Migrate(t.Context(), schema); err != nil {
		t.Fatal(err)
	}
	statements := recorder.all()
	firstDDL := -1
	for index, statement := range statements {
		if strings.HasPrefix(statement.query, "CREATE") {
			firstDDL = index
			break
		}
	}
	if firstDDL < 0 || statements[firstDDL].query != `CREATE SCHEMA IF NOT EXISTS "auth"` {
		t.Fatalf("migration did not create the schema first: %#v", statements)
	}
	var sawTable, sawIndex, sawCompound bool
	for _, statement := range statements {
		assertQualified(t, statement.query)
		sawTable = sawTable || strings.HasPrefix(statement.query, `CREATE TABLE IF NOT EXISTS "auth"."member" (`)
		sawIndex = sawIndex || strings.Contains(statement.query, `INDEX IF NOT EXISTS "member_name_index" ON "auth"."member"`)
		sawCompound = sawCompound || strings.Contains(statement.query, `INDEX IF NOT EXISTS "member_name_count" ON "auth"."member"`)
		if strings.Contains(statement.query, "pg_catalog.pg_class") {
			if len(statement.args) != 2 || statement.args[1].Value != "auth" ||
				strings.Contains(statement.query, "current_schema()") {
				t.Fatalf("migration inspected the wrong schema: %#v", statement)
			}
		}
	}
	if !sawTable || !sawIndex || !sawCompound {
		t.Fatalf("missing migration statements: %#v", statements)
	}

	configured, err := adapter.WithSchema(schema)
	if err != nil {
		t.Fatal(err)
	}
	before := len(recorder.all())
	ctx := t.Context()
	where := []betterauth.Where{betterauth.Eq("id", "member-1")}
	err = configured.Transaction(ctx, func(transaction betterauth.DatabaseAdapter) error {
		if transaction.(*Adapter).SchemaName() != "auth" {
			t.Fatal("transaction lost the schema name")
		}
		_, _ = transaction.Create(ctx, betterauth.CreateQuery{Model: "member", Data: betterauth.Record{"id": "member-1"}})
		_, _ = transaction.FindOne(ctx, betterauth.FindOneQuery{Model: "member", Where: where})
		_, _ = transaction.FindMany(ctx, betterauth.FindManyQuery{Model: "member", Where: where})
		_, _ = transaction.Count(ctx, betterauth.CountQuery{Model: "member", Where: where})
		_, _ = transaction.Update(ctx, betterauth.UpdateQuery{Model: "member", Where: where, Update: betterauth.Record{"name": "a"}})
		_, _ = transaction.UpdateMany(ctx, betterauth.UpdateQuery{Model: "member", Where: where, Update: betterauth.Record{"name": "a"}})
		_ = transaction.Delete(ctx, betterauth.DeleteQuery{Model: "member", Where: where})
		_, _ = transaction.DeleteMany(ctx, betterauth.DeleteQuery{Model: "member", Where: where})
		_, _ = transaction.ConsumeOne(ctx, betterauth.DeleteQuery{Model: "member", Where: where})
		_, _ = transaction.IncrementOne(ctx, betterauth.IncrementQuery{
			Model: "member", Where: where, Increment: map[string]float64{"count": 1},
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	crud := recorder.all()[before:]
	if len(crud) != 10 {
		t.Fatalf("recorded %d CRUD statements, want 10: %#v", len(crud), crud)
	}
	for _, statement := range crud {
		if !strings.Contains(statement.query, `"auth"."member"`) {
			t.Fatalf("statement does not use the schema: %s", statement.query)
		}
		assertQualified(t, statement.query)
	}

	before = len(recorder.all())
	if _, err := adapter.CheckSchema(ctx, schema); err != nil {
		t.Fatal(err)
	}
	for _, statement := range recorder.all()[before:] {
		if len(statement.args) != 2 || statement.args[1].Value != "auth" ||
			strings.Contains(statement.query, "current_schemas") {
			t.Fatalf("schema check looked outside the configured schema: %#v", statement)
		}
	}
}

func TestMigrationWithoutSchemaNameKeepsUnqualifiedNames(t *testing.T) {
	t.Parallel()
	database, recorder := recordingDatabase(t)
	adapter, err := New(database, PostgreSQL)
	if err != nil {
		t.Fatal(err)
	}
	if err := adapter.Migrate(t.Context(), memberSchema()); err != nil {
		t.Fatal(err)
	}
	for _, statement := range recorder.all() {
		if strings.Contains(statement.query, "CREATE SCHEMA") || strings.Contains(statement.query, `"auth"`) {
			t.Fatalf("unexpected schema statement: %s", statement.query)
		}
		if strings.Contains(statement.query, "pg_catalog.pg_class") &&
			!strings.Contains(statement.query, "pg_catalog.current_schema()") {
			t.Fatalf("migration did not inspect current_schema(): %s", statement.query)
		}
	}
}

func TestMigrationSkipsCreateSchemaWhenTablesExist(t *testing.T) {
	t.Parallel()
	database, recorder := recordingDatabase(t)
	adapter, err := NewWithOptions(database, PostgreSQL, Options{SchemaName: "auth"})
	if err != nil {
		t.Fatal(err)
	}
	// An empty schema creates no tables, so it must not need CREATE on the
	// database either.
	if err := adapter.Migrate(t.Context(), betterauth.Schema{}); err != nil {
		t.Fatal(err)
	}
	for _, statement := range recorder.all() {
		if strings.Contains(statement.query, "CREATE SCHEMA") {
			t.Fatalf("created the schema with no tables to create: %s", statement.query)
		}
	}
}

func TestSchemaNameValidation(t *testing.T) {
	t.Parallel()
	database, _ := recordingDatabase(t)
	_, err := NewWithOptions(database, SQLite, Options{SchemaName: "auth"})
	if err == nil || !strings.Contains(err.Error(), "only supported on PostgreSQL") ||
		!strings.Contains(err.Error(), `"sqlite"`) {
		t.Fatalf("SQLite schema name error = %v", err)
	}
	if _, err := NewWithOptions(database, SQLite, Options{}); err != nil {
		t.Fatalf("SQLite without a schema name: %v", err)
	}
	for _, name := range []string{strings.Repeat("a", 64), "auth\x00x", "\xff"} {
		if _, err := NewWithOptions(database, PostgreSQL, Options{SchemaName: name}); err == nil {
			t.Fatalf("accepted schema name %q", name)
		}
	}
	for _, name := range []string{strings.Repeat("a", 63), "auth", `odd "name"`, "Auth-Schema"} {
		adapter, err := NewWithOptions(database, PostgreSQL, Options{SchemaName: name})
		if err != nil {
			t.Fatalf("rejected schema name %q: %v", name, err)
		}
		if name == `odd "name"` && adapter.table("user") != `"odd ""name"""."user"` {
			t.Fatalf("schema name was not quoted: %s", adapter.table("user"))
		}
	}
}

func TestPostgreSQLMigrationRejectsRelationsThatAreNotTables(t *testing.T) {
	t.Parallel()
	for kind, name := range map[string]string{"v": "view", "m": "materialized view", "f": "foreign table"} {
		database, recorder := scriptedDatabase(t, func(query string) [][]driver.Value {
			if strings.Contains(query, "pg_catalog.pg_class") {
				return [][]driver.Value{{kind, "id"}}
			}
			return nil
		})
		adapter, err := NewWithOptions(database, PostgreSQL, Options{SchemaName: "auth"})
		if err != nil {
			t.Fatal(err)
		}
		err = adapter.Migrate(t.Context(), memberSchema())
		want := `"auth"."member" is a ` + name + ", not a table"
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("Migrate() over a %s = %v", name, err)
		}
		for _, statement := range recorder.all() {
			if strings.HasPrefix(statement.query, "CREATE") || strings.HasPrefix(statement.query, "ALTER") {
				t.Fatalf("ran DDL after finding a %s: %s", name, statement.query)
			}
		}
	}
}

func TestPostgreSQLMigrationTreatsPartitionedTablesAsTables(t *testing.T) {
	t.Parallel()
	database, recorder := scriptedDatabase(t, func(query string) [][]driver.Value {
		if strings.Contains(query, "pg_catalog.pg_class") {
			return [][]driver.Value{{"p", "id"}, {"p", "name"}}
		}
		return nil
	})
	adapter, err := New(database, PostgreSQL)
	if err != nil {
		t.Fatal(err)
	}
	if err := adapter.Migrate(t.Context(), memberSchema()); err != nil {
		t.Fatal(err)
	}
	var added []string
	for _, statement := range recorder.all() {
		if strings.HasPrefix(statement.query, "ALTER TABLE") {
			added = append(added, statement.query)
		}
	}
	if len(added) != 1 || !strings.Contains(added[0], `ADD COLUMN "count"`) {
		t.Fatalf("partitioned table was not treated as existing: %#v", added)
	}
}

func TestPostgreSQLSchemaCheckReadsColumnRules(t *testing.T) {
	t.Parallel()
	database, recorder := scriptedDatabase(t, func(query string) [][]driver.Value {
		if !strings.Contains(query, "pg_catalog.pg_attribute") {
			return nil
		}
		return [][]driver.Value{
			{"id", false, false},
			{"name", true, false},
			{"legacy", false, false},
			{"serial_key", false, true},
		}
	})
	adapter, err := New(database, PostgreSQL)
	if err != nil {
		t.Fatal(err)
	}
	findings, err := adapter.CheckSchema(t.Context(), memberSchema())
	if err != nil {
		t.Fatal(err)
	}
	want := []betterauth.SchemaFinding{
		{Kind: betterauth.SchemaFindingMissingColumn, Table: "member", Column: "count"},
		{Kind: betterauth.SchemaFindingUnexpectedRequiredColumn, Table: "member", Column: "legacy"},
	}
	if !reflect.DeepEqual(findings, want) {
		t.Fatalf("findings = %#v, want %#v", findings, want)
	}
	statements := recorder.all()
	if len(statements) != 1 || !strings.Contains(statements[0].query, "pg_catalog.current_schemas(true)") {
		t.Fatalf("check did not follow the search_path: %#v", statements)
	}
}
