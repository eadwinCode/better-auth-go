package sqladapter

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	betterauth "github.com/eadwinCode/better-auth-go"
)

// postgreSQLRelationKinds names pg_class.relkind values for error messages.
var postgreSQLRelationKinds = map[string]string{
	"v": "view",
	"m": "materialized view",
	"f": "foreign table",
	"S": "sequence",
	"i": "index",
	"I": "partitioned index",
	"c": "composite type",
	"t": "TOAST table",
}

// existingPostgreSQLColumns reads the columns of model in the target schema:
// the configured schema, or current_schema() when none is set. Only ordinary
// and partitioned tables count. A view or any other relation with the same
// name is an error, because CREATE TABLE IF NOT EXISTS would quietly skip it
// and later ALTER TABLE or CREATE INDEX statements would fail with a
// confusing message.
func (adapter *Adapter) existingPostgreSQLColumns(ctx context.Context, model string) (map[string]bool, error) {
	schema := "pg_catalog.current_schema()"
	args := []any{model}
	if adapter.schemaName != "" {
		schema = "$2"
		args = append(args, adapter.schemaName)
	}
	rows, err := adapter.query(ctx,
		"SELECT c.relkind::text, a.attname::text FROM pg_catalog.pg_class c "+
			"JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "+
			"LEFT JOIN pg_catalog.pg_attribute a ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped "+
			"WHERE n.nspname = "+schema+" AND c.relname = $1 ORDER BY a.attnum",
		args...,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make(map[string]bool)
	kind := ""
	for rows.Next() {
		var column sql.NullString
		if err := rows.Scan(&kind, &column); err != nil {
			return nil, err
		}
		if column.Valid {
			result[column.String] = true
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	switch kind {
	case "", "r", "p":
		return result, nil
	default:
		name, known := postgreSQLRelationKinds[kind]
		if !known {
			name = "relation of kind " + kind
		}
		return nil, fmt.Errorf(
			"%s is a %s, not a table; rename or drop it so Migrate can create the table",
			adapter.table(model), name,
		)
	}
}

// CheckSchema reads the live tables that schema writes and returns every
// problem DiffSchema finds. On PostgreSQL it looks only in the configured
// schema when one is set, and otherwise in the first schema on the
// search_path that holds a table or view with that name. It implements
// betterauth.SchemaChecker.
func (adapter *Adapter) CheckSchema(
	ctx context.Context,
	schema betterauth.Schema,
) ([]betterauth.SchemaFinding, error) {
	expected := betterauth.ExpectedTables(schema)
	tables := make([]betterauth.IntrospectedTable, 0, len(expected))
	for _, table := range expected {
		var (
			columns []betterauth.IntrospectedColumn
			found   bool
			err     error
		)
		if adapter.dialect == PostgreSQL {
			columns, found, err = adapter.introspectPostgreSQLTable(ctx, table.Name)
		} else {
			columns, found, err = adapter.introspectSQLiteTable(ctx, table.Name)
		}
		if err != nil {
			return nil, fmt.Errorf("sqladapter: check schema of %s: %w", table.Name, err)
		}
		if found {
			tables = append(tables, betterauth.IntrospectedTable{Name: table.Name, Columns: columns})
		}
	}
	return betterauth.DiffSchema(schema, tables), nil
}

func (adapter *Adapter) introspectPostgreSQLTable(
	ctx context.Context,
	name string,
) ([]betterauth.IntrospectedColumn, bool, error) {
	// Ordinary tables, views, and partitioned tables, as Better Auth's
	// Kysely introspection reports them.
	target := "SELECT c.oid FROM pg_catalog.pg_class c " +
		"JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "
	args := []any{name}
	if adapter.schemaName != "" {
		target += "WHERE n.nspname = $2 AND c.relname = $1 AND c.relkind IN ('r', 'v', 'p')"
		args = append(args, adapter.schemaName)
	} else {
		target += "JOIN unnest(pg_catalog.current_schemas(true)) WITH ORDINALITY AS s(schema_name, ordinal) " +
			"ON s.schema_name = n.nspname " +
			"WHERE c.relname = $1 AND c.relkind IN ('r', 'v', 'p') " +
			"AND n.nspname !~ '^pg_' AND n.nspname <> 'information_schema' " +
			"ORDER BY s.ordinal LIMIT 1"
	}
	rows, err := adapter.query(ctx,
		"WITH target AS ("+target+") "+
			"SELECT a.attname::text, NOT a.attnotnull, (a.atthasdef OR a.attidentity <> '') "+
			"FROM target LEFT JOIN pg_catalog.pg_attribute a "+
			"ON a.attrelid = target.oid AND a.attnum > 0 AND NOT a.attisdropped "+
			"ORDER BY a.attnum",
		args...,
	)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	found := false
	columns := make([]betterauth.IntrospectedColumn, 0)
	for rows.Next() {
		found = true
		var (
			column     sql.NullString
			nullable   sql.NullBool
			hasDefault sql.NullBool
		)
		if err := rows.Scan(&column, &nullable, &hasDefault); err != nil {
			return nil, false, err
		}
		if !column.Valid {
			continue
		}
		columns = append(columns, betterauth.IntrospectedColumn{
			Name: column.String, Nullable: nullable.Bool, HasDefault: hasDefault.Bool,
		})
	}
	return columns, found, rows.Err()
}

func (adapter *Adapter) introspectSQLiteTable(
	ctx context.Context,
	name string,
) ([]betterauth.IntrospectedColumn, bool, error) {
	rows, err := adapter.query(ctx, "PRAGMA table_info("+quote(name)+")")
	if err != nil {
		return nil, false, err
	}
	columns := make([]betterauth.IntrospectedColumn, 0)
	primaryKeys := make([]int, 0, 1)
	types := make([]string, 0)
	for rows.Next() {
		var (
			position     int
			column       string
			dataType     string
			notNull      int
			defaultValue any
			primaryKey   int
		)
		if err := rows.Scan(&position, &column, &dataType, &notNull, &defaultValue, &primaryKey); err != nil {
			_ = rows.Close()
			return nil, false, err
		}
		if primaryKey > 0 {
			primaryKeys = append(primaryKeys, len(columns))
		}
		types = append(types, dataType)
		columns = append(columns, betterauth.IntrospectedColumn{
			Name: column, Nullable: notNull == 0, HasDefault: defaultValue != nil,
		})
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, false, err
	}
	_ = rows.Close()
	if len(columns) == 0 {
		return nil, false, nil
	}
	// A lone INTEGER PRIMARY KEY column is the rowid, which SQLite fills
	// itself, unless the key is backed by its own index.
	if len(primaryKeys) == 1 && strings.EqualFold(types[primaryKeys[0]], "integer") {
		generated, err := adapter.sqliteRowIDAlias(ctx, name)
		if err != nil {
			return nil, false, err
		}
		if generated {
			columns[primaryKeys[0]].HasDefault = true
		}
	}
	return columns, true, nil
}

func (adapter *Adapter) sqliteRowIDAlias(ctx context.Context, name string) (bool, error) {
	rows, err := adapter.query(ctx, "PRAGMA index_list("+quote(name)+")")
	if err != nil {
		return false, err
	}
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		return false, err
	}
	originIndex := -1
	for index, column := range columns {
		if column == "origin" {
			originIndex = index
		}
	}
	for rows.Next() {
		values := make([]any, len(columns))
		destinations := make([]any, len(columns))
		for index := range values {
			destinations[index] = &values[index]
		}
		if err := rows.Scan(destinations...); err != nil {
			return false, err
		}
		if originIndex < 0 {
			continue
		}
		origin := values[originIndex]
		if bytes, ok := origin.([]byte); ok {
			origin = string(bytes)
		}
		if origin == "pk" {
			return false, nil
		}
	}
	return true, rows.Err()
}

var _ betterauth.SchemaChecker = (*Adapter)(nil)
