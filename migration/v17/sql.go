package v17

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"unicode"

	betterauth "github.com/eadwinCode/better-auth-go"
)

type SQLDialect string

const (
	PostgreSQL SQLDialect = "postgresql"
	SQLite     SQLDialect = "sqlite"
)

type sqlAccountLayout struct {
	table          string
	issuer         string
	accountID      string
	fields         map[string]betterauth.FieldSchema
	identityIndex  betterauth.IndexSchema
	orderedColumns []string
}

// FinalizeSQL performs the destructive physical cutover only after Backfill
// has succeeded. It validates nulls and collisions again inside the same
// transaction. SQLite also refuses to rewrite a table whose live columns do
// not exactly match the reviewed merged schema.
func FinalizeSQL(
	ctx context.Context,
	db *sql.DB,
	dialect SQLDialect,
	finalSchema betterauth.Schema,
) error {
	if db == nil {
		return errors.New("v17 migration: SQL database is required")
	}
	layout, err := accountLayout(finalSchema)
	if err != nil {
		return err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("v17 migration: begin SQL finalization: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err = validateSQLIdentities(ctx, tx, layout); err != nil {
		return err
	}
	switch dialect {
	case PostgreSQL:
		err = finalizePostgreSQL(ctx, tx, layout)
	case SQLite:
		err = finalizeSQLite(ctx, tx, layout)
	default:
		err = fmt.Errorf("v17 migration: unsupported SQL dialect %q", dialect)
	}
	if err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("v17 migration: commit SQL finalization: %w", err)
	}
	return nil
}

func accountLayout(schema betterauth.Schema) (sqlAccountLayout, error) {
	model, exists := schema[betterauth.ModelAccount]
	if !exists {
		return sqlAccountLayout{}, errors.New("v17 migration: final schema has no account model")
	}
	layout := sqlAccountLayout{table: model.ModelName}
	if layout.table == "" {
		layout.table = betterauth.ModelAccount
	}
	if !safeSQLIdentifier(layout.table) {
		return sqlAccountLayout{}, errors.New("v17 migration: unsafe physical account model name")
	}
	layout.fields = make(map[string]betterauth.FieldSchema, len(model.Fields))
	logicalToPhysical := make(map[string]string, len(model.Fields))
	for logical, definition := range model.Fields {
		physical := definition.FieldName
		if physical == "" {
			physical = logical
		}
		if !safeSQLIdentifier(physical) {
			return sqlAccountLayout{}, fmt.Errorf("v17 migration: unsafe account field %q", physical)
		}
		if _, duplicate := layout.fields[physical]; duplicate {
			return sqlAccountLayout{}, fmt.Errorf("v17 migration: duplicate physical account field %q", physical)
		}
		layout.fields[physical] = definition
		logicalToPhysical[logical] = physical
		layout.orderedColumns = append(layout.orderedColumns, physical)
	}
	sort.Strings(layout.orderedColumns)
	layout.issuer = logicalToPhysical["issuer"]
	layout.accountID = logicalToPhysical["accountId"]
	issuerDefinition, issuerExists := model.Fields["issuer"]
	if !issuerExists || !issuerDefinition.Required || layout.issuer == "" || layout.accountID == "" {
		return sqlAccountLayout{}, errors.New("v17 migration: final account issuer must be required")
	}
	for _, index := range model.Indexes {
		if !index.Unique || len(index.Fields) != 2 ||
			index.Fields[0] != "issuer" || index.Fields[1] != "accountId" {
			continue
		}
		if !safeSQLIdentifier(index.Name) {
			return sqlAccountLayout{}, errors.New("v17 migration: unsafe account identity index name")
		}
		layout.identityIndex = index
		break
	}
	if layout.identityIndex.Name == "" {
		return sqlAccountLayout{}, errors.New("v17 migration: final issuer/accountId unique index is missing")
	}
	return layout, nil
}

func validateSQLIdentities(ctx context.Context, tx *sql.Tx, layout sqlAccountLayout) error {
	var invalid int
	query := "SELECT COUNT(*) FROM " + sqlQuote(layout.table) + " WHERE " +
		sqlQuote(layout.issuer) + " IS NULL OR " + sqlQuote(layout.issuer) + " = ''"
	if err := tx.QueryRowContext(ctx, query).Scan(&invalid); err != nil {
		return fmt.Errorf("v17 migration: validate SQL account issuers: %w", err)
	}
	if invalid != 0 {
		return fmt.Errorf("v17 migration: %d account rows have no issuer", invalid)
	}
	query = "SELECT 1 FROM " + sqlQuote(layout.table) + " GROUP BY " +
		sqlQuote(layout.issuer) + ", " + sqlQuote(layout.accountID) +
		" HAVING COUNT(*) > 1 LIMIT 1"
	var duplicate int
	err := tx.QueryRowContext(ctx, query).Scan(&duplicate)
	if err == nil {
		return errors.New("v17 migration: issuer/accountId collisions remain")
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("v17 migration: validate SQL account collisions: %w", err)
	}
	return nil
}

func finalizePostgreSQL(ctx context.Context, tx *sql.Tx, layout sqlAccountLayout) error {
	for _, legacy := range []string{"uniq_provider_account", "account_provider_account_unique"} {
		if _, err := tx.ExecContext(ctx, "DROP INDEX IF EXISTS "+sqlQuote(legacy)); err != nil {
			return fmt.Errorf("v17 migration: drop PostgreSQL legacy index %s: %w", legacy, err)
		}
	}
	if _, err := tx.ExecContext(ctx, "ALTER TABLE "+sqlQuote(layout.table)+
		" ALTER COLUMN "+sqlQuote(layout.issuer)+" SET NOT NULL"); err != nil {
		return fmt.Errorf("v17 migration: require PostgreSQL account issuer: %w", err)
	}
	statement := "CREATE UNIQUE INDEX IF NOT EXISTS " + sqlQuote(layout.identityIndex.Name) +
		" ON " + sqlQuote(layout.table) + " (" + sqlQuote(layout.issuer) + ", " +
		sqlQuote(layout.accountID) + ")"
	if _, err := tx.ExecContext(ctx, statement); err != nil {
		return fmt.Errorf("v17 migration: create PostgreSQL account identity index: %w", err)
	}
	return nil
}

func finalizeSQLite(ctx context.Context, tx *sql.Tx, layout sqlAccountLayout) error {
	liveColumns, err := sqliteColumns(ctx, tx, layout.table)
	if err != nil {
		return err
	}
	if !slices.Equal(liveColumns, layout.orderedColumns) {
		return fmt.Errorf(
			"v17 migration: SQLite account columns differ from reviewed final schema: live=%v final=%v",
			liveColumns, layout.orderedColumns,
		)
	}
	temporary := layout.table + "__better_auth_v17"
	if !safeSQLIdentifier(temporary) {
		return errors.New("v17 migration: SQLite temporary account table name is unsafe")
	}
	var exists int
	if err = tx.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?", temporary,
	).Scan(&exists); err != nil {
		return fmt.Errorf("v17 migration: inspect SQLite temporary table: %w", err)
	}
	if exists != 0 {
		return errors.New("v17 migration: SQLite temporary account table already exists")
	}
	definitions := make([]string, 0, len(layout.orderedColumns))
	for _, column := range layout.orderedColumns {
		definition := layout.fields[column]
		value := sqlQuote(column) + " " + sqliteType(definition.Type)
		if definition.Required {
			value += " NOT NULL"
		}
		if definition.Unique {
			value += " UNIQUE"
		}
		definitions = append(definitions, value)
	}
	if _, err = tx.ExecContext(ctx, "CREATE TABLE "+sqlQuote(temporary)+" ("+
		strings.Join(definitions, ", ")+")"); err != nil {
		return fmt.Errorf("v17 migration: create SQLite replacement account table: %w", err)
	}
	columns := quotedSQLList(layout.orderedColumns)
	if _, err = tx.ExecContext(ctx, "INSERT INTO "+sqlQuote(temporary)+" ("+columns+") SELECT "+
		columns+" FROM "+sqlQuote(layout.table)); err != nil {
		return fmt.Errorf("v17 migration: copy SQLite account rows: %w", err)
	}
	if _, err = tx.ExecContext(ctx, "DROP TABLE "+sqlQuote(layout.table)); err != nil {
		return fmt.Errorf("v17 migration: replace SQLite account table: %w", err)
	}
	if _, err = tx.ExecContext(ctx, "ALTER TABLE "+sqlQuote(temporary)+" RENAME TO "+
		sqlQuote(layout.table)); err != nil {
		return fmt.Errorf("v17 migration: rename SQLite account table: %w", err)
	}
	for _, index := range layoutIndexes(layout) {
		if _, err = tx.ExecContext(ctx, index); err != nil {
			return fmt.Errorf("v17 migration: create SQLite account index: %w", err)
		}
	}
	rows, err := tx.QueryContext(ctx, "PRAGMA foreign_key_check")
	if err != nil {
		return fmt.Errorf("v17 migration: SQLite foreign-key check: %w", err)
	}
	if rows.Next() {
		_ = rows.Close()
		return errors.New("v17 migration: SQLite foreign-key check failed")
	}
	if err = rows.Close(); err != nil {
		return fmt.Errorf("v17 migration: close SQLite foreign-key check: %w", err)
	}
	var integrity string
	if err = tx.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&integrity); err != nil || integrity != "ok" {
		return fmt.Errorf("v17 migration: SQLite integrity check failed: %s: %w", integrity, err)
	}
	return nil
}

func sqliteColumns(ctx context.Context, tx *sql.Tx, table string) ([]string, error) {
	rows, err := tx.QueryContext(ctx, "PRAGMA table_info("+sqlQuote(table)+")")
	if err != nil {
		return nil, fmt.Errorf("v17 migration: inspect SQLite account columns: %w", err)
	}
	defer rows.Close()
	columns := make([]string, 0)
	for rows.Next() {
		var position, notNull, primaryKey int
		var name, dataType string
		var defaultValue any
		if err = rows.Scan(&position, &name, &dataType, &notNull, &defaultValue, &primaryKey); err != nil {
			return nil, err
		}
		columns = append(columns, name)
	}
	sort.Strings(columns)
	return columns, rows.Err()
}

func layoutIndexes(layout sqlAccountLayout) []string {
	definitions := make([]string, 0)
	for column, field := range layout.fields {
		if field.Unique || !field.Index {
			continue
		}
		name := layout.table + "_" + column + "_index"
		definitions = append(definitions, "CREATE INDEX "+sqlQuote(name)+" ON "+
			sqlQuote(layout.table)+" ("+sqlQuote(column)+")")
	}
	definitions = append(definitions, "CREATE UNIQUE INDEX "+sqlQuote(layout.identityIndex.Name)+
		" ON "+sqlQuote(layout.table)+" ("+sqlQuote(layout.issuer)+", "+
		sqlQuote(layout.accountID)+")")
	sort.Strings(definitions)
	return definitions
}

func sqliteType(fieldType betterauth.FieldType) string {
	switch fieldType {
	case betterauth.FieldNumber:
		return "REAL"
	case betterauth.FieldBoolean:
		return "INTEGER"
	default:
		return "TEXT"
	}
}

func quotedSQLList(values []string) string {
	quoted := make([]string, len(values))
	for index, value := range values {
		quoted[index] = sqlQuote(value)
	}
	return strings.Join(quoted, ", ")
}

func sqlQuote(identifier string) string {
	return `"` + strings.ReplaceAll(identifier, `"`, `""`) + `"`
}

func safeSQLIdentifier(value string) bool {
	if value == "" || len(value) > 96 {
		return false
	}
	for index, character := range value {
		if index == 0 && !unicode.IsLetter(character) && character != '_' {
			return false
		}
		if !unicode.IsLetter(character) && !unicode.IsDigit(character) && character != '_' {
			return false
		}
	}
	return true
}
