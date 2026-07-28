// Package sqladapter implements the shared database/sql adapter used by the
// PostgreSQL and SQLite dialect packages.
package sqladapter

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"sort"
	"strings"
	"unicode"

	betterauth "github.com/eadwinCode/better-auth-go"
)

type Dialect string

const (
	PostgreSQL Dialect = "postgresql"
	SQLite     Dialect = "sqlite"
)

type runner interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// Adapter is a schema-aware database/sql adapter. Call Migrate explicitly
// before serving requests.
type Adapter struct {
	db                   *sql.DB
	tx                   *sql.Tx
	dialect              Dialect
	schema               betterauth.Schema
	accountModel         string
	accountProviderField string
	accountIDField       string
	idFields             map[string]string
}

func New(db *sql.DB, dialect Dialect) (*Adapter, error) {
	if db == nil {
		return nil, errors.New("sqladapter: database is required")
	}
	if dialect != PostgreSQL && dialect != SQLite {
		return nil, fmt.Errorf("sqladapter: unsupported dialect %q", dialect)
	}
	return &Adapter{db: db, dialect: dialect}, nil
}

func (adapter *Adapter) ID() string { return string(adapter.dialect) }

func (adapter *Adapter) Capabilities() betterauth.AdapterCapabilities {
	return betterauth.AdapterCapabilities{Transactions: true}
}

func (adapter *Adapter) WithSchema(schema betterauth.Schema) (betterauth.DatabaseAdapter, error) {
	return adapter.withSchema(schema)
}

func (adapter *Adapter) withSchema(schema betterauth.Schema) (*Adapter, error) {
	physical, err := physicalSchema(schema)
	if err != nil {
		return nil, err
	}
	configured := &Adapter{
		db: adapter.db, tx: adapter.tx, dialect: adapter.dialect, schema: physical,
		idFields: make(map[string]string, len(schema)),
	}
	for logicalName, model := range schema {
		modelName := model.ModelName
		if modelName == "" {
			modelName = logicalName
		}
		id := "id"
		if definition, exists := model.Fields["id"]; exists && definition.FieldName != "" {
			id = definition.FieldName
		}
		configured.idFields[modelName] = id
	}
	if account, exists := schema[betterauth.ModelAccount]; exists {
		configured.accountModel = account.ModelName
		if configured.accountModel == "" {
			configured.accountModel = betterauth.ModelAccount
		}
		if provider, exists := account.Fields["providerId"]; exists {
			configured.accountProviderField = provider.FieldName
			if configured.accountProviderField == "" {
				configured.accountProviderField = "providerId"
			}
		}
		if accountID, exists := account.Fields["accountId"]; exists {
			configured.accountIDField = accountID.FieldName
			if configured.accountIDField == "" {
				configured.accountIDField = "accountId"
			}
		}
	}
	return configured, nil
}

// Migrate creates missing tables and indexes for the supplied merged schema.
// It is additive and never drops or rewrites an existing column.
func (adapter *Adapter) Migrate(ctx context.Context, schema betterauth.Schema) error {
	configured, err := adapter.withSchema(schema)
	if err != nil {
		return err
	}
	return configured.Transaction(ctx, func(transaction betterauth.DatabaseAdapter) error {
		return transaction.(*Adapter).migrate(ctx)
	})
}

func (adapter *Adapter) Create(ctx context.Context, query betterauth.CreateQuery) (betterauth.Record, error) {
	model, err := adapter.model(query.Model)
	if err != nil {
		return nil, err
	}
	if len(query.Data) == 0 {
		return nil, errors.New("sqladapter: create data is empty")
	}
	columns := sortedKeys(query.Data)
	values := make([]any, 0, len(columns))
	placeholders := make([]string, 0, len(columns))
	for _, column := range columns {
		if _, exists := model.Fields[column]; !exists {
			return nil, fmt.Errorf("sqladapter: unknown field %s.%s", query.Model, column)
		}
		values = append(values, query.Data[column])
		placeholders = append(placeholders, adapter.placeholder(len(values)))
	}
	selected, err := adapter.selectColumns(query.Model, query.Select)
	if err != nil {
		return nil, err
	}
	statement := "INSERT INTO " + quote(query.Model) + " (" + quoteList(columns) + ") VALUES (" +
		strings.Join(placeholders, ", ") + ") RETURNING " + quoteList(selected)
	row, err := scanRow(adapter.queryRow(ctx, statement, values...), selected)
	return row, adapter.mapError(err)
}

func (adapter *Adapter) FindOne(ctx context.Context, query betterauth.FindOneQuery) (betterauth.Record, error) {
	if len(query.Joins) > 0 {
		return nil, errors.New("sqladapter: joins are not supported")
	}
	if _, err := adapter.model(query.Model); err != nil {
		return nil, err
	}
	where, args, err := adapter.where(query.Model, query.Where, true)
	if err != nil {
		return nil, err
	}
	selected, err := adapter.selectColumns(query.Model, query.Select)
	if err != nil {
		return nil, err
	}
	statement := "SELECT " + quoteList(selected) + " FROM " + quote(query.Model) + where + " LIMIT 1"
	row, err := scanRow(adapter.queryRow(ctx, statement, args...), selected)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return row, adapter.mapError(err)
}

func (adapter *Adapter) FindMany(ctx context.Context, query betterauth.FindManyQuery) ([]betterauth.Record, error) {
	if len(query.Joins) > 0 {
		return nil, errors.New("sqladapter: joins are not supported")
	}
	if _, err := adapter.model(query.Model); err != nil {
		return nil, err
	}
	if query.Limit == 0 {
		query.Limit = 100
	}
	if query.Limit < 0 || query.Limit > 1000 || query.Offset < 0 {
		return nil, errors.New("sqladapter: pagination is out of bounds")
	}
	where, args, err := adapter.where(query.Model, query.Where, true)
	if err != nil {
		return nil, err
	}
	selected, err := adapter.selectColumns(query.Model, query.Select)
	if err != nil {
		return nil, err
	}
	statement := "SELECT " + quoteList(selected) + " FROM " + quote(query.Model) + where
	if query.Sort != nil {
		if err := adapter.field(query.Model, query.Sort.Field); err != nil {
			return nil, err
		}
		direction := strings.ToUpper(strings.TrimSpace(query.Sort.Direction))
		if direction == "" {
			direction = "ASC"
		}
		if direction != "ASC" && direction != "DESC" {
			return nil, errors.New("sqladapter: invalid sort direction")
		}
		statement += " ORDER BY " + quote(query.Sort.Field) + " " + direction
	}
	args = append(args, query.Limit, query.Offset)
	statement += " LIMIT " + adapter.placeholder(len(args)-1) + " OFFSET " + adapter.placeholder(len(args))
	rows, err := adapter.query(ctx, statement, args...)
	if err != nil {
		return nil, adapter.mapError(err)
	}
	defer rows.Close()
	result := make([]betterauth.Record, 0)
	for rows.Next() {
		record, err := scanRows(rows, selected)
		if err != nil {
			return nil, adapter.mapError(err)
		}
		result = append(result, record)
	}
	if err := rows.Err(); err != nil {
		return nil, adapter.mapError(err)
	}
	return result, nil
}

func (adapter *Adapter) Count(ctx context.Context, query betterauth.CountQuery) (int64, error) {
	if _, err := adapter.model(query.Model); err != nil {
		return 0, err
	}
	where, args, err := adapter.where(query.Model, query.Where, true)
	if err != nil {
		return 0, err
	}
	var count int64
	err = adapter.queryRow(ctx, "SELECT COUNT(*) FROM "+quote(query.Model)+where, args...).Scan(&count)
	return count, adapter.mapError(err)
}

func (adapter *Adapter) Update(ctx context.Context, query betterauth.UpdateQuery) (betterauth.Record, error) {
	if len(query.Update) == 0 {
		return nil, errors.New("sqladapter: update is empty")
	}
	where, args, err := adapter.where(query.Model, query.Where, false)
	if err != nil {
		return nil, err
	}
	assignments, args, err := adapter.assignments(query.Model, query.Update, args)
	if err != nil {
		return nil, err
	}
	if len(assignments) == 0 {
		return nil, errors.New("sqladapter: update has no writable fields")
	}
	selected, err := adapter.selectColumns(query.Model, nil)
	if err != nil {
		return nil, err
	}
	id := adapter.idFields[query.Model]
	statement := "UPDATE " + quote(query.Model) + " SET " + strings.Join(assignments, ", ") +
		" WHERE " + quote(id) + " = (SELECT " + quote(id) + " FROM " + quote(query.Model) +
		where + " LIMIT 1) RETURNING " + quoteList(selected)
	row, err := scanRow(adapter.queryRow(ctx, statement, args...), selected)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return row, adapter.mapError(err)
}

func (adapter *Adapter) UpdateMany(ctx context.Context, query betterauth.UpdateQuery) (int64, error) {
	if len(query.Update) == 0 {
		return 0, errors.New("sqladapter: update is empty")
	}
	where, args, err := adapter.where(query.Model, query.Where, false)
	if err != nil {
		return 0, err
	}
	assignments, args, err := adapter.assignments(query.Model, query.Update, args)
	if err != nil {
		return 0, err
	}
	if len(assignments) == 0 {
		return 0, errors.New("sqladapter: update has no writable fields")
	}
	result, err := adapter.exec(ctx,
		"UPDATE "+quote(query.Model)+" SET "+strings.Join(assignments, ", ")+where, args...,
	)
	if err != nil {
		return 0, adapter.mapError(err)
	}
	return result.RowsAffected()
}

func (adapter *Adapter) Delete(ctx context.Context, query betterauth.DeleteQuery) error {
	where, args, err := adapter.where(query.Model, query.Where, false)
	if err != nil {
		return err
	}
	id := adapter.idFields[query.Model]
	_, err = adapter.exec(ctx, "DELETE FROM "+quote(query.Model)+" WHERE "+quote(id)+
		" = (SELECT "+quote(id)+" FROM "+quote(query.Model)+where+" LIMIT 1)", args...)
	return adapter.mapError(err)
}

func (adapter *Adapter) DeleteMany(ctx context.Context, query betterauth.DeleteQuery) (int64, error) {
	where, args, err := adapter.where(query.Model, query.Where, false)
	if err != nil {
		return 0, err
	}
	result, err := adapter.exec(ctx, "DELETE FROM "+quote(query.Model)+where, args...)
	if err != nil {
		return 0, adapter.mapError(err)
	}
	return result.RowsAffected()
}

func (adapter *Adapter) ConsumeOne(ctx context.Context, query betterauth.DeleteQuery) (betterauth.Record, error) {
	where, args, err := adapter.where(query.Model, query.Where, false)
	if err != nil {
		return nil, err
	}
	selected, err := adapter.selectColumns(query.Model, nil)
	if err != nil {
		return nil, err
	}
	id := adapter.idFields[query.Model]
	statement := "DELETE FROM " + quote(query.Model) + " WHERE " + quote(id) +
		" = (SELECT " + quote(id) + " FROM " + quote(query.Model) +
		where + " LIMIT 1) RETURNING " + quoteList(selected)
	row, err := scanRow(adapter.queryRow(ctx, statement, args...), selected)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return row, adapter.mapError(err)
}

func (adapter *Adapter) IncrementOne(ctx context.Context, query betterauth.IncrementQuery) (betterauth.Record, error) {
	if len(query.Increment) == 0 {
		return nil, errors.New("sqladapter: increment is empty")
	}
	where, args, err := adapter.where(query.Model, query.Where, false)
	if err != nil {
		return nil, err
	}
	assignments := make([]string, 0, len(query.Increment)+len(query.Set))
	for _, field := range sortedKeys(query.Increment) {
		if err := adapter.field(query.Model, field); err != nil {
			return nil, err
		}
		args = append(args, query.Increment[field])
		assignments = append(assignments, quote(field)+" = "+quote(field)+" + "+adapter.placeholder(len(args)))
	}
	setAssignments, args, err := adapter.assignments(query.Model, query.Set, args)
	if err != nil {
		return nil, err
	}
	assignments = append(assignments, setAssignments...)
	selected, err := adapter.selectColumns(query.Model, nil)
	if err != nil {
		return nil, err
	}
	id := adapter.idFields[query.Model]
	statement := "UPDATE " + quote(query.Model) + " SET " + strings.Join(assignments, ", ") +
		" WHERE " + quote(id) + " = (SELECT " + quote(id) + " FROM " + quote(query.Model) +
		where + " LIMIT 1) RETURNING " + quoteList(selected)
	row, err := scanRow(adapter.queryRow(ctx, statement, args...), selected)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return row, adapter.mapError(err)
}

func (adapter *Adapter) Transaction(ctx context.Context, callback func(betterauth.DatabaseAdapter) error) error {
	if callback == nil {
		return errors.New("sqladapter: transaction callback is nil")
	}
	if adapter.tx != nil {
		return callback(adapter)
	}
	tx, err := adapter.db.BeginTx(ctx, nil)
	if err != nil {
		return adapter.mapError(err)
	}
	transaction := &Adapter{
		db: adapter.db, tx: tx, dialect: adapter.dialect, schema: adapter.schema,
		accountModel: adapter.accountModel, accountProviderField: adapter.accountProviderField,
		accountIDField: adapter.accountIDField, idFields: adapter.idFields,
	}
	if err := callback(transaction); err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
			return errors.Join(err, rollbackErr)
		}
		return err
	}
	return adapter.mapError(tx.Commit())
}

func (adapter *Adapter) migrate(ctx context.Context) error {
	models := sortedKeys(adapter.schema)
	for _, name := range models {
		model := adapter.schema[name]
		fields := sortedKeys(model.Fields)
		existing, err := adapter.existingColumns(ctx, name)
		if err != nil {
			return fmt.Errorf("sqladapter: inspect %s: %w", name, err)
		}
		columns := make([]string, 0, len(fields))
		for _, field := range fields {
			definition := model.Fields[field]
			columns = append(columns, adapter.columnDefinition(field, definition, true))
		}
		if _, err := adapter.exec(ctx,
			"CREATE TABLE IF NOT EXISTS "+quote(name)+" ("+strings.Join(columns, ", ")+")",
		); err != nil {
			return fmt.Errorf("sqladapter: migrate %s: %w", name, err)
		}
		for _, field := range fields {
			if existing[field] {
				continue
			}
			// CREATE TABLE populated every field when the table did not exist.
			if len(existing) == 0 {
				continue
			}
			if _, err := adapter.exec(ctx, "ALTER TABLE "+quote(name)+" ADD COLUMN "+
				adapter.columnDefinition(field, model.Fields[field], false)); err != nil {
				return fmt.Errorf("sqladapter: add %s.%s: %w", name, field, err)
			}
		}
		for _, field := range fields {
			definition := model.Fields[field]
			if !definition.Unique && !definition.Index {
				continue
			}
			kind := "index"
			unique := ""
			if definition.Unique {
				kind = "unique"
				unique = "UNIQUE "
			}
			indexName := safeIndexName(name + "_" + field + "_" + kind)
			if _, err := adapter.exec(ctx, "CREATE "+unique+"INDEX IF NOT EXISTS "+quote(indexName)+
				" ON "+quote(name)+" ("+quote(field)+")"); err != nil {
				return fmt.Errorf("sqladapter: index %s.%s: %w", name, field, err)
			}
		}
	}
	if adapter.accountModel != "" && adapter.accountProviderField != "" && adapter.accountIDField != "" {
		if _, exists := adapter.schema[adapter.accountModel]; exists {
			indexName := safeIndexName(adapter.accountModel + "_provider_account_unique")
			_, err := adapter.exec(ctx, "CREATE UNIQUE INDEX IF NOT EXISTS "+quote(indexName)+
				" ON "+quote(adapter.accountModel)+" ("+quote(adapter.accountProviderField)+", "+
				quote(adapter.accountIDField)+")")
			if err != nil {
				return fmt.Errorf("sqladapter: migrate account identity index: %w", err)
			}
		}
	}
	return nil
}

func (adapter *Adapter) existingColumns(ctx context.Context, model string) (map[string]bool, error) {
	var (
		rows *sql.Rows
		err  error
	)
	if adapter.dialect == PostgreSQL {
		rows, err = adapter.query(ctx,
			"SELECT column_name FROM information_schema.columns "+
				"WHERE table_schema = current_schema() AND table_name = "+adapter.placeholder(1),
			model,
		)
	} else {
		rows, err = adapter.query(ctx, "PRAGMA table_info("+quote(model)+")")
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make(map[string]bool)
	for rows.Next() {
		if adapter.dialect == PostgreSQL {
			var name string
			if err := rows.Scan(&name); err != nil {
				return nil, err
			}
			result[name] = true
			continue
		}
		var (
			position     int
			name         string
			dataType     string
			notNull      int
			defaultValue any
			primaryKey   int
		)
		if err := rows.Scan(&position, &name, &dataType, &notNull, &defaultValue, &primaryKey); err != nil {
			return nil, err
		}
		result[name] = true
	}
	return result, rows.Err()
}

func (adapter *Adapter) columnDefinition(
	name string,
	definition betterauth.FieldSchema,
	includeUnique bool,
) string {
	column := quote(name) + " " + adapter.sqlType(definition.Type)
	if definition.Required {
		column += " NOT NULL"
	}
	if includeUnique && definition.Unique {
		column += " UNIQUE"
	}
	return column
}

func (adapter *Adapter) model(name string) (betterauth.ModelSchema, error) {
	if !validIdentifier(name) {
		return betterauth.ModelSchema{}, fmt.Errorf("sqladapter: invalid model %q", name)
	}
	model, exists := adapter.schema[name]
	if !exists {
		return betterauth.ModelSchema{}, fmt.Errorf("sqladapter: unknown model %q", name)
	}
	return model, nil
}

func (adapter *Adapter) field(modelName, field string) error {
	model, err := adapter.model(modelName)
	if err != nil {
		return err
	}
	if !validIdentifier(field) {
		return fmt.Errorf("sqladapter: invalid field %q", field)
	}
	if _, exists := model.Fields[field]; !exists {
		return fmt.Errorf("sqladapter: unknown field %s.%s", modelName, field)
	}
	return nil
}

func (adapter *Adapter) selectColumns(modelName string, requested []string) ([]string, error) {
	model, err := adapter.model(modelName)
	if err != nil {
		return nil, err
	}
	if len(requested) == 0 {
		return sortedKeys(model.Fields), nil
	}
	result := slices.Clone(requested)
	for _, field := range result {
		if err := adapter.field(modelName, field); err != nil {
			return nil, err
		}
	}
	return result, nil
}

func (adapter *Adapter) assignments(
	modelName string,
	update betterauth.Record,
	args []any,
) ([]string, []any, error) {
	fields := sortedKeys(update)
	assignments := make([]string, 0, len(fields))
	for _, field := range fields {
		if field == "id" {
			continue
		}
		if err := adapter.field(modelName, field); err != nil {
			return nil, nil, err
		}
		args = append(args, update[field])
		assignments = append(assignments, quote(field)+" = "+adapter.placeholder(len(args)))
	}
	return assignments, args, nil
}

func (adapter *Adapter) where(
	model string,
	input []betterauth.Where,
	allowEmpty bool,
) (string, []any, error) {
	where, err := betterauth.ValidateWhere(input, allowEmpty)
	if err != nil {
		return "", nil, err
	}
	if _, err := adapter.model(model); err != nil {
		return "", nil, err
	}
	if len(where) == 0 {
		return "", nil, nil
	}
	andParts := make([]string, 0, len(where))
	orParts := make([]string, 0, len(where))
	args := make([]any, 0, len(where))
	for _, condition := range where {
		if err := adapter.field(model, condition.Field); err != nil {
			return "", nil, err
		}
		part, next, err := adapter.condition(condition, args)
		if err != nil {
			return "", nil, err
		}
		args = next
		if condition.Connector == betterauth.WhereOR {
			orParts = append(orParts, part)
		} else {
			andParts = append(andParts, part)
		}
	}
	groups := make([]string, 0, 2)
	if len(andParts) > 0 {
		groups = append(groups, "("+strings.Join(andParts, " AND ")+")")
	}
	if len(orParts) > 0 {
		groups = append(groups, "("+strings.Join(orParts, " OR ")+")")
	}
	return " WHERE " + strings.Join(groups, " AND "), args, nil
}

func (adapter *Adapter) condition(
	condition betterauth.Where,
	args []any,
) (string, []any, error) {
	column := quote(condition.Field)
	if condition.Mode == betterauth.StringInsensitive {
		column = "LOWER(" + column + ")"
	}
	if condition.Value == nil {
		switch condition.Operator {
		case betterauth.WhereEQ:
			return column + " IS NULL", args, nil
		case betterauth.WhereNE:
			return column + " IS NOT NULL", args, nil
		default:
			return "", nil, errors.New("sqladapter: nil only supports equality predicates")
		}
	}
	operator := ""
	value := condition.Value
	switch condition.Operator {
	case betterauth.WhereEQ:
		operator = "="
	case betterauth.WhereNE:
		operator = "<>"
	case betterauth.WhereLT:
		operator = "<"
	case betterauth.WhereLTE:
		operator = "<="
	case betterauth.WhereGT:
		operator = ">"
	case betterauth.WhereGTE:
		operator = ">="
	case betterauth.WhereContains, betterauth.WhereStartsWith, betterauth.WhereEndsWith:
		text, ok := value.(string)
		if !ok {
			return "", nil, errors.New("sqladapter: string predicate requires a string")
		}
		text = strings.NewReplacer("\\", "\\\\", "%", "\\%", "_", "\\_").Replace(text)
		if condition.Operator == betterauth.WhereContains || condition.Operator == betterauth.WhereEndsWith {
			text = "%" + text
		}
		if condition.Operator == betterauth.WhereContains || condition.Operator == betterauth.WhereStartsWith {
			text += "%"
		}
		value, operator = text, "LIKE"
	case betterauth.WhereIn, betterauth.WhereNotIn:
		values := reflect.ValueOf(value)
		if values.Kind() != reflect.Array && values.Kind() != reflect.Slice {
			return "", nil, errors.New("sqladapter: IN predicate requires an array")
		}
		if values.Len() == 0 {
			if condition.Operator == betterauth.WhereIn {
				return "1 = 0", args, nil
			}
			return "1 = 1", args, nil
		}
		placeholders := make([]string, 0, values.Len())
		for index := range values.Len() {
			item := values.Index(index).Interface()
			if condition.Mode == betterauth.StringInsensitive {
				item = strings.ToLower(fmt.Sprint(item))
			}
			args = append(args, item)
			placeholders = append(placeholders, adapter.placeholder(len(args)))
		}
		if condition.Operator == betterauth.WhereIn {
			operator = "IN"
		} else {
			operator = "NOT IN"
		}
		return column + " " + operator + " (" + strings.Join(placeholders, ", ") + ")", args, nil
	default:
		return "", nil, fmt.Errorf("sqladapter: unsupported predicate %q", condition.Operator)
	}
	if condition.Mode == betterauth.StringInsensitive {
		value = strings.ToLower(fmt.Sprint(value))
	}
	args = append(args, value)
	part := column + " " + operator + " " + adapter.placeholder(len(args))
	if operator == "LIKE" {
		part += " ESCAPE '\\'"
	}
	return part, args, nil
}

func (adapter *Adapter) placeholder(position int) string {
	if adapter.dialect == PostgreSQL {
		return fmt.Sprintf("$%d", position)
	}
	return fmt.Sprintf("?%d", position)
}

func (adapter *Adapter) sqlType(fieldType betterauth.FieldType) string {
	switch fieldType {
	case betterauth.FieldNumber:
		if adapter.dialect == PostgreSQL {
			return "DOUBLE PRECISION"
		}
		return "REAL"
	case betterauth.FieldBoolean:
		if adapter.dialect == PostgreSQL {
			return "BIGINT"
		}
		return "INTEGER"
	default:
		return "TEXT"
	}
}

func (adapter *Adapter) exec(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return adapter.runner().ExecContext(ctx, query, args...)
}

func (adapter *Adapter) query(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return adapter.runner().QueryContext(ctx, query, args...)
}

func (adapter *Adapter) queryRow(ctx context.Context, query string, args ...any) *sql.Row {
	return adapter.runner().QueryRowContext(ctx, query, args...)
}

func (adapter *Adapter) runner() runner {
	if adapter.tx != nil {
		return adapter.tx
	}
	return adapter.db
}

func (adapter *Adapter) mapError(err error) error {
	if err == nil || errors.Is(err, sql.ErrNoRows) {
		return err
	}
	message := strings.ToLower(err.Error())
	if strings.Contains(message, "unique constraint") ||
		strings.Contains(message, "duplicate key") ||
		strings.Contains(message, "is not unique") {
		return fmt.Errorf("%w: %v", betterauth.ErrConflict, err)
	}
	return err
}

func scanRow(row *sql.Row, columns []string) (betterauth.Record, error) {
	values := make([]any, len(columns))
	destinations := make([]any, len(columns))
	for index := range values {
		destinations[index] = &values[index]
	}
	if err := row.Scan(destinations...); err != nil {
		return nil, err
	}
	return scannedRecord(columns, values), nil
}

func scanRows(rows *sql.Rows, columns []string) (betterauth.Record, error) {
	values := make([]any, len(columns))
	destinations := make([]any, len(columns))
	for index := range values {
		destinations[index] = &values[index]
	}
	if err := rows.Scan(destinations...); err != nil {
		return nil, err
	}
	return scannedRecord(columns, values), nil
}

func scannedRecord(columns []string, values []any) betterauth.Record {
	record := make(betterauth.Record, len(columns))
	for index, column := range columns {
		value := values[index]
		if bytes, ok := value.([]byte); ok {
			value = string(bytes)
		}
		record[column] = value
	}
	return record
}

func physicalSchema(schema betterauth.Schema) (betterauth.Schema, error) {
	result := make(betterauth.Schema, len(schema))
	for logicalName, logicalModel := range schema {
		name := logicalModel.ModelName
		if name == "" {
			name = logicalName
		}
		if !validIdentifier(name) {
			return nil, fmt.Errorf("sqladapter: invalid model name %q", name)
		}
		model := betterauth.ModelSchema{Fields: make(map[string]betterauth.FieldSchema, len(logicalModel.Fields))}
		for logicalField, definition := range logicalModel.Fields {
			field := definition.FieldName
			if field == "" {
				field = logicalField
			}
			if !validIdentifier(field) {
				return nil, fmt.Errorf("sqladapter: invalid field name %q", field)
			}
			model.Fields[field] = definition
		}
		idDefinition, exists := logicalModel.Fields["id"]
		if !exists {
			return nil, fmt.Errorf("sqladapter: model %q must define an id field", name)
		}
		idField := idDefinition.FieldName
		if idField == "" {
			idField = "id"
		}
		if _, exists := model.Fields[idField]; !exists {
			return nil, fmt.Errorf("sqladapter: model %q has an invalid id mapping", name)
		}
		result[name] = model
	}
	return result, nil
}

func validIdentifier(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for index, character := range value {
		if index == 0 {
			if character != '_' && !unicode.IsLetter(character) {
				return false
			}
			continue
		}
		if character != '_' && !unicode.IsLetter(character) && !unicode.IsDigit(character) {
			return false
		}
	}
	return true
}

func safeIndexName(value string) string {
	if validIdentifier(value) {
		return value
	}
	sum := sha256.Sum256([]byte(value))
	return "better_auth_" + hex.EncodeToString(sum[:8])
}

func quote(identifier string) string {
	return `"` + strings.ReplaceAll(identifier, `"`, `""`) + `"`
}

func quoteList(values []string) string {
	quoted := make([]string, len(values))
	for index, value := range values {
		quoted[index] = quote(value)
	}
	return strings.Join(quoted, ", ")
}

func sortedKeys[M ~map[string]V, V any](values M) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

var _ betterauth.DatabaseAdapter = (*Adapter)(nil)
var _ betterauth.SchemaConfigurableAdapter = (*Adapter)(nil)
