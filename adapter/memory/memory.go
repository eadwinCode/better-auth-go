// Package memory provides a concurrency-safe adapter for tests, examples, and
// ephemeral development. It is not durable storage.
package memory

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"

	betterauth "github.com/eadwinCode/better-auth-go"
)

type storage struct {
	mu   sync.RWMutex
	rows map[string]map[string]betterauth.Record
}

type Adapter struct {
	storage *storage
	txRows  map[string]map[string]betterauth.Record
	rules   *rules
}

// rules holds what the adapter needs to know about the physical schema. All
// keys are physical (stored) names, because the server maps logical names to
// physical ones before it calls the adapter.
type rules struct {
	// ids maps a stored model name to its stored id field.
	ids map[string]string
	// unique maps a stored model name to its unique keys. Each key is a list
	// of stored field names: one field for a unique field, or several for a
	// unique compound index.
	unique map[string][][]string
}

// New returns an empty adapter that enforces the core schema's unique fields
// and indexes. A server calls WithSchema to replace them with the rules of
// its merged schema.
func New() *Adapter {
	return &Adapter{
		storage: &storage{rows: map[string]map[string]betterauth.Record{}},
		rules:   rulesFromSchema(betterauth.CoreSchema()),
	}
}

// WithSchema returns an adapter that shares this adapter's data and enforces
// the unique fields and unique compound indexes of the given logical schema,
// using their stored model and field names.
func (a *Adapter) WithSchema(schema betterauth.Schema) (betterauth.DatabaseAdapter, error) {
	return &Adapter{storage: a.storage, txRows: a.txRows, rules: rulesFromSchema(schema)}, nil
}

func rulesFromSchema(schema betterauth.Schema) *rules {
	result := &rules{
		ids:    make(map[string]string, len(schema)),
		unique: make(map[string][][]string, len(schema)),
	}
	for logicalModel, model := range schema {
		storedModel := model.ModelName
		if storedModel == "" {
			storedModel = logicalModel
		}
		stored := func(logicalField string) string {
			if name := model.Fields[logicalField].FieldName; name != "" {
				return name
			}
			return logicalField
		}
		idField := stored("id")
		result.ids[storedModel] = idField
		for _, logicalField := range slices.Sorted(maps.Keys(model.Fields)) {
			field := stored(logicalField)
			if model.Fields[logicalField].Unique && field != idField {
				result.unique[storedModel] = append(result.unique[storedModel], []string{field})
			}
		}
		for _, index := range model.Indexes {
			if !index.Unique || len(index.Fields) == 0 {
				continue
			}
			fields := make([]string, len(index.Fields))
			for position, logicalField := range index.Fields {
				fields[position] = stored(logicalField)
			}
			result.unique[storedModel] = append(result.unique[storedModel], fields)
		}
	}
	return result
}

func (a *Adapter) idField(model string) string {
	if a.rules != nil {
		if field := a.rules.ids[model]; field != "" {
			return field
		}
	}
	return "id"
}

func (a *Adapter) uniqueKeys(model string) [][]string {
	if a.rules == nil {
		return nil
	}
	return a.rules.unique[model]
}

func (a *Adapter) ID() string { return "memory" }

func (a *Adapter) Capabilities() betterauth.AdapterCapabilities {
	return betterauth.AdapterCapabilities{
		JSON: true, Dates: true, Booleans: true, Arrays: true, Transactions: true,
	}
}

func (a *Adapter) Create(_ context.Context, query betterauth.CreateQuery) (betterauth.Record, error) {
	return mutateValue(a, func(rows map[string]map[string]betterauth.Record) (betterauth.Record, error) {
		record := cloneRecord(query.Data)
		id, _ := record[a.idField(query.Model)].(string)
		if id == "" {
			return nil, errors.New("memory: record id is required")
		}
		model := ensureModel(rows, query.Model)
		if _, exists := model[id]; exists || a.conflicts(rows, query.Model, record, "") {
			return nil, betterauth.ErrConflict
		}
		model[id] = record
		return project(record, query.Select), nil
	})
}

func (a *Adapter) FindOne(_ context.Context, query betterauth.FindOneQuery) (betterauth.Record, error) {
	if len(query.Joins) > 0 {
		return nil, errors.New("memory: joins are not supported")
	}
	where, err := betterauth.ValidateWhere(query.Where, true)
	if err != nil {
		return nil, err
	}
	return readValue(a, func(rows map[string]map[string]betterauth.Record) (betterauth.Record, error) {
		for _, record := range rows[query.Model] {
			if matches(record, where) {
				return project(record, query.Select), nil
			}
		}
		return nil, nil
	})
}

func (a *Adapter) FindMany(_ context.Context, query betterauth.FindManyQuery) ([]betterauth.Record, error) {
	if len(query.Joins) > 0 {
		return nil, errors.New("memory: joins are not supported")
	}
	where, err := betterauth.ValidateWhere(query.Where, true)
	if err != nil {
		return nil, err
	}
	if query.Limit == 0 {
		query.Limit = 100
	}
	if query.Limit < 0 || query.Limit > 1000 || query.Offset < 0 {
		return nil, errors.New("memory: pagination is out of bounds")
	}
	return readValue(a, func(rows map[string]map[string]betterauth.Record) ([]betterauth.Record, error) {
		result := make([]betterauth.Record, 0)
		for _, record := range rows[query.Model] {
			if matches(record, where) {
				result = append(result, cloneRecord(record))
			}
		}
		if query.Sort != nil {
			slices.SortStableFunc(result, func(left, right betterauth.Record) int {
				order := compare(left[query.Sort.Field], right[query.Sort.Field])
				if query.Sort.Direction == "desc" {
					return -order
				}
				return order
			})
		}
		if query.Offset >= len(result) {
			return []betterauth.Record{}, nil
		}
		result = result[query.Offset:]
		if len(result) > query.Limit {
			result = result[:query.Limit]
		}
		for index := range result {
			result[index] = project(result[index], query.Select)
		}
		return result, nil
	})
}

func (a *Adapter) Count(ctx context.Context, query betterauth.CountQuery) (int64, error) {
	rows, err := a.FindMany(ctx, betterauth.FindManyQuery{Model: query.Model, Where: query.Where, Limit: 1000})
	return int64(len(rows)), err
}

func (a *Adapter) Update(_ context.Context, query betterauth.UpdateQuery) (betterauth.Record, error) {
	where, err := betterauth.ValidateWhere(query.Where, false)
	if err != nil {
		return nil, err
	}
	return mutateValue(a, func(rows map[string]map[string]betterauth.Record) (betterauth.Record, error) {
		for id, record := range rows[query.Model] {
			if !matches(record, where) {
				continue
			}
			updated := cloneRecord(record)
			idField := a.idField(query.Model)
			for field, value := range query.Update {
				if field != idField {
					updated[field] = cloneValue(value)
				}
			}
			if a.conflicts(rows, query.Model, updated, id) {
				return nil, betterauth.ErrConflict
			}
			rows[query.Model][id] = updated
			return cloneRecord(updated), nil
		}
		return nil, nil
	})
}

func (a *Adapter) UpdateMany(_ context.Context, query betterauth.UpdateQuery) (int64, error) {
	where, err := betterauth.ValidateWhere(query.Where, false)
	if err != nil {
		return 0, err
	}
	return mutateValue(a, func(rows map[string]map[string]betterauth.Record) (int64, error) {
		var count int64
		for id, record := range rows[query.Model] {
			if !matches(record, where) {
				continue
			}
			updated := cloneRecord(record)
			idField := a.idField(query.Model)
			for field, value := range query.Update {
				if field != idField {
					updated[field] = cloneValue(value)
				}
			}
			if a.conflicts(rows, query.Model, updated, id) {
				return 0, betterauth.ErrConflict
			}
			rows[query.Model][id] = updated
			count++
		}
		return count, nil
	})
}

func (a *Adapter) Delete(_ context.Context, query betterauth.DeleteQuery) error {
	where, err := betterauth.ValidateWhere(query.Where, false)
	if err != nil {
		return err
	}
	_, err = mutateValue(a, func(rows map[string]map[string]betterauth.Record) (struct{}, error) {
		for id, record := range rows[query.Model] {
			if matches(record, where) {
				delete(rows[query.Model], id)
				break
			}
		}
		return struct{}{}, nil
	})
	return err
}

func (a *Adapter) DeleteMany(_ context.Context, query betterauth.DeleteQuery) (int64, error) {
	where, err := betterauth.ValidateWhere(query.Where, false)
	if err != nil {
		return 0, err
	}
	return mutateValue(a, func(rows map[string]map[string]betterauth.Record) (int64, error) {
		var count int64
		for id, record := range rows[query.Model] {
			if matches(record, where) {
				delete(rows[query.Model], id)
				count++
			}
		}
		return count, nil
	})
}

func (a *Adapter) ConsumeOne(_ context.Context, query betterauth.DeleteQuery) (betterauth.Record, error) {
	where, err := betterauth.ValidateWhere(query.Where, false)
	if err != nil {
		return nil, err
	}
	return mutateValue(a, func(rows map[string]map[string]betterauth.Record) (betterauth.Record, error) {
		for id, record := range rows[query.Model] {
			if matches(record, where) {
				result := cloneRecord(record)
				delete(rows[query.Model], id)
				return result, nil
			}
		}
		return nil, nil
	})
}

func (a *Adapter) IncrementOne(_ context.Context, query betterauth.IncrementQuery) (betterauth.Record, error) {
	where, err := betterauth.ValidateWhere(query.Where, false)
	if err != nil {
		return nil, err
	}
	if len(query.Increment) == 0 {
		return nil, errors.New("memory: increment is empty")
	}
	return mutateValue(a, func(rows map[string]map[string]betterauth.Record) (betterauth.Record, error) {
		for id, record := range rows[query.Model] {
			if !matches(record, where) {
				continue
			}
			updated := cloneRecord(record)
			for field, delta := range query.Increment {
				current, ok := number(updated[field])
				if !ok {
					return nil, fmt.Errorf("memory: %s is not numeric", field)
				}
				updated[field] = current + delta
			}
			idField := a.idField(query.Model)
			for field, value := range query.Set {
				if field != idField {
					updated[field] = cloneValue(value)
				}
			}
			if a.conflicts(rows, query.Model, updated, id) {
				return nil, betterauth.ErrConflict
			}
			rows[query.Model][id] = updated
			return cloneRecord(updated), nil
		}
		return nil, nil
	})
}

func (a *Adapter) Transaction(_ context.Context, callback func(betterauth.DatabaseAdapter) error) error {
	if a.txRows != nil {
		return callback(a)
	}
	a.storage.mu.Lock()
	defer a.storage.mu.Unlock()
	snapshot := cloneRows(a.storage.rows)
	transaction := &Adapter{storage: a.storage, txRows: snapshot, rules: a.rules}
	if err := callback(transaction); err != nil {
		return err
	}
	a.storage.rows = snapshot
	return nil
}

func mutateValue[T any](a *Adapter, operation func(map[string]map[string]betterauth.Record) (T, error)) (T, error) {
	if a.txRows != nil {
		return operation(a.txRows)
	}
	a.storage.mu.Lock()
	defer a.storage.mu.Unlock()
	return operation(a.storage.rows)
}

func readValue[T any](a *Adapter, operation func(map[string]map[string]betterauth.Record) (T, error)) (T, error) {
	if a.txRows != nil {
		return operation(a.txRows)
	}
	a.storage.mu.RLock()
	defer a.storage.mu.RUnlock()
	return operation(a.storage.rows)
}

func ensureModel(rows map[string]map[string]betterauth.Record, model string) map[string]betterauth.Record {
	if rows[model] == nil {
		rows[model] = map[string]betterauth.Record{}
	}
	return rows[model]
}

// conflicts reports whether candidate repeats a unique key of another row in
// the same model. Like SQL, a key with a nil or missing value never collides.
func (a *Adapter) conflicts(
	rows map[string]map[string]betterauth.Record,
	model string,
	candidate betterauth.Record,
	exceptID string,
) bool {
	keys := a.uniqueKeys(model)
	if len(keys) == 0 {
		return false
	}
	for id, existing := range rows[model] {
		if id == exceptID {
			continue
		}
		for _, key := range keys {
			if sameUniqueKey(existing, candidate, key) {
				return true
			}
		}
	}
	return false
}

func sameUniqueKey(left, right betterauth.Record, fields []string) bool {
	for _, field := range fields {
		leftValue, rightValue := left[field], right[field]
		if leftValue == nil || rightValue == nil || !reflect.DeepEqual(leftValue, rightValue) {
			return false
		}
	}
	return true
}

func matches(record betterauth.Record, where []betterauth.Where) bool {
	if len(where) == 0 {
		return true
	}
	andMatch := true
	orPresent := false
	orMatch := false
	for _, condition := range where {
		result := match(record[condition.Field], condition)
		if condition.Connector == betterauth.WhereOR {
			orPresent = true
			orMatch = orMatch || result
		} else {
			andMatch = andMatch && result
		}
	}
	return andMatch && (!orPresent || orMatch)
}

func match(actual any, condition betterauth.Where) bool {
	expected := condition.Value
	if condition.Mode == betterauth.StringInsensitive {
		actual = strings.ToLower(fmt.Sprint(actual))
		expected = strings.ToLower(fmt.Sprint(expected))
	}
	switch condition.Operator {
	case betterauth.WhereEQ:
		return reflect.DeepEqual(actual, expected)
	case betterauth.WhereNE:
		return !reflect.DeepEqual(actual, expected)
	case betterauth.WhereLT:
		return compare(actual, expected) < 0
	case betterauth.WhereLTE:
		return compare(actual, expected) <= 0
	case betterauth.WhereGT:
		return compare(actual, expected) > 0
	case betterauth.WhereGTE:
		return compare(actual, expected) >= 0
	case betterauth.WhereContains:
		return strings.Contains(fmt.Sprint(actual), fmt.Sprint(expected))
	case betterauth.WhereStartsWith:
		return strings.HasPrefix(fmt.Sprint(actual), fmt.Sprint(expected))
	case betterauth.WhereEndsWith:
		return strings.HasSuffix(fmt.Sprint(actual), fmt.Sprint(expected))
	case betterauth.WhereIn, betterauth.WhereNotIn:
		found := false
		value := reflect.ValueOf(expected)
		if value.IsValid() && (value.Kind() == reflect.Slice || value.Kind() == reflect.Array) {
			for index := 0; index < value.Len(); index++ {
				if reflect.DeepEqual(actual, value.Index(index).Interface()) {
					found = true
					break
				}
			}
		}
		if condition.Operator == betterauth.WhereNotIn {
			return !found
		}
		return found
	default:
		return false
	}
}

func compare(left, right any) int {
	if leftTime, ok := left.(time.Time); ok {
		if rightTime, valid := right.(time.Time); valid {
			return leftTime.Compare(rightTime)
		}
	}
	if leftNumber, ok := number(left); ok {
		if rightNumber, valid := number(right); valid {
			return cmp.Compare(leftNumber, rightNumber)
		}
	}
	return strings.Compare(fmt.Sprint(left), fmt.Sprint(right))
}

func number(value any) (float64, bool) {
	switch typed := value.(type) {
	case int:
		return float64(typed), true
	case int64:
		return float64(typed), true
	case float64:
		return typed, true
	case float32:
		return float64(typed), true
	default:
		return 0, false
	}
}

func project(record betterauth.Record, fields []string) betterauth.Record {
	if len(fields) == 0 {
		return cloneRecord(record)
	}
	result := betterauth.Record{}
	for _, field := range fields {
		if value, ok := record[field]; ok {
			result[field] = cloneValue(value)
		}
	}
	return result
}

func cloneRows(input map[string]map[string]betterauth.Record) map[string]map[string]betterauth.Record {
	result := make(map[string]map[string]betterauth.Record, len(input))
	for model, records := range input {
		result[model] = make(map[string]betterauth.Record, len(records))
		for id, record := range records {
			result[model][id] = cloneRecord(record)
		}
	}
	return result
}

func cloneRecord(input betterauth.Record) betterauth.Record {
	result := make(betterauth.Record, len(input))
	for key, value := range input {
		result[key] = cloneValue(value)
	}
	return result
}

func cloneValue(value any) any {
	switch typed := value.(type) {
	case map[string]string:
		result := make(map[string]string, len(typed))
		for key, item := range typed {
			result[key] = item
		}
		return result
	case map[string]any:
		result := make(map[string]any, len(typed))
		for key, item := range typed {
			result[key] = cloneValue(item)
		}
		return result
	case []string:
		return append([]string(nil), typed...)
	case []any:
		result := make([]any, len(typed))
		for index, item := range typed {
			result[index] = cloneValue(item)
		}
		return result
	default:
		return value
	}
}

var (
	_ betterauth.DatabaseAdapter           = (*Adapter)(nil)
	_ betterauth.SchemaConfigurableAdapter = (*Adapter)(nil)
)
