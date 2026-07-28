package betterauth

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"
)

type schemaAdapter struct {
	inner  DatabaseAdapter
	schema Schema
}

// WrapDatabaseAdapter applies model/field mapping and capability-aware value
// transforms to an adapter. Server construction applies this automatically.
func WrapDatabaseAdapter(inner DatabaseAdapter, schema Schema) (DatabaseAdapter, error) {
	if inner == nil {
		return nil, fmt.Errorf("betterauth: database adapter is required")
	}
	if err := validateSchema(schema); err != nil {
		return nil, err
	}
	return &schemaAdapter{inner: inner, schema: schema}, nil
}

func (a *schemaAdapter) ID() string                        { return a.inner.ID() }
func (a *schemaAdapter) Capabilities() AdapterCapabilities { return a.inner.Capabilities() }

func (a *schemaAdapter) Create(ctx context.Context, query CreateQuery) (Record, error) {
	logicalModel := query.Model
	query.Model = a.model(query.Model)
	query.Data = a.inputRecord(logicalModel, query.Data)
	query.Select = a.fields(logicalModel, query.Select)
	record, err := a.inner.Create(ctx, query)
	return a.outputRecord(logicalModel, record), err
}

func (a *schemaAdapter) FindOne(ctx context.Context, query FindOneQuery) (Record, error) {
	logicalModel := query.Model
	query.Model = a.model(query.Model)
	query.Where = a.where(logicalModel, query.Where)
	query.Select = a.fields(logicalModel, query.Select)
	query.Joins = a.joins(query.Joins)
	record, err := a.inner.FindOne(ctx, query)
	return a.outputRecord(logicalModel, record), err
}

func (a *schemaAdapter) FindMany(ctx context.Context, query FindManyQuery) ([]Record, error) {
	logicalModel := query.Model
	query.Model = a.model(query.Model)
	query.Where = a.where(logicalModel, query.Where)
	query.Select = a.fields(logicalModel, query.Select)
	query.Joins = a.joins(query.Joins)
	if query.Sort != nil {
		copySort := *query.Sort
		copySort.Field = a.field(logicalModel, copySort.Field)
		query.Sort = &copySort
	}
	records, err := a.inner.FindMany(ctx, query)
	for index := range records {
		records[index] = a.outputRecord(logicalModel, records[index])
	}
	return records, err
}

func (a *schemaAdapter) Count(ctx context.Context, query CountQuery) (int64, error) {
	logicalModel := query.Model
	query.Model = a.model(query.Model)
	query.Where = a.where(logicalModel, query.Where)
	return a.inner.Count(ctx, query)
}

func (a *schemaAdapter) Update(ctx context.Context, query UpdateQuery) (Record, error) {
	logicalModel := query.Model
	query.Model = a.model(query.Model)
	query.Where = a.where(logicalModel, query.Where)
	query.Update = a.inputRecord(logicalModel, query.Update)
	record, err := a.inner.Update(ctx, query)
	return a.outputRecord(logicalModel, record), err
}

func (a *schemaAdapter) UpdateMany(ctx context.Context, query UpdateQuery) (int64, error) {
	logicalModel := query.Model
	query.Model = a.model(query.Model)
	query.Where = a.where(logicalModel, query.Where)
	query.Update = a.inputRecord(logicalModel, query.Update)
	return a.inner.UpdateMany(ctx, query)
}

func (a *schemaAdapter) Delete(ctx context.Context, query DeleteQuery) error {
	logicalModel := query.Model
	query.Model = a.model(query.Model)
	query.Where = a.where(logicalModel, query.Where)
	return a.inner.Delete(ctx, query)
}

func (a *schemaAdapter) DeleteMany(ctx context.Context, query DeleteQuery) (int64, error) {
	logicalModel := query.Model
	query.Model = a.model(query.Model)
	query.Where = a.where(logicalModel, query.Where)
	return a.inner.DeleteMany(ctx, query)
}

func (a *schemaAdapter) ConsumeOne(ctx context.Context, query DeleteQuery) (Record, error) {
	logicalModel := query.Model
	query.Model = a.model(query.Model)
	query.Where = a.where(logicalModel, query.Where)
	record, err := a.inner.ConsumeOne(ctx, query)
	return a.outputRecord(logicalModel, record), err
}

func (a *schemaAdapter) IncrementOne(ctx context.Context, query IncrementQuery) (Record, error) {
	logicalModel := query.Model
	query.Model = a.model(query.Model)
	query.Where = a.where(logicalModel, query.Where)
	increment := make(map[string]float64, len(query.Increment))
	for field, value := range query.Increment {
		increment[a.field(logicalModel, field)] = value
	}
	query.Increment = increment
	query.Set = a.inputRecord(logicalModel, query.Set)
	record, err := a.inner.IncrementOne(ctx, query)
	return a.outputRecord(logicalModel, record), err
}

func (a *schemaAdapter) Transaction(ctx context.Context, callback func(DatabaseAdapter) error) error {
	return a.inner.Transaction(ctx, func(transaction DatabaseAdapter) error {
		return callback(&schemaAdapter{inner: transaction, schema: a.schema})
	})
}

func (a *schemaAdapter) model(logical string) string {
	if model, ok := a.schema[logical]; ok && model.ModelName != "" {
		return model.ModelName
	}
	return logical
}

func (a *schemaAdapter) field(model, logical string) string {
	if definition, ok := a.schema[model].Fields[logical]; ok && definition.FieldName != "" {
		return definition.FieldName
	}
	return logical
}

func (a *schemaAdapter) logicalField(model, stored string) string {
	for logical, definition := range a.schema[model].Fields {
		if definition.FieldName == stored {
			return logical
		}
	}
	return stored
}

func (a *schemaAdapter) fields(model string, values []string) []string {
	if len(values) == 0 {
		return nil
	}
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = a.field(model, value)
	}
	return result
}

func (a *schemaAdapter) where(model string, values []Where) []Where {
	result := make([]Where, len(values))
	for index, value := range values {
		logicalField := value.Field
		value.Field = a.field(model, logicalField)
		value.Value = a.inputValue(model, logicalField, value.Value)
		result[index] = value
	}
	return result
}

func (a *schemaAdapter) joins(values []Join) []Join {
	result := make([]Join, len(values))
	for index, value := range values {
		logicalModel := value.Model
		value.Model = a.model(logicalModel)
		value.From = a.field(logicalModel, value.From)
		value.To = a.field(logicalModel, value.To)
		result[index] = value
	}
	return result
}

func (a *schemaAdapter) inputRecord(model string, record Record) Record {
	if record == nil {
		return nil
	}
	result := make(Record, len(record))
	for logical, value := range record {
		result[a.field(model, logical)] = a.inputValue(model, logical, value)
	}
	return result
}

func (a *schemaAdapter) outputRecord(model string, record Record) Record {
	if record == nil {
		return nil
	}
	result := make(Record, len(record))
	for stored, value := range record {
		logical := a.logicalField(model, stored)
		result[logical] = a.outputValue(model, logical, value)
	}
	return result
}

func (a *schemaAdapter) inputValue(model, field string, value any) any {
	if value == nil {
		return nil
	}
	definition, known := a.schema[model].Fields[field]
	if !known {
		return value
	}
	capabilities := a.inner.Capabilities()
	switch definition.Type {
	case FieldDate:
		if !capabilities.Dates {
			if date, ok := value.(time.Time); ok {
				return date.UTC().Format(time.RFC3339Nano)
			}
		}
	case FieldBoolean:
		if !capabilities.Booleans {
			if boolean, ok := value.(bool); ok {
				if boolean {
					return 1
				}
				return 0
			}
		}
	case FieldJSON:
		if !capabilities.JSON {
			encoded, err := json.Marshal(value)
			if err == nil {
				return string(encoded)
			}
		}
	case FieldStringArray:
		if !capabilities.Arrays {
			encoded, err := json.Marshal(value)
			if err == nil {
				return string(encoded)
			}
		}
	}
	return value
}

func (a *schemaAdapter) outputValue(model, field string, value any) any {
	if value == nil {
		return nil
	}
	definition, known := a.schema[model].Fields[field]
	if !known {
		return value
	}
	capabilities := a.inner.Capabilities()
	switch definition.Type {
	case FieldDate:
		if !capabilities.Dates {
			if text, ok := value.(string); ok {
				parsed, err := time.Parse(time.RFC3339Nano, text)
				if err == nil {
					return parsed.UTC()
				}
			}
		}
	case FieldBoolean:
		if !capabilities.Booleans {
			switch typed := value.(type) {
			case int:
				return typed != 0
			case int64:
				return typed != 0
			case float64:
				return typed != 0
			case string:
				parsed, _ := strconv.ParseBool(typed)
				return parsed
			}
		}
	case FieldJSON, FieldStringArray:
		unsupported := definition.Type == FieldJSON && !capabilities.JSON ||
			definition.Type == FieldStringArray && !capabilities.Arrays
		if unsupported {
			if text, ok := value.(string); ok {
				var decoded any
				if err := json.Unmarshal([]byte(text), &decoded); err == nil {
					return decoded
				}
			}
		}
	}
	return value
}

func validateSchema(schema Schema) error {
	storedModels := map[string]string{}
	for logical, model := range schema {
		stored := model.ModelName
		if stored == "" {
			stored = logical
		}
		if previous, exists := storedModels[stored]; exists && previous != logical {
			return fmt.Errorf("betterauth: models %s and %s map to %s", previous, logical, stored)
		}
		storedModels[stored] = logical
		storedFields := map[string]string{}
		for logicalField, definition := range model.Fields {
			storedField := definition.FieldName
			if storedField == "" {
				storedField = logicalField
			}
			if previous, exists := storedFields[storedField]; exists && previous != logicalField {
				return fmt.Errorf("betterauth: fields %s.%s and %s.%s collide", logical, previous, logical, logicalField)
			}
			storedFields[storedField] = logicalField
		}
	}
	return nil
}

var _ DatabaseAdapter = (*schemaAdapter)(nil)
