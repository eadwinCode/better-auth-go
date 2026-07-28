package betterauth

import (
	"context"
	"fmt"
)

// Record is a schema-neutral database row. Adapter factories transform logical
// model and field names before a raw database adapter receives it.
type Record map[string]any

type WhereOperator string

const (
	WhereEQ         WhereOperator = "eq"
	WhereNE         WhereOperator = "ne"
	WhereLT         WhereOperator = "lt"
	WhereLTE        WhereOperator = "lte"
	WhereGT         WhereOperator = "gt"
	WhereGTE        WhereOperator = "gte"
	WhereIn         WhereOperator = "in"
	WhereNotIn      WhereOperator = "not_in"
	WhereContains   WhereOperator = "contains"
	WhereStartsWith WhereOperator = "starts_with"
	WhereEndsWith   WhereOperator = "ends_with"
)

type WhereConnector string

const (
	WhereAND WhereConnector = "AND"
	WhereOR  WhereConnector = "OR"
)

type StringMode string

const (
	StringSensitive   StringMode = "sensitive"
	StringInsensitive StringMode = "insensitive"
)

type Where struct {
	Field     string
	Operator  WhereOperator
	Value     any
	Connector WhereConnector
	Mode      StringMode
}

func Eq(field string, value any) Where {
	return Where{Field: field, Operator: WhereEQ, Connector: WhereAND, Mode: StringSensitive, Value: value}
}

type JoinRelation string

const (
	JoinOneToOne   JoinRelation = "one-to-one"
	JoinOneToMany  JoinRelation = "one-to-many"
	JoinManyToMany JoinRelation = "many-to-many"
)

type Join struct {
	Model    string
	From     string
	To       string
	Limit    int
	Relation JoinRelation
}

type Sort struct {
	Field     string
	Direction string
}

type CreateQuery struct {
	Model        string
	Data         Record
	Select       []string
	ForceAllowID bool
}

type FindOneQuery struct {
	Model  string
	Where  []Where
	Select []string
	Joins  []Join
}

type FindManyQuery struct {
	Model  string
	Where  []Where
	Limit  int
	Offset int
	Select []string
	Sort   *Sort
	Joins  []Join
}

type CountQuery struct {
	Model string
	Where []Where
}

type UpdateQuery struct {
	Model  string
	Where  []Where
	Update Record
}

type DeleteQuery struct {
	Model string
	Where []Where
}

type IncrementQuery struct {
	Model     string
	Where     []Where
	Increment map[string]float64
	Set       Record
}

// AdapterCapabilities describe native storage behavior.
type AdapterCapabilities struct {
	JSON         bool
	Dates        bool
	Booleans     bool
	Arrays       bool
	NumericIDs   bool
	UUIDs        bool
	Joins        bool
	Transactions bool
}

// DatabaseAdapter follows Better Auth's database adapter vocabulary. Single-row
// update/delete methods reject an empty predicate.
type DatabaseAdapter interface {
	ID() string
	Capabilities() AdapterCapabilities
	Create(context.Context, CreateQuery) (Record, error)
	FindOne(context.Context, FindOneQuery) (Record, error)
	FindMany(context.Context, FindManyQuery) ([]Record, error)
	Count(context.Context, CountQuery) (int64, error)
	Update(context.Context, UpdateQuery) (Record, error)
	UpdateMany(context.Context, UpdateQuery) (int64, error)
	Delete(context.Context, DeleteQuery) error
	DeleteMany(context.Context, DeleteQuery) (int64, error)
	ConsumeOne(context.Context, DeleteQuery) (Record, error)
	IncrementOne(context.Context, IncrementQuery) (Record, error)
	Transaction(context.Context, func(DatabaseAdapter) error) error
}

// SchemaConfigurableAdapter receives the fully merged logical schema before
// the server applies logical-to-physical query mapping. Adapters with a fixed
// schema do not need to implement it.
type SchemaConfigurableAdapter interface {
	WithSchema(Schema) (DatabaseAdapter, error)
}

// ValidateWhere applies contract defaults and rejects malformed predicates.
func ValidateWhere(where []Where, allowEmpty bool) ([]Where, error) {
	if len(where) == 0 && !allowEmpty {
		return nil, fmt.Errorf("betterauth: empty where clause is unsafe")
	}
	result := make([]Where, len(where))
	for i, item := range where {
		if item.Field == "" {
			return nil, fmt.Errorf("betterauth: where field is required")
		}
		if item.Operator == "" {
			item.Operator = WhereEQ
		}
		switch item.Operator {
		case WhereEQ, WhereNE, WhereLT, WhereLTE, WhereGT, WhereGTE, WhereIn, WhereNotIn, WhereContains, WhereStartsWith, WhereEndsWith:
		default:
			return nil, fmt.Errorf("betterauth: unsupported where operator %q", item.Operator)
		}
		if item.Connector == "" {
			item.Connector = WhereAND
		}
		if item.Connector != WhereAND && item.Connector != WhereOR {
			return nil, fmt.Errorf("betterauth: unsupported where connector %q", item.Connector)
		}
		if item.Mode == "" {
			item.Mode = StringSensitive
		}
		if item.Mode != StringSensitive && item.Mode != StringInsensitive {
			return nil, fmt.Errorf("betterauth: unsupported string mode %q", item.Mode)
		}
		result[i] = item
	}
	return result, nil
}
