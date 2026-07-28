// Package mongodb implements the generic Better Auth database adapter contract.
package mongodb

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	betterauth "github.com/eadwinCode/better-auth-go"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type Config struct {
	Database    *mongo.Database
	Collections map[string]string
}

type Adapter struct {
	database    *mongo.Database
	collections map[string]string
	transaction context.Context
}

func New(config Config) (*Adapter, error) {
	if config.Database == nil {
		return nil, errors.New("mongodb: database is required")
	}
	collections := map[string]string{
		betterauth.ModelUser: "user", betterauth.ModelSession: "session",
		betterauth.ModelAccount: "account", betterauth.ModelVerification: "verification",
		betterauth.ModelAuditEvent: "auditEvent", betterauth.ModelOutboxEvent: "outboxEvent",
	}
	for model, collection := range config.Collections {
		if model == "" || collection == "" || strings.Contains(collection, "$") || strings.ContainsRune(collection, '\x00') {
			return nil, fmt.Errorf("mongodb: invalid collection mapping")
		}
		collections[model] = collection
	}
	return &Adapter{database: config.Database, collections: collections}, nil
}

func (a *Adapter) ID() string { return "mongodb" }

func (a *Adapter) Capabilities() betterauth.AdapterCapabilities {
	return betterauth.AdapterCapabilities{
		JSON: true, Dates: true, Booleans: true, Arrays: true, UUIDs: false,
		NumericIDs: false, Joins: false, Transactions: true,
	}
}

func (a *Adapter) Create(ctx context.Context, query betterauth.CreateQuery) (betterauth.Record, error) {
	if err := validateModel(query.Model); err != nil {
		return nil, err
	}
	document := toMongoRecord(query.Data)
	_, err := a.collection(query.Model).InsertOne(a.ctx(ctx), document)
	if err != nil {
		return nil, translateError(err)
	}
	return projectRecord(fromMongoRecord(document), query.Select), nil
}

func (a *Adapter) FindOne(ctx context.Context, query betterauth.FindOneQuery) (betterauth.Record, error) {
	if len(query.Joins) > 0 {
		return nil, errors.New("mongodb: joins are not supported")
	}
	filter, err := buildFilter(query.Where, true)
	if err != nil {
		return nil, err
	}
	var document bson.M
	err = a.collection(query.Model).FindOne(a.ctx(ctx), filter, options.FindOne().SetProjection(buildProjection(query.Select))).Decode(&document)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, nil
	}
	if err != nil {
		return nil, translateError(err)
	}
	return fromMongoRecord(document), nil
}

func (a *Adapter) FindMany(ctx context.Context, query betterauth.FindManyQuery) ([]betterauth.Record, error) {
	if len(query.Joins) > 0 {
		return nil, errors.New("mongodb: joins are not supported")
	}
	filter, err := buildFilter(query.Where, true)
	if err != nil {
		return nil, err
	}
	if query.Limit == 0 {
		query.Limit = 100
	}
	if query.Limit < 0 || query.Limit > 1000 || query.Offset < 0 {
		return nil, errors.New("mongodb: pagination is out of bounds")
	}
	findOptions := options.Find().
		SetLimit(int64(query.Limit)).
		SetSkip(int64(query.Offset)).
		SetProjection(buildProjection(query.Select))
	if query.Sort != nil {
		direction := 1
		if query.Sort.Direction == "desc" {
			direction = -1
		} else if query.Sort.Direction != "" && query.Sort.Direction != "asc" {
			return nil, errors.New("mongodb: invalid sort direction")
		}
		findOptions.SetSort(bson.D{{Key: mongoField(query.Sort.Field), Value: direction}})
	}
	cursor, err := a.collection(query.Model).Find(a.ctx(ctx), filter, findOptions)
	if err != nil {
		return nil, translateError(err)
	}
	defer cursor.Close(a.ctx(ctx))
	var documents []bson.M
	if err := cursor.All(a.ctx(ctx), &documents); err != nil {
		return nil, translateError(err)
	}
	result := make([]betterauth.Record, 0, len(documents))
	for _, document := range documents {
		result = append(result, fromMongoRecord(document))
	}
	return result, nil
}

func (a *Adapter) Count(ctx context.Context, query betterauth.CountQuery) (int64, error) {
	filter, err := buildFilter(query.Where, true)
	if err != nil {
		return 0, err
	}
	count, err := a.collection(query.Model).CountDocuments(a.ctx(ctx), filter)
	return count, translateError(err)
}

func (a *Adapter) Update(ctx context.Context, query betterauth.UpdateQuery) (betterauth.Record, error) {
	filter, err := buildFilter(query.Where, false)
	if err != nil {
		return nil, err
	}
	update := toMongoRecord(query.Update)
	delete(update, "_id")
	if len(update) == 0 {
		return nil, errors.New("mongodb: empty update")
	}
	var document bson.M
	err = a.collection(query.Model).FindOneAndUpdate(
		a.ctx(ctx), filter, bson.M{"$set": update},
		options.FindOneAndUpdate().SetReturnDocument(options.After),
	).Decode(&document)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, nil
	}
	if err != nil {
		return nil, translateError(err)
	}
	return fromMongoRecord(document), nil
}

func (a *Adapter) UpdateMany(ctx context.Context, query betterauth.UpdateQuery) (int64, error) {
	filter, err := buildFilter(query.Where, false)
	if err != nil {
		return 0, err
	}
	update := toMongoRecord(query.Update)
	delete(update, "_id")
	if len(update) == 0 {
		return 0, errors.New("mongodb: empty update")
	}
	result, err := a.collection(query.Model).UpdateMany(a.ctx(ctx), filter, bson.M{"$set": update})
	if err != nil {
		return 0, translateError(err)
	}
	return result.ModifiedCount, nil
}

func (a *Adapter) Delete(ctx context.Context, query betterauth.DeleteQuery) error {
	filter, err := buildFilter(query.Where, false)
	if err != nil {
		return err
	}
	_, err = a.collection(query.Model).DeleteOne(a.ctx(ctx), filter)
	return translateError(err)
}

func (a *Adapter) DeleteMany(ctx context.Context, query betterauth.DeleteQuery) (int64, error) {
	filter, err := buildFilter(query.Where, false)
	if err != nil {
		return 0, err
	}
	result, err := a.collection(query.Model).DeleteMany(a.ctx(ctx), filter)
	if err != nil {
		return 0, translateError(err)
	}
	return result.DeletedCount, nil
}

func (a *Adapter) ConsumeOne(ctx context.Context, query betterauth.DeleteQuery) (betterauth.Record, error) {
	filter, err := buildFilter(query.Where, false)
	if err != nil {
		return nil, err
	}
	var document bson.M
	err = a.collection(query.Model).FindOneAndDelete(a.ctx(ctx), filter).Decode(&document)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, nil
	}
	if err != nil {
		return nil, translateError(err)
	}
	return fromMongoRecord(document), nil
}

func (a *Adapter) IncrementOne(ctx context.Context, query betterauth.IncrementQuery) (betterauth.Record, error) {
	filter, err := buildFilter(query.Where, false)
	if err != nil {
		return nil, err
	}
	if len(query.Increment) == 0 {
		return nil, errors.New("mongodb: increment is empty")
	}
	increment := bson.M{}
	for field, delta := range query.Increment {
		increment[mongoField(field)] = delta
	}
	update := bson.M{"$inc": increment}
	if len(query.Set) > 0 {
		values := toMongoRecord(query.Set)
		delete(values, "_id")
		update["$set"] = values
	}
	var document bson.M
	err = a.collection(query.Model).FindOneAndUpdate(
		a.ctx(ctx), filter, update, options.FindOneAndUpdate().SetReturnDocument(options.After),
	).Decode(&document)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, nil
	}
	if err != nil {
		return nil, translateError(err)
	}
	return fromMongoRecord(document), nil
}

func (a *Adapter) Transaction(ctx context.Context, callback func(betterauth.DatabaseAdapter) error) error {
	if a.transaction != nil {
		return callback(a)
	}
	session, err := a.database.Client().StartSession()
	if err != nil {
		return translateError(err)
	}
	defer session.EndSession(ctx)
	_, err = session.WithTransaction(ctx, func(sessionContext context.Context) (any, error) {
		transactionAdapter := *a
		transactionAdapter.transaction = sessionContext
		if err := callback(&transactionAdapter); err != nil {
			return nil, err
		}
		return nil, nil
	})
	return translateError(err)
}

func (a *Adapter) EnsureCoreIndexes(ctx context.Context) error {
	return a.EnsureIndexes(ctx, betterauth.CoreSchema())
}

// EnsureIndexes creates indexes declared by the fully merged core/application/
// plugin schema plus the core compound and TTL indexes. Call it with
// Server.Schema after constructing the server.
func (a *Adapter) EnsureIndexes(ctx context.Context, schema betterauth.Schema) error {
	indexes := make(map[string][]mongo.IndexModel, len(schema))
	modelNames := make(map[string]string, len(schema))
	fieldNames := make(map[string]map[string]string, len(schema))
	for logicalModel, model := range schema {
		storedModel := model.ModelName
		if storedModel == "" {
			storedModel = logicalModel
		}
		modelNames[logicalModel] = storedModel
		fieldNames[logicalModel] = make(map[string]string, len(model.Fields))
		for logicalField, definition := range model.Fields {
			storedField := definition.FieldName
			if storedField == "" {
				storedField = logicalField
			}
			fieldNames[logicalModel][logicalField] = storedField
			// The conventional logical id is persisted as MongoDB's built-in
			// unique _id field by toMongoRecord.
			if logicalField == "id" && storedField == "id" {
				continue
			}
			if !definition.Unique && !definition.Index {
				continue
			}
			name := mongoIndexName(logicalModel, logicalField, definition.Unique)
			index := options.Index().SetName(name)
			if definition.Unique {
				index.SetUnique(true)
			}
			indexes[storedModel] = append(indexes[storedModel], mongo.IndexModel{
				Keys: bson.D{{Key: storedField, Value: 1}}, Options: index,
			})
		}
	}
	addCoreMongoIndexes(indexes, modelNames, fieldNames)
	for model, definitions := range indexes {
		if _, err := a.collection(model).Indexes().CreateMany(a.ctx(ctx), definitions); err != nil {
			return translateError(err)
		}
	}
	return nil
}

func addCoreMongoIndexes(
	indexes map[string][]mongo.IndexModel,
	models map[string]string,
	fields map[string]map[string]string,
) {
	if model := models[betterauth.ModelSession]; model != "" {
		indexes[model] = append(indexes[model], mongo.IndexModel{
			Keys:    bson.D{{Key: fields[betterauth.ModelSession]["expiresAt"], Value: 1}},
			Options: options.Index().SetExpireAfterSeconds(0).SetName("ttl_expires"),
		})
	}
	if model := models[betterauth.ModelVerification]; model != "" {
		indexes[model] = append(indexes[model], mongo.IndexModel{
			Keys:    bson.D{{Key: fields[betterauth.ModelVerification]["expiresAt"], Value: 1}},
			Options: options.Index().SetExpireAfterSeconds(0).SetName("ttl_expires"),
		})
	}
	if model := models[betterauth.ModelAccount]; model != "" {
		indexes[model] = append(indexes[model], mongo.IndexModel{
			Keys: bson.D{
				{Key: fields[betterauth.ModelAccount]["providerId"], Value: 1},
				{Key: fields[betterauth.ModelAccount]["accountId"], Value: 1},
			},
			Options: options.Index().SetUnique(true).SetName("uniq_provider_account"),
		})
	}
	if model := models[betterauth.ModelOutboxEvent]; model != "" {
		indexes[model] = append(indexes[model], mongo.IndexModel{
			Keys: bson.D{
				{Key: fields[betterauth.ModelOutboxEvent]["publishedAt"], Value: 1},
				{Key: fields[betterauth.ModelOutboxEvent]["occurredAt"], Value: 1},
			},
			Options: options.Index().SetName("outbox_unpublished"),
		})
	}
}

func mongoIndexName(model, field string, unique bool) string {
	switch model + "." + field {
	case betterauth.ModelUser + ".email":
		return "uniq_email"
	case betterauth.ModelSession + ".tokenHash":
		return "uniq_token_hash"
	case betterauth.ModelSession + ".userId":
		return "user_sessions"
	case betterauth.ModelAccount + ".userId":
		return "user_accounts"
	case betterauth.ModelVerification + ".value":
		return "uniq_value_hash"
	}
	kind := "index"
	if unique {
		kind = "unique"
	}
	name := regexp.MustCompile(`[^A-Za-z0-9_-]+`).ReplaceAllString(
		model+"_"+field+"_"+kind, "_",
	)
	if len(name) > 120 {
		name = name[:120]
	}
	return name
}

func (a *Adapter) collection(model string) *mongo.Collection {
	name := a.collections[model]
	if name == "" {
		name = model
	}
	return a.database.Collection(name)
}

func (a *Adapter) ctx(ctx context.Context) context.Context {
	if a.transaction != nil {
		return a.transaction
	}
	return ctx
}

func validateModel(model string) error {
	if model == "" || strings.Contains(model, "$") || strings.ContainsRune(model, '\x00') {
		return errors.New("mongodb: invalid model")
	}
	return nil
}

func buildFilter(where []betterauth.Where, allowEmpty bool) (bson.M, error) {
	normalized, err := betterauth.ValidateWhere(where, allowEmpty)
	if err != nil {
		return nil, err
	}
	if len(normalized) == 0 {
		return bson.M{}, nil
	}
	andClauses := bson.A{}
	orClauses := bson.A{}
	for _, condition := range normalized {
		clause, err := conditionFilter(condition)
		if err != nil {
			return nil, err
		}
		if condition.Connector == betterauth.WhereOR {
			orClauses = append(orClauses, clause)
		} else {
			andClauses = append(andClauses, clause)
		}
	}
	if len(orClauses) > 0 {
		andClauses = append(andClauses, bson.M{"$or": orClauses})
	}
	if len(andClauses) == 1 {
		return andClauses[0].(bson.M), nil
	}
	return bson.M{"$and": andClauses}, nil
}

func conditionFilter(condition betterauth.Where) (bson.M, error) {
	field := mongoField(condition.Field)
	value := toMongoValue(condition.Value)
	if condition.Mode == betterauth.StringInsensitive {
		text, ok := condition.Value.(string)
		if !ok {
			return nil, errors.New("mongodb: insensitive mode requires string value")
		}
		pattern := regexp.QuoteMeta(text)
		switch condition.Operator {
		case betterauth.WhereEQ:
			return bson.M{field: bson.M{"$regex": "^" + pattern + "$", "$options": "i"}}, nil
		case betterauth.WhereContains:
			return bson.M{field: bson.M{"$regex": pattern, "$options": "i"}}, nil
		case betterauth.WhereStartsWith:
			return bson.M{field: bson.M{"$regex": "^" + pattern, "$options": "i"}}, nil
		case betterauth.WhereEndsWith:
			return bson.M{field: bson.M{"$regex": pattern + "$", "$options": "i"}}, nil
		default:
			return nil, errors.New("mongodb: insensitive mode is unsupported for this operator")
		}
	}
	switch condition.Operator {
	case betterauth.WhereEQ:
		return bson.M{field: value}, nil
	case betterauth.WhereNE:
		return bson.M{field: bson.M{"$ne": value}}, nil
	case betterauth.WhereLT:
		return bson.M{field: bson.M{"$lt": value}}, nil
	case betterauth.WhereLTE:
		return bson.M{field: bson.M{"$lte": value}}, nil
	case betterauth.WhereGT:
		return bson.M{field: bson.M{"$gt": value}}, nil
	case betterauth.WhereGTE:
		return bson.M{field: bson.M{"$gte": value}}, nil
	case betterauth.WhereIn:
		return bson.M{field: bson.M{"$in": value}}, nil
	case betterauth.WhereNotIn:
		return bson.M{field: bson.M{"$nin": value}}, nil
	case betterauth.WhereContains:
		text, ok := condition.Value.(string)
		if !ok {
			return nil, errors.New("mongodb: contains requires string value")
		}
		return bson.M{field: bson.M{"$regex": regexp.QuoteMeta(text)}}, nil
	case betterauth.WhereStartsWith:
		text, ok := condition.Value.(string)
		if !ok {
			return nil, errors.New("mongodb: starts_with requires string value")
		}
		return bson.M{field: bson.M{"$regex": "^" + regexp.QuoteMeta(text)}}, nil
	case betterauth.WhereEndsWith:
		text, ok := condition.Value.(string)
		if !ok {
			return nil, errors.New("mongodb: ends_with requires string value")
		}
		return bson.M{field: bson.M{"$regex": regexp.QuoteMeta(text) + "$"}}, nil
	default:
		return nil, fmt.Errorf("mongodb: unsupported operator %q", condition.Operator)
	}
}

func mongoField(field string) string {
	if field == "id" {
		return "_id"
	}
	return field
}

func buildProjection(fields []string) bson.M {
	if len(fields) == 0 {
		return nil
	}
	projection := bson.M{}
	for _, field := range fields {
		projection[mongoField(field)] = 1
	}
	return projection
}

func projectRecord(record betterauth.Record, fields []string) betterauth.Record {
	if len(fields) == 0 {
		return record
	}
	result := betterauth.Record{}
	for _, field := range fields {
		if value, ok := record[field]; ok {
			result[field] = value
		}
	}
	return result
}

func toMongoRecord(input betterauth.Record) bson.M {
	result := bson.M{}
	for key, value := range input {
		result[mongoField(key)] = toMongoValue(value)
	}
	return result
}

func toMongoValue(value any) any {
	switch typed := value.(type) {
	case betterauth.Record:
		return toMongoRecord(typed)
	case map[string]string:
		result := bson.M{}
		for key, item := range typed {
			result[key] = item
		}
		return result
	case map[string]any:
		result := bson.M{}
		for key, item := range typed {
			result[key] = toMongoValue(item)
		}
		return result
	default:
		return value
	}
}

func fromMongoRecord(document bson.M) betterauth.Record {
	result := betterauth.Record{}
	for key, value := range document {
		if key == "_id" {
			key = "id"
		}
		result[key] = fromMongoValue(value)
	}
	return result
}

func fromMongoValue(value any) any {
	switch typed := value.(type) {
	case bson.M:
		return fromMongoRecord(typed)
	case map[string]any:
		result := map[string]any{}
		for key, item := range typed {
			result[key] = fromMongoValue(item)
		}
		return result
	case bson.A:
		result := make([]any, len(typed))
		for index, item := range typed {
			result[index] = fromMongoValue(item)
		}
		return result
	case bson.DateTime:
		return typed.Time().UTC()
	default:
		return value
	}
}

func translateError(err error) error {
	if err == nil {
		return nil
	}
	if mongo.IsDuplicateKeyError(err) {
		return fmt.Errorf("%w: %v", betterauth.ErrConflict, err)
	}
	return err
}

var _ betterauth.DatabaseAdapter = (*Adapter)(nil)
