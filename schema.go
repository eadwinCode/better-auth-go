package betterauth

import (
	"fmt"
	"maps"
	"slices"
)

const (
	ModelUser         = "user"
	ModelSession      = "session"
	ModelAccount      = "account"
	ModelVerification = "verification"
	ModelAuditEvent   = "auditEvent"
	ModelOutboxEvent  = "outboxEvent"
)

type FieldType string

const (
	FieldString      FieldType = "string"
	FieldNumber      FieldType = "number"
	FieldBoolean     FieldType = "boolean"
	FieldDate        FieldType = "date"
	FieldJSON        FieldType = "json"
	FieldStringArray FieldType = "string[]"
)

type FieldSchema struct {
	Type       FieldType
	Required   bool
	Unique     bool
	Index      bool
	References string
	Input      bool
	Returned   bool
	FieldName  string
}

type ModelSchema struct {
	ModelName string
	Fields    map[string]FieldSchema
	Indexes   []IndexSchema
}

// IndexSchema declares a compound adapter index using logical field names.
type IndexSchema struct {
	Name   string
	Fields []string
	Unique bool
}

type Schema map[string]ModelSchema

// CoreSchema returns an independent schema copy that plugins can extend before
// server construction.
func CoreSchema() Schema {
	return Schema{
		ModelUser: {
			Fields: map[string]FieldSchema{
				"id":            {Type: FieldString, Required: true, Unique: true, Returned: true},
				"email":         {Type: FieldString, Required: true, Unique: true, Input: true, Returned: true},
				"emailVerified": {Type: FieldBoolean, Required: true, Returned: true},
				"name":          {Type: FieldString, Input: true, Returned: true},
				"image":         {Type: FieldString, Input: true, Returned: true},
				"createdAt":     {Type: FieldDate, Required: true, Returned: true},
				"updatedAt":     {Type: FieldDate, Required: true, Returned: true},
				"disabledAt":    {Type: FieldDate},
			},
		},
		ModelSession: {
			Fields: map[string]FieldSchema{
				"id":              {Type: FieldString, Required: true, Unique: true},
				"userId":          {Type: FieldString, Required: true, Index: true, References: ModelUser},
				"tokenHash":       {Type: FieldString, Required: true, Unique: true},
				"expiresAt":       {Type: FieldDate, Required: true},
				"createdAt":       {Type: FieldDate, Required: true},
				"updatedAt":       {Type: FieldDate, Required: true},
				"lastSeenAt":      {Type: FieldDate, Required: true},
				"revokedAt":       {Type: FieldDate},
				"impersonatedBy":  {Type: FieldString},
				"impersonationId": {Type: FieldString},
			},
		},
		ModelAccount: {
			Fields: map[string]FieldSchema{
				"id":                    {Type: FieldString, Required: true, Unique: true},
				"userId":                {Type: FieldString, Required: true, Index: true, References: ModelUser},
				"providerId":            {Type: FieldString, Required: true},
				"issuer":                {Type: FieldString, Required: true},
				"accountId":             {Type: FieldString, Required: true},
				"password":              {Type: FieldString},
				"accessToken":           {Type: FieldString},
				"refreshToken":          {Type: FieldString},
				"idToken":               {Type: FieldString},
				"accessTokenExpiresAt":  {Type: FieldDate},
				"refreshTokenExpiresAt": {Type: FieldDate},
				"scope":                 {Type: FieldString},
				"createdAt":             {Type: FieldDate, Required: true},
				"updatedAt":             {Type: FieldDate, Required: true},
			},
			Indexes: []IndexSchema{{
				Name: "account_issuer_accountId_uidx", Fields: []string{"issuer", "accountId"}, Unique: true,
			}},
		},
		ModelVerification: {
			Fields: map[string]FieldSchema{
				"id":         {Type: FieldString, Required: true, Unique: true},
				"identifier": {Type: FieldString, Required: true},
				"value":      {Type: FieldString, Required: true, Unique: true},
				"expiresAt":  {Type: FieldDate, Required: true},
				"createdAt":  {Type: FieldDate, Required: true},
				"metadata":   {Type: FieldJSON},
			},
		},
		ModelAuditEvent: {
			Fields: map[string]FieldSchema{
				"id":            {Type: FieldString, Required: true, Unique: true},
				"schemaVersion": {Type: FieldNumber, Required: true},
				"action":        {Type: FieldString, Required: true},
				"actorUserId":   {Type: FieldString, Required: true},
				"subjectUserId": {Type: FieldString, Required: true},
				"sessionId":     {Type: FieldString},
				"occurredAt":    {Type: FieldDate, Required: true},
				"request":       {Type: FieldJSON},
				"details":       {Type: FieldJSON},
			},
		},
		ModelOutboxEvent: {
			Fields: map[string]FieldSchema{
				"id":            {Type: FieldString, Required: true, Unique: true},
				"schemaVersion": {Type: FieldNumber, Required: true},
				"name":          {Type: FieldString, Required: true},
				"aggregateId":   {Type: FieldString, Required: true},
				"occurredAt":    {Type: FieldDate, Required: true},
				"payload":       {Type: FieldJSON},
				"publishedAt":   {Type: FieldDate},
			},
		},
	}
}

func MergeSchema(base Schema, extensions ...Schema) (Schema, error) {
	result := make(Schema, len(base))
	for name, model := range base {
		copyModel := model
		copyModel.Fields = maps.Clone(model.Fields)
		copyModel.Indexes = cloneIndexes(model.Indexes)
		result[name] = copyModel
	}
	for _, extension := range extensions {
		for name, model := range extension {
			current, exists := result[name]
			if !exists {
				copyModel := model
				copyModel.Fields = maps.Clone(model.Fields)
				copyModel.Indexes = cloneIndexes(model.Indexes)
				result[name] = copyModel
				continue
			}
			if model.ModelName != "" {
				if current.ModelName != "" && current.ModelName != model.ModelName {
					return nil, fmt.Errorf("betterauth: conflicting model name for %s", name)
				}
				current.ModelName = model.ModelName
			}
			if current.Fields == nil {
				current.Fields = map[string]FieldSchema{}
			}
			for field, definition := range model.Fields {
				if existing, ok := current.Fields[field]; ok {
					if definition.Type != "" && definition.Type != existing.Type {
						return nil, fmt.Errorf("betterauth: cannot change core field type for %s.%s", name, field)
					}
					if definition.FieldName != "" {
						existing.FieldName = definition.FieldName
					}
					current.Fields[field] = existing
					continue
				}
				current.Fields[field] = definition
			}
			for _, index := range model.Indexes {
				if !containsIndex(current.Indexes, index) {
					index.Fields = slices.Clone(index.Fields)
					current.Indexes = append(current.Indexes, index)
				}
			}
			result[name] = current
		}
	}
	return result, nil
}

func cloneIndexes(indexes []IndexSchema) []IndexSchema {
	result := make([]IndexSchema, len(indexes))
	for index, definition := range indexes {
		definition.Fields = slices.Clone(definition.Fields)
		result[index] = definition
	}
	return result
}

func containsIndex(indexes []IndexSchema, candidate IndexSchema) bool {
	for _, existing := range indexes {
		if existing.Name == candidate.Name && existing.Unique == candidate.Unique &&
			slices.Equal(existing.Fields, candidate.Fields) {
			return true
		}
	}
	return false
}
