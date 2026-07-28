package betterauth_test

import (
	"context"
	"testing"
	"time"

	betterauth "github.com/eadwinCode/better-auth-go"
	"github.com/eadwinCode/better-auth-go/adapter/memory"
)

type limitedAdapter struct{ *memory.Adapter }

func (limitedAdapter) Capabilities() betterauth.AdapterCapabilities {
	return betterauth.AdapterCapabilities{Transactions: true}
}

func TestSchemaAdapterRenamesModelsAndFields(t *testing.T) {
	t.Parallel()
	inner := memory.New()
	schema, err := betterauth.MergeSchema(betterauth.CoreSchema(), betterauth.Schema{
		betterauth.ModelUser: {
			ModelName: "app_users",
			Fields: map[string]betterauth.FieldSchema{
				"email": {FieldName: "email_address"},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := betterauth.WrapDatabaseAdapter(inner, schema)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	_, err = adapter.Create(context.Background(), betterauth.CreateQuery{Model: betterauth.ModelUser, Data: betterauth.Record{
		"id": "user-1", "email": "user@example.com", "emailVerified": false,
		"createdAt": now, "updatedAt": now,
	}, ForceAllowID: true})
	if err != nil {
		t.Fatal(err)
	}
	stored, err := inner.FindOne(context.Background(), betterauth.FindOneQuery{
		Model: "app_users", Where: []betterauth.Where{betterauth.Eq("email_address", "user@example.com")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if stored == nil || stored["email"] != nil || stored["email_address"] != "user@example.com" {
		t.Fatalf("unexpected stored record: %#v", stored)
	}
	logical, err := adapter.FindOne(context.Background(), betterauth.FindOneQuery{
		Model: betterauth.ModelUser, Where: []betterauth.Where{betterauth.Eq("email", "user@example.com")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if logical["email"] != "user@example.com" || logical["email_address"] != nil {
		t.Fatalf("unexpected logical record: %#v", logical)
	}
}

func TestSchemaAdapterTransformsUnsupportedTypes(t *testing.T) {
	t.Parallel()
	inner := limitedAdapter{Adapter: memory.New()}
	adapter, err := betterauth.WrapDatabaseAdapter(inner, betterauth.CoreSchema())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 28, 12, 0, 0, 123, time.UTC)
	_, err = adapter.Create(context.Background(), betterauth.CreateQuery{Model: betterauth.ModelUser, Data: betterauth.Record{
		"id": "user-1", "email": "user@example.com", "emailVerified": true,
		"createdAt": now, "updatedAt": now,
	}, ForceAllowID: true})
	if err != nil {
		t.Fatal(err)
	}
	stored, err := inner.FindOne(context.Background(), betterauth.FindOneQuery{
		Model: betterauth.ModelUser, Where: []betterauth.Where{betterauth.Eq("id", "user-1")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if stored["emailVerified"] != 1 {
		t.Fatalf("boolean was not transformed: %#v", stored)
	}
	if _, ok := stored["createdAt"].(string); !ok {
		t.Fatalf("date was not transformed: %#v", stored)
	}
	logical, err := adapter.FindOne(context.Background(), betterauth.FindOneQuery{
		Model: betterauth.ModelUser, Where: []betterauth.Where{betterauth.Eq("id", "user-1")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if logical["emailVerified"] != true || !logical["createdAt"].(time.Time).Equal(now) {
		t.Fatalf("output was not restored: %#v", logical)
	}
}
