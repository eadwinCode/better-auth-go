package mongodb

import (
	"strings"
	"testing"

	betterauth "github.com/eadwinCode/better-auth-go"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

func TestMongoIndexNamesRemainCompatibleAndNamespacePlugins(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		mongoIndexName(betterauth.ModelUser, "email", true):         "uniq_email",
		mongoIndexName(betterauth.ModelSession, "tokenHash", true):  "uniq_token_hash",
		mongoIndexName(betterauth.ModelSession, "userId", false):    "user_sessions",
		mongoIndexName(betterauth.ModelAccount, "userId", false):    "user_accounts",
		mongoIndexName(betterauth.ModelVerification, "value", true): "uniq_value_hash",
		mongoIndexName("passkey", "credentialID", true):             "passkey_credentialID_unique",
		mongoIndexName("passkey", "userHandle", false):              "passkey_userHandle_index",
		mongoIndexName("twoFactor", "userId", true):                 "twoFactor_userId_unique",
	}
	for actual, expected := range tests {
		if actual != expected {
			t.Fatalf("unexpected MongoDB index name %q, want %q", actual, expected)
		}
	}
}

func TestCoreProviderAccountIndexRetainsReleaseCompatibleName(t *testing.T) {
	t.Parallel()
	account := betterauth.CoreSchema()[betterauth.ModelAccount]
	if len(account.Indexes) != 1 {
		t.Fatalf("core account indexes = %#v, want one provider-account index", account.Indexes)
	}
	index := account.Indexes[0]
	if index.Name != "uniq_provider_account" ||
		len(index.Fields) != 2 ||
		index.Fields[0] != "providerId" ||
		index.Fields[1] != "accountId" ||
		!index.Unique {
		t.Fatalf("provider-account index is not release compatible: %#v", index)
	}
	if _, exists := account.Fields["issuer"]; exists {
		t.Fatal("account schema still has the issuer field")
	}
}

func TestCoreMongoIndexesDoNotAddAccountIdentityIndex(t *testing.T) {
	t.Parallel()
	models := map[string]string{betterauth.ModelAccount: betterauth.ModelAccount}
	fields := map[string]map[string]string{
		betterauth.ModelAccount: {"providerId": "providerId", "accountId": "accountId"},
	}
	indexes := map[string][]mongo.IndexModel{}
	addCoreMongoIndexes(indexes, models, fields)
	if len(indexes[betterauth.ModelAccount]) != 0 {
		t.Fatalf("account identity index must come only from the schema: %#v", indexes)
	}
}

func TestCollectionsAndSchemaModelNamesCannotBeMixed(t *testing.T) {
	t.Parallel()
	adapter := &Adapter{
		collections: map[string]string{betterauth.ModelUser: "people"},
		renamed:     true,
	}
	schema := betterauth.CoreSchema()
	if _, err := adapter.WithSchema(schema); err != nil {
		t.Fatalf("Collections without schema renames was rejected: %v", err)
	}
	user := schema[betterauth.ModelUser]
	user.ModelName = "members"
	schema[betterauth.ModelUser] = user
	if _, err := adapter.WithSchema(schema); err == nil ||
		!strings.Contains(err.Error(), "Config.Collections") {
		t.Fatalf("Collections mixed with schema renames was accepted: %v", err)
	}
	plain := &Adapter{collections: map[string]string{betterauth.ModelUser: betterauth.ModelUser}}
	if _, err := plain.WithSchema(schema); err != nil {
		t.Fatalf("schema renames without Collections was rejected: %v", err)
	}
}

func TestCollectionsMustNotShareACollection(t *testing.T) {
	t.Parallel()
	_, err := New(Config{
		Database:    &mongo.Database{},
		Collections: map[string]string{betterauth.ModelUser: betterauth.ModelAccount},
	})
	if err == nil || !strings.Contains(err.Error(), "map to collection") {
		t.Fatalf("two models sharing one collection was accepted: %v", err)
	}
}
