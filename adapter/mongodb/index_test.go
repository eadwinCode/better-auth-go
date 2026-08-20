package mongodb

import (
	"testing"

	betterauth "github.com/eadwinCode/better-auth-go"
	"go.mongodb.org/mongo-driver/v2/bson"
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

func TestCoreIssuerAccountIndexMatchesV17Identity(t *testing.T) {
	t.Parallel()
	account := betterauth.CoreSchema()[betterauth.ModelAccount]
	if len(account.Indexes) != 1 {
		t.Fatalf("core account indexes = %#v, want one issuer-account index", account.Indexes)
	}
	index := account.Indexes[0]
	if index.Name != "account_issuer_accountId_uidx" ||
		len(index.Fields) != 2 ||
		index.Fields[0] != "issuer" ||
		index.Fields[1] != "accountId" ||
		!index.Unique {
		t.Fatalf("issuer-account index is not v1.7 compatible: %#v", index)
	}
}

func TestCoreIssuerAccountIndexFallbackDoesNotDuplicateSchemaIndex(t *testing.T) {
	t.Parallel()
	models := map[string]string{betterauth.ModelAccount: betterauth.ModelAccount}
	fields := map[string]map[string]string{
		betterauth.ModelAccount: {
			"issuer":    "issuer",
			"accountId": "accountId",
		},
	}
	declared := map[string][]mongo.IndexModel{
		betterauth.ModelAccount: {{Keys: bson.D{{Key: "issuer", Value: 1}, {Key: "accountId", Value: 1}}}},
	}
	addCoreMongoIndexes(declared, models, fields, true, true)
	if len(declared[betterauth.ModelAccount]) != 1 {
		t.Fatalf("schema-declared issuer-account index was duplicated: %#v", declared)
	}

	legacy := map[string][]mongo.IndexModel{}
	addCoreMongoIndexes(legacy, models, fields, false, true)
	if len(legacy[betterauth.ModelAccount]) != 1 {
		t.Fatalf("issuer-account fallback missing: %#v", legacy)
	}
	staging := map[string][]mongo.IndexModel{}
	addCoreMongoIndexes(staging, models, fields, false, false)
	if len(staging[betterauth.ModelAccount]) != 0 {
		t.Fatalf("staging schema created the final unique index: %#v", staging)
	}
}
