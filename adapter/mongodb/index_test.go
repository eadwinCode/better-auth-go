package mongodb

import (
	"testing"

	betterauth "github.com/eadwinCode/better-auth-go"
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
	}
	for actual, expected := range tests {
		if actual != expected {
			t.Fatalf("unexpected MongoDB index name %q, want %q", actual, expected)
		}
	}
}
