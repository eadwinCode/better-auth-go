package scim

import (
	"database/sql"
	"net/http"
	"testing"

	betterauth "github.com/eadwinCode/better-auth-go"
	sqliteadapter "github.com/eadwinCode/better-auth-go/adapter/sqlite"
	_ "modernc.org/sqlite"
)

func TestSCIMSchemaAndLifecycleOnSQLite(t *testing.T) {
	t.Parallel()
	secret := "sqlite-scim-fixture-secret-000001"
	token, err := encodeBearerToken(secret, "sqlite-directory", "")
	if err != nil {
		t.Fatal(err)
	}
	plugin, err := New(Config{DefaultConnections: []DefaultConnection{{
		ProviderID: "sqlite-directory", TokenHash: betterauth.HashToken(secret), UserID: "owner",
	}}})
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", "file:scim-runtime?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	adapter, err := sqliteadapter.New(db)
	if err != nil {
		t.Fatal(err)
	}
	schema, err := betterauth.MergeSchema(betterauth.CoreSchema(), plugin.Schema)
	if err != nil {
		t.Fatal(err)
	}
	if err = adapter.Migrate(t.Context(), schema); err != nil {
		t.Fatal(err)
	}
	server, err := betterauth.New(betterauth.Config{
		PublicURL: "https://auth.example.com", TrustedOrigins: []string{"https://app.example.com"},
		Database: adapter, Mailer: discardMailer{},
		ImpersonationAuthorizer: denyImpersonation{}, Plugins: []betterauth.Plugin{plugin},
	})
	if err != nil {
		t.Fatal(err)
	}
	create := protocolRequest(
		t, server.Handler(), http.MethodPost, "/scim/v2/Users",
		token, "application/scim+json",
		UserInput{
			Schemas: []string{SchemaUser}, UserName: "sqlite-user@example.com",
			ExternalID: "sqlite-external-1",
		},
	)
	if create.Code != http.StatusCreated {
		t.Fatalf("create = %d: %s", create.Code, create.Body.String())
	}
	list := protocolRequest(
		t, server.Handler(), http.MethodGet, "/scim/v2/Users", token, "", nil,
	)
	if list.Code != http.StatusOK {
		t.Fatalf("list = %d: %s", list.Code, list.Body.String())
	}
}
