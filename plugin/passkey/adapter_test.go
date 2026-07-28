package passkey

import (
	"database/sql"
	"path/filepath"
	"testing"

	betterauth "github.com/eadwinCode/better-auth-go"
	sqliteadapter "github.com/eadwinCode/better-auth-go/adapter/sqlite"
	_ "modernc.org/sqlite"
)

func TestPasskeySchemaMigratesOnSQLite(t *testing.T) {
	t.Parallel()
	database, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "passkey.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	adapter, err := sqliteadapter.New(database)
	if err != nil {
		t.Fatal(err)
	}
	plugin, err := New(Config{
		RPID: "example.org", RPDisplayName: "Example", Origins: []string{testOrigin},
	})
	if err != nil {
		t.Fatal(err)
	}
	server, err := betterauth.New(betterauth.Config{
		PublicURL: "https://auth.example.org", TrustedOrigins: []string{testOrigin},
		Database: adapter, Mailer: discardMailer{}, ImpersonationAuthorizer: denyImpersonation{},
		Plugins: []betterauth.Plugin{plugin},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := adapter.Migrate(t.Context(), server.Schema()); err != nil {
		t.Fatal(err)
	}
	rows, err := database.QueryContext(t.Context(), `PRAGMA table_info("passkey")`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	columns := map[string]bool{}
	for rows.Next() {
		var (
			cid       int
			name      string
			fieldType string
			notNull   int
			defaultV  any
			primary   int
		)
		if err := rows.Scan(&cid, &name, &fieldType, &notNull, &defaultV, &primary); err != nil {
			t.Fatal(err)
		}
		columns[name] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"id", "userId", "credentialID", "publicKey", "counter",
		"userHandle", "credentialData",
	} {
		if !columns[required] {
			t.Fatalf("passkey migration omitted %q: %#v", required, columns)
		}
	}
	indexRows, err := database.QueryContext(
		t.Context(),
		`SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'passkey'`,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer indexRows.Close()
	indexes := map[string]bool{}
	for indexRows.Next() {
		var name string
		if err := indexRows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		indexes[name] = true
	}
	if err := indexRows.Err(); err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"passkey_credentialID_unique",
		"passkey_userId_index",
		"passkey_userHandle_index",
	} {
		if !indexes[required] {
			t.Fatalf("passkey migration omitted index %q: %#v", required, indexes)
		}
	}
}
