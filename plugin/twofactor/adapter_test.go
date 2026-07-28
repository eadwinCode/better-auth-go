package twofactor

import (
	"bytes"
	"database/sql"
	"path/filepath"
	"testing"

	betterauth "github.com/eadwinCode/better-auth-go"
	sqliteadapter "github.com/eadwinCode/better-auth-go/adapter/sqlite"
	_ "modernc.org/sqlite"
)

func TestTwoFactorSchemaMigratesOnSQLite(t *testing.T) {
	t.Parallel()
	database, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "twofactor.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	adapter, err := sqliteadapter.New(database)
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := betterauth.NewAESGCMTokenCipher(bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	plugin, err := New(Config{Issuer: "Example", Cipher: cipher})
	if err != nil {
		t.Fatal(err)
	}
	server, err := betterauth.New(betterauth.Config{
		PublicURL: "https://auth.example.org",
		TrustedOrigins: []string{
			"https://app.example.org",
		},
		Database: adapter, Mailer: discardMailer{},
		ImpersonationAuthorizer: denyImpersonation{},
		Plugins:                 []betterauth.Plugin{plugin},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := adapter.Migrate(t.Context(), server.Schema()); err != nil {
		t.Fatal(err)
	}
	for table, required := range map[string][]string{
		"user": {"twoFactorEnabled"},
		"twoFactor": {
			"id", "userId", "secret", "backupCodes", "verified",
			"failedVerificationCount", "lockedUntil", "createdAt", "updatedAt",
		},
	} {
		rows, queryErr := database.QueryContext(
			t.Context(), `PRAGMA table_info("`+table+`")`,
		)
		if queryErr != nil {
			t.Fatal(queryErr)
		}
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
			if scanErr := rows.Scan(
				&cid, &name, &fieldType, &notNull, &defaultV, &primary,
			); scanErr != nil {
				_ = rows.Close()
				t.Fatal(scanErr)
			}
			columns[name] = true
		}
		if err := rows.Close(); err != nil {
			t.Fatal(err)
		}
		for _, field := range required {
			if !columns[field] {
				t.Fatalf("%s migration omitted %q: %#v", table, field, columns)
			}
		}
	}
	indexRows, err := database.QueryContext(
		t.Context(),
		`SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'twoFactor'`,
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
	if !indexes["twoFactor_userId_unique"] {
		t.Fatalf("two-factor migration omitted unique user index: %#v", indexes)
	}
}
