package onetimetoken

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	betterauth "github.com/eadwinCode/better-auth-go"
	sqliteadapter "github.com/eadwinCode/better-auth-go/adapter/sqlite"
	_ "modernc.org/sqlite"
)

// The sealed session lives in the verification metadata JSON column, and
// single use relies on the adapter's ConsumeOne. Run the flow on SQLite to
// check both survive a real SQL round trip.
func TestOneTimeTokenOnSQLite(t *testing.T) {
	t.Parallel()
	database, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "ott.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	adapter, err := sqliteadapter.New(database)
	if err != nil {
		t.Fatal(err)
	}
	for _, storage := range []TokenStorage{TokenStoragePlain, TokenStorageHashed} {
		plugin, err := New(Config{StoreToken: storage})
		if err != nil {
			t.Fatal(err)
		}
		server, err := betterauth.New(betterauth.Config{
			PublicURL:      "https://auth.example.org",
			TrustedOrigins: []string{"https://app.example.org"},
			Database:       adapter, Mailer: discardMailer{},
			ImpersonationAuthorizer: denyImpersonation{},
			Plugins:                 []betterauth.Plugin{plugin},
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := adapter.Migrate(t.Context(), server.Schema()); err != nil {
			t.Fatal(err)
		}
		send := func(method, path, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
			request := httptest.NewRequest(method, "https://auth.example.org/api/auth"+path, strings.NewReader(body))
			request.Header.Set("Origin", "https://app.example.org")
			if body != "" {
				request.Header.Set("Content-Type", "application/json")
			}
			if cookie != nil {
				request.AddCookie(cookie)
			}
			recorder := httptest.NewRecorder()
			server.Handler().ServeHTTP(recorder, request)
			return recorder
		}
		signUp := send(http.MethodPost, "/sign-up/email",
			`{"email":"sqlite-`+string(storage)+`@example.org","password":"Correct-Horse-123!","name":"SQLite"}`, nil)
		if signUp.Code != http.StatusOK {
			t.Fatalf("%s sign-up status=%d body=%s", storage, signUp.Code, signUp.Body)
		}
		session := responseCookie(t, signUp, sessionCookie)
		generate := send(http.MethodGet, "/one-time-token/generate", "", session)
		if generate.Code != http.StatusOK {
			t.Fatalf("%s generate status=%d body=%s", storage, generate.Code, generate.Body)
		}
		token, _ := decode(t, generate)["token"].(string)
		body := `{"token":"` + token + `"}`
		verify := send(http.MethodPost, "/one-time-token/verify", body, nil)
		if verify.Code != http.StatusOK || responseCookie(t, verify, sessionCookie).Value != session.Value {
			t.Fatalf("%s verify status=%d body=%s", storage, verify.Code, verify.Body)
		}
		if replay := send(http.MethodPost, "/one-time-token/verify", body, nil); replay.Code != http.StatusBadRequest {
			t.Fatalf("%s replay status=%d body=%s", storage, replay.Code, replay.Body)
		}
	}
}
