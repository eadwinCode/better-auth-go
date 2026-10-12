package adaptertest

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	betterauth "github.com/eadwinCode/better-auth-go"
)

// SchemaCheckAdapter is an adapter that can migrate and check its schema.
type SchemaCheckAdapter interface {
	betterauth.DatabaseAdapter
	betterauth.SchemaChecker
	Migrate(context.Context, betterauth.Schema) error
}

// SchemaCheckTarget is one fresh, empty database for the schema check suite.
type SchemaCheckTarget struct {
	Adapter SchemaCheckAdapter
	// Exec runs one raw SQL statement against the database.
	Exec func(t *testing.T, statement string)
	// Table returns the quoted table name to use in raw SQL, including any
	// schema the adapter is configured with.
	Table func(name string) string
}

// SchemaCheckFactory returns a fresh, empty database for each call.
type SchemaCheckFactory func(*testing.T) SchemaCheckTarget

func schemaCheckModels() betterauth.Schema {
	return betterauth.Schema{
		"sc_user": {Fields: map[string]betterauth.FieldSchema{
			"id":    {Type: betterauth.FieldString, Required: true, Unique: true},
			"email": {Type: betterauth.FieldString},
		}},
		"sc_session": {Fields: map[string]betterauth.FieldSchema{
			"id": {Type: betterauth.FieldString, Required: true, Unique: true},
		}},
	}
}

// RunSchemaCheck runs the live schema check contract for SQL adapters.
func RunSchemaCheck(t *testing.T, factory SchemaCheckFactory) {
	t.Helper()
	t.Run("missing tables then clean after Migrate", func(t *testing.T) {
		target := factory(t)
		ctx := t.Context()
		schema := schemaCheckModels()
		findings, err := target.Adapter.CheckSchema(ctx, schema)
		if err != nil {
			t.Fatal(err)
		}
		want := []betterauth.SchemaFinding{
			{Kind: betterauth.SchemaFindingMissingTable, Table: "sc_session"},
			{Kind: betterauth.SchemaFindingMissingTable, Table: "sc_user"},
		}
		if !reflect.DeepEqual(findings, want) {
			t.Fatalf("findings before Migrate = %#v, want %#v", findings, want)
		}
		if err := target.Adapter.Migrate(ctx, schema); err != nil {
			t.Fatal(err)
		}
		if findings, err := target.Adapter.CheckSchema(ctx, schema); err != nil || len(findings) != 0 {
			t.Fatalf("findings after Migrate = %#v, %v", findings, err)
		}
	})

	t.Run("missing column and required column Better Auth never writes", func(t *testing.T) {
		target := factory(t)
		ctx := t.Context()
		schema := schemaCheckModels()
		if err := target.Adapter.Migrate(ctx, betterauth.Schema{"sc_session": schema["sc_session"]}); err != nil {
			t.Fatal(err)
		}
		target.Exec(t, "CREATE TABLE "+target.Table("sc_user")+` ("id" TEXT NOT NULL, `+
			`"legacy" TEXT NOT NULL, "note" TEXT, "kind" TEXT NOT NULL DEFAULT 'member')`)
		findings, err := target.Adapter.CheckSchema(ctx, schema)
		if err != nil {
			t.Fatal(err)
		}
		want := []betterauth.SchemaFinding{
			{Kind: betterauth.SchemaFindingMissingColumn, Table: "sc_user", Column: "email"},
			{Kind: betterauth.SchemaFindingUnexpectedRequiredColumn, Table: "sc_user", Column: "legacy"},
		}
		if !reflect.DeepEqual(findings, want) {
			t.Fatalf("findings = %#v, want %#v", findings, want)
		}
		// Migrate adds the missing column, but only the application can
		// relax a column Better Auth does not own.
		if err := target.Adapter.Migrate(ctx, schema); err != nil {
			t.Fatal(err)
		}
		findings, err = target.Adapter.CheckSchema(ctx, schema)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(findings, want[1:]) {
			t.Fatalf("findings after Migrate = %#v, want %#v", findings, want[1:])
		}
		target.Exec(t, "ALTER TABLE "+target.Table("sc_user")+` DROP COLUMN "legacy"`)
		if findings, err := target.Adapter.CheckSchema(ctx, schema); err != nil || len(findings) != 0 {
			t.Fatalf("findings after repair = %#v, %v", findings, err)
		}
	})

	t.Run("server rejects requests until Migrate runs", func(t *testing.T) {
		target := factory(t)
		ctx := t.Context()
		server, err := betterauth.New(betterauth.Config{
			PublicURL: "https://auth.example.com", TrustedOrigins: []string{"https://app.example.com"},
			Database: target.Adapter, Mailer: discardMailer{}, ImpersonationAuthorizer: denyImpersonation{},
		})
		if err != nil {
			t.Fatal(err)
		}
		status, code := getSession(t, server.Handler())
		if status != http.StatusInternalServerError || code != "SCHEMA_MISMATCH" {
			t.Fatalf("request before Migrate = %d %q", status, code)
		}
		var mismatch *betterauth.SchemaMismatchError
		if err := server.CheckSchema(ctx); !errors.As(err, &mismatch) || len(mismatch.Findings) == 0 {
			t.Fatalf("CheckSchema() before Migrate = %v", err)
		}
		if err := target.Adapter.Migrate(ctx, server.Schema()); err != nil {
			t.Fatal(err)
		}
		// No restart: the next request checks again and passes.
		if status, code := getSession(t, server.Handler()); status != http.StatusOK {
			t.Fatalf("request after Migrate = %d %q", status, code)
		}
		if err := server.CheckSchema(ctx); err != nil {
			t.Fatalf("CheckSchema() after Migrate = %v", err)
		}
	})

	t.Run("server skips the check when validation is off", func(t *testing.T) {
		target := factory(t)
		server, err := betterauth.New(betterauth.Config{
			PublicURL: "https://auth.example.com", TrustedOrigins: []string{"https://app.example.com"},
			Database: target.Adapter, Mailer: discardMailer{}, ImpersonationAuthorizer: denyImpersonation{},
			DisableSchemaValidation: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		if status, code := getSession(t, server.Handler()); status != http.StatusOK {
			t.Fatalf("request with validation off = %d %q", status, code)
		}
	})
}

func getSession(t *testing.T, handler http.Handler) (int, string) {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, "https://auth.example.com/api/auth/get-session", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	var body struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(recorder.Body.Bytes(), &body)
	return recorder.Code, body.Code
}

type discardMailer struct{}

func (discardMailer) Send(context.Context, betterauth.Mail) error { return nil }

type denyImpersonation struct{}

func (denyImpersonation) CanImpersonate(context.Context, betterauth.User, betterauth.User) error {
	return errors.New("impersonation is not allowed")
}
