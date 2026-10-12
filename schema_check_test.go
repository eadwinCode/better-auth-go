package betterauth_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	betterauth "github.com/eadwinCode/better-auth-go"
	"github.com/eadwinCode/better-auth-go/adapter/memory"
)

// checkedMemory is a memory adapter with a scripted live schema check.
type checkedMemory struct {
	*memory.Adapter
	mu       sync.Mutex
	findings []betterauth.SchemaFinding
	err      error
	release  chan struct{}
	calls    atomic.Int32
}

func (adapter *checkedMemory) CheckSchema(
	ctx context.Context,
	_ betterauth.Schema,
) ([]betterauth.SchemaFinding, error) {
	adapter.calls.Add(1)
	adapter.mu.Lock()
	release := adapter.release
	adapter.mu.Unlock()
	if release != nil {
		select {
		case <-release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	return adapter.findings, adapter.err
}

func (adapter *checkedMemory) set(findings []betterauth.SchemaFinding, err error) {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	adapter.findings, adapter.err = findings, err
}

var issuerDrift = []betterauth.SchemaFinding{{
	Kind: betterauth.SchemaFindingUnexpectedRequiredColumn, Table: "account", Column: "issuer",
}}

func newSchemaCheckServer(
	t *testing.T,
	database betterauth.DatabaseAdapter,
	configure func(*betterauth.Config),
) *betterauth.Server {
	t.Helper()
	config := betterauth.Config{
		PublicURL: "https://auth.example.com", TrustedOrigins: []string{"https://app.example.com"},
		Database: database, Mailer: discardMailer{}, ImpersonationAuthorizer: denyImpersonation{},
		Clock:  fixedClock{now: time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)},
		Tokens: &sequenceTokens{},
	}
	if configure != nil {
		configure(&config)
	}
	server, err := betterauth.New(config)
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func getSession(t *testing.T, handler http.Handler) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, "https://auth.example.com/api/auth/get-session", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	var body map[string]any
	_ = json.Unmarshal(recorder.Body.Bytes(), &body)
	return recorder, body
}

func TestDiffSchemaReportsMissingTablesColumnsAndRequiredColumns(t *testing.T) {
	t.Parallel()
	schema := betterauth.Schema{
		"user": {Fields: map[string]betterauth.FieldSchema{
			"id": {Type: betterauth.FieldString}, "email": {Type: betterauth.FieldString},
		}},
		"session": {Fields: map[string]betterauth.FieldSchema{
			"id": {Type: betterauth.FieldString},
		}},
		"account": {ModelName: "auth_account", Fields: map[string]betterauth.FieldSchema{
			"id":     {Type: betterauth.FieldString, FieldName: "account_id"},
			"userId": {Type: betterauth.FieldString, FieldName: "user_id"},
		}},
	}
	tables := []betterauth.IntrospectedTable{
		{Name: "user", Columns: []betterauth.IntrospectedColumn{{Name: "id"}}},
		{Name: "auth_account", Columns: []betterauth.IntrospectedColumn{
			{Name: "account_id"}, {Name: "user_id"},
			{Name: "issuer"},
			{Name: "note", Nullable: true},
			{Name: "kind", HasDefault: true},
		}},
	}
	got := betterauth.DiffSchema(schema, tables)
	want := []betterauth.SchemaFinding{
		{Kind: betterauth.SchemaFindingUnexpectedRequiredColumn, Table: "auth_account", Column: "issuer"},
		{Kind: betterauth.SchemaFindingMissingTable, Table: "session"},
		{Kind: betterauth.SchemaFindingMissingColumn, Table: "user", Column: "email"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("DiffSchema() = %#v, want %#v", got, want)
	}
	clean := []betterauth.IntrospectedTable{
		{Name: "user", Columns: []betterauth.IntrospectedColumn{{Name: "id"}, {Name: "email"}}},
		{Name: "session", Columns: []betterauth.IntrospectedColumn{{Name: "id"}}},
		{Name: "auth_account", Columns: []betterauth.IntrospectedColumn{
			{Name: "account_id"}, {Name: "user_id"}, {Name: "note", Nullable: true},
		}},
	}
	if got := betterauth.DiffSchema(schema, clean); len(got) != 0 {
		t.Fatalf("clean schema reported findings: %#v", got)
	}
}

func TestDiffSchemaMergesModelsThatShareATable(t *testing.T) {
	t.Parallel()
	schema := betterauth.Schema{
		"managed": {ModelName: "shared", Fields: map[string]betterauth.FieldSchema{
			"id": {Type: betterauth.FieldString}, "value": {Type: betterauth.FieldString},
		}},
		"other": {ModelName: "shared", Fields: map[string]betterauth.FieldSchema{
			"id": {Type: betterauth.FieldString}, "extra": {Type: betterauth.FieldString},
		}},
	}
	got := betterauth.DiffSchema(schema, []betterauth.IntrospectedTable{
		{Name: "shared", Columns: []betterauth.IntrospectedColumn{{Name: "id"}, {Name: "value"}}},
	})
	want := []betterauth.SchemaFinding{
		{Kind: betterauth.SchemaFindingMissingColumn, Table: "shared", Column: "extra"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("DiffSchema() = %#v, want %#v", got, want)
	}
}

func TestSchemaMismatchErrorMessage(t *testing.T) {
	t.Parallel()
	err := &betterauth.SchemaMismatchError{Findings: []betterauth.SchemaFinding{
		{Kind: betterauth.SchemaFindingMissingColumn, Table: "user", Column: "email"},
		issuerDrift[0],
		{Kind: betterauth.SchemaFindingMissingTable, Table: "verification"},
	}}
	want := "Database schema mismatch\n\n" +
		"  Missing tables\n    verification\n\n" +
		"  Missing columns\n    user.email\n\n" +
		"  Required columns Better Auth never writes\n    account.issuer\n\n" +
		"  Inserts into account will fail.\n\n" +
		"  help: Make the listed columns nullable, give them defaults, or remove them.\n" +
		"        Run the adapter's Migrate with Server.Schema() to add the missing tables and columns.\n\n" +
		"  note: If this column came from Better Auth 1.7.0 through 1.7.2,\n" +
		"        follow the upgrade guide before removing it:\n" +
		"        https://www.better-auth.com/docs/guides/1-7-upgrade-guide"
	if err.Error() != want {
		t.Fatalf("message mismatch:\n%s\nwant:\n%s", err.Error(), want)
	}
	if err.Code() != "SCHEMA_MISMATCH" {
		t.Fatalf("code = %q", err.Code())
	}
	finding := issuerDrift[0].String()
	if !strings.Contains(finding, "If this column came from Better Auth 1.7.0 through 1.7.2") {
		t.Fatalf("issuer finding misses the upgrade note: %s", finding)
	}
}

func TestSchemaCheckRejectsRequestsUntilTheSchemaIsFixed(t *testing.T) {
	t.Parallel()
	database := &checkedMemory{Adapter: memory.New()}
	database.set(issuerDrift, nil)
	var pluginCalls atomic.Int32
	server := newSchemaCheckServer(t, database, func(config *betterauth.Config) {
		config.Plugins = []betterauth.Plugin{{
			ID: "request-handler",
			OnRequest: func(*betterauth.HookContext) (*betterauth.PluginResponse, error) {
				pluginCalls.Add(1)
				return nil, nil
			},
		}}
	})

	recorder, body := getSession(t, server.Handler())
	if recorder.Code != http.StatusInternalServerError || body["code"] != "SCHEMA_MISMATCH" {
		t.Fatalf("request before migration = %d %v", recorder.Code, body)
	}
	if strings.Contains(recorder.Body.String(), "issuer") {
		t.Fatalf("response leaked schema details: %s", recorder.Body.String())
	}
	if pluginCalls.Load() != 0 {
		t.Fatal("a plugin handled the request before the schema check")
	}
	var mismatch *betterauth.SchemaMismatchError
	if _, err := server.ResolveSession(t.Context(), httptest.NewRequest(http.MethodGet, "/", nil)); !errors.As(err, &mismatch) {
		t.Fatalf("ResolveSession() error = %v, want schema mismatch", err)
	}
	if err := server.CheckSchema(t.Context()); !errors.As(err, &mismatch) ||
		!reflect.DeepEqual(mismatch.Findings, issuerDrift) {
		t.Fatalf("CheckSchema() = %v", err)
	}

	// Fixing the database (for example by running Migrate) is picked up on
	// the next request without a restart.
	database.set(nil, nil)
	recorder, _ = getSession(t, server.Handler())
	if recorder.Code != http.StatusOK {
		t.Fatalf("request after migration = %d %s", recorder.Code, recorder.Body.String())
	}
	calls := database.calls.Load()
	for range 3 {
		if recorder, _ := getSession(t, server.Handler()); recorder.Code != http.StatusOK {
			t.Fatalf("later request = %d", recorder.Code)
		}
	}
	if err := server.CheckSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
	if database.calls.Load() != calls {
		t.Fatalf("a clean result was not kept: %d checks after %d", database.calls.Load(), calls)
	}
	if pluginCalls.Load() == 0 {
		t.Fatal("plugin did not run after the schema check passed")
	}
}

func TestSchemaCheckRetriesDatabaseErrorsWithoutLeakingThem(t *testing.T) {
	t.Parallel()
	database := &checkedMemory{Adapter: memory.New()}
	database.set(nil, errors.New("postgres://user:secret@private-db/database"))
	server := newSchemaCheckServer(t, database, nil)

	recorder, body := getSession(t, server.Handler())
	if recorder.Code != http.StatusInternalServerError || body["code"] != "INTERNAL_SERVER_ERROR" {
		t.Fatalf("request with failing check = %d %v", recorder.Code, body)
	}
	if strings.Contains(recorder.Body.String(), "secret") {
		t.Fatalf("response leaked the driver error: %s", recorder.Body.String())
	}
	database.set(nil, nil)
	if recorder, _ := getSession(t, server.Handler()); recorder.Code != http.StatusOK {
		t.Fatalf("request after recovery = %d", recorder.Code)
	}
	if database.calls.Load() != 2 {
		t.Fatalf("checks = %d, want 2", database.calls.Load())
	}
}

func TestSchemaCheckCanBeDisabled(t *testing.T) {
	t.Parallel()
	database := &checkedMemory{Adapter: memory.New()}
	database.set(issuerDrift, nil)
	server := newSchemaCheckServer(t, database, func(config *betterauth.Config) {
		config.DisableSchemaValidation = true
	})
	if recorder, _ := getSession(t, server.Handler()); recorder.Code != http.StatusOK {
		t.Fatalf("request with validation off = %d %s", recorder.Code, recorder.Body.String())
	}
	if _, err := server.ResolveSession(t.Context(), httptest.NewRequest(http.MethodGet, "/", nil)); !errors.Is(err, betterauth.ErrNoSession) {
		t.Fatalf("ResolveSession() error = %v", err)
	}
	if database.calls.Load() != 0 {
		t.Fatalf("requests ran %d schema checks with validation off", database.calls.Load())
	}
	// The explicit check still works, like Better Auth's explicit check for
	// migration tooling.
	var mismatch *betterauth.SchemaMismatchError
	if err := server.CheckSchema(t.Context()); !errors.As(err, &mismatch) {
		t.Fatalf("CheckSchema() = %v", err)
	}
}

func TestSchemaCheckSharesOneRunningCheck(t *testing.T) {
	t.Parallel()
	database := &checkedMemory{Adapter: memory.New(), release: make(chan struct{})}
	server := newSchemaCheckServer(t, database, nil)
	var group sync.WaitGroup
	codes := make([]int, 8)
	for index := range codes {
		group.Add(1)
		go func() {
			defer group.Done()
			recorder, _ := getSession(t, server.Handler())
			codes[index] = recorder.Code
		}()
	}
	deadline := time.Now().Add(5 * time.Second)
	for database.calls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	close(database.release)
	group.Wait()
	for _, code := range codes {
		if code != http.StatusOK {
			t.Fatalf("codes = %v", codes)
		}
	}
	if database.calls.Load() != 1 {
		t.Fatalf("concurrent requests ran %d checks, want 1", database.calls.Load())
	}
}

func TestSchemaCheckSkipsAdaptersWithoutAChecker(t *testing.T) {
	t.Parallel()
	server := newSchemaCheckServer(t, memory.New(), nil)
	if err := server.CheckSchema(t.Context()); err != nil {
		t.Fatalf("CheckSchema() = %v", err)
	}
	if recorder, _ := getSession(t, server.Handler()); recorder.Code != http.StatusOK {
		t.Fatalf("request = %d", recorder.Code)
	}
}
