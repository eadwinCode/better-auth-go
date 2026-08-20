package betterauth_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	betterauth "github.com/eadwinCode/better-auth-go"
	"github.com/eadwinCode/better-auth-go/adapter/memory"
)

func newPluginServer(
	t *testing.T,
	database betterauth.DatabaseAdapter,
	limiter betterauth.RateLimiter,
	plugins ...betterauth.Plugin,
) http.Handler {
	t.Helper()
	if database == nil {
		database = memory.New()
	}
	server, err := betterauth.New(betterauth.Config{
		PublicURL: "https://auth.example.com", TrustedOrigins: []string{"https://app.example.com"},
		Database: database, Mailer: discardMailer{}, ImpersonationAuthorizer: denyImpersonation{},
		RateLimiter: limiter, Plugins: plugins,
		Clock:  fixedClock{now: time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)},
		Tokens: &sequenceTokens{},
	})
	if err != nil {
		t.Fatal(err)
	}
	return server.Handler()
}

func pluginRequest(
	t *testing.T,
	handler http.Handler,
	method string,
	path string,
	origin string,
	body string,
) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, "https://auth.example.com/api/auth"+path, bytes.NewBufferString(body))
	request.Header.Set("Origin", origin)
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func TestPluginLifecycleEndpointAndTrustedOrigin(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	var calls []string
	appendCall := func(value string) {
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, value)
	}
	matcher := func(context *betterauth.HookContext) bool {
		return context.Path == "/example/echo"
	}
	plugin := betterauth.Plugin{
		ID: "example",
		TrustedOrigins: []string{
			"https://plugin.example.com",
		},
		OnRequest: func(*betterauth.HookContext) (*betterauth.PluginResponse, error) {
			appendCall("onRequest")
			return nil, nil
		},
		Middlewares: []betterauth.PluginMiddleware{{
			Matcher: matcher,
			Handler: func(*betterauth.HookContext) (*betterauth.PluginResponse, error) {
				appendCall("middleware")
				return nil, nil
			},
		}},
		Before: []betterauth.PluginBeforeHook{{
			Matcher: matcher,
			Handler: func(context *betterauth.HookContext) (*betterauth.PluginResponse, error) {
				appendCall("before")
				body := context.Body.(map[string]any)
				body["hooked"] = true
				context.Headers.Set("X-Plugin-Request", "yes")
				return nil, nil
			},
		}},
		Endpoints: []betterauth.PluginEndpoint{{
			Name: "echo", Path: "/example/echo", Method: http.MethodPost,
			Handler: func(context *betterauth.HookContext) (*betterauth.PluginResponse, error) {
				appendCall("endpoint")
				if context.Request.Header.Get("X-Plugin-Request") != "yes" {
					return nil, errors.New("request header mutation was not applied")
				}
				return betterauth.JSONResponse(http.StatusCreated, context.Body)
			},
		}},
		After: []betterauth.PluginAfterHook{{
			Matcher: matcher,
			Handler: func(_ *betterauth.HookContext, response *betterauth.PluginResponse) error {
				appendCall("after")
				var body map[string]any
				if err := response.DecodeJSON(&body); err != nil {
					return err
				}
				body["after"] = true
				return response.SetJSON(body)
			},
		}},
		OnResponse: func(_ *betterauth.HookContext, response *betterauth.PluginResponse) error {
			appendCall("onResponse")
			response.Headers.Set("X-Plugin-Response", "yes")
			return nil
		},
	}
	handler := newPluginServer(t, nil, nil, plugin)
	response := pluginRequest(
		t, handler, http.MethodPost, "/example/echo", "https://plugin.example.com", `{"name":"Ada"}`,
	)
	if response.Code != http.StatusCreated {
		t.Fatalf("unexpected status %d: %s", response.Code, response.Body.String())
	}
	if response.Header().Get("X-Plugin-Response") != "yes" ||
		response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("missing response/security headers: %#v", response.Header())
	}
	var body map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["name"] != "Ada" || body["hooked"] != true || body["after"] != true {
		t.Fatalf("unexpected response body: %#v", body)
	}
	expected := []string{"onRequest", "middleware", "before", "endpoint", "after", "onResponse"}
	if !reflect.DeepEqual(calls, expected) {
		t.Fatalf("unexpected lifecycle order: %#v", calls)
	}
}

func TestOriginFailsBeforePluginCode(t *testing.T) {
	t.Parallel()
	var called atomic.Int64
	handler := newPluginServer(t, nil, nil, betterauth.Plugin{
		ID: "origin-test",
		OnRequest: func(*betterauth.HookContext) (*betterauth.PluginResponse, error) {
			called.Add(1)
			return nil, nil
		},
		Endpoints: []betterauth.PluginEndpoint{{
			Path: "/origin-test", Method: http.MethodPost,
			Handler: func(*betterauth.HookContext) (*betterauth.PluginResponse, error) {
				called.Add(1)
				return betterauth.JSONResponse(http.StatusOK, map[string]bool{"ok": true})
			},
		}},
	})
	response := pluginRequest(t, handler, http.MethodPost, "/origin-test", "https://evil.example", `{}`)
	if response.Code != http.StatusForbidden || called.Load() != 0 {
		t.Fatalf("origin did not fail before plugin code: status=%d calls=%d", response.Code, called.Load())
	}
}

func TestPluginUnsafeMethodsRequireOriginUnlessExplicitlySkipped(t *testing.T) {
	t.Parallel()
	var called atomic.Int64
	var endpoints []betterauth.PluginEndpoint
	for _, method := range []string{
		http.MethodPut, http.MethodPatch, http.MethodDelete,
	} {
		method := method
		endpoints = append(endpoints, betterauth.PluginEndpoint{
			Name: method, Path: "/scim-test/resource", Method: method,
			Handler: func(*betterauth.HookContext) (*betterauth.PluginResponse, error) {
				called.Add(1)
				return betterauth.JSONResponse(http.StatusOK, map[string]string{"method": method})
			},
		})
	}
	endpoints = append(endpoints, betterauth.PluginEndpoint{
		Name: "bearer", Path: "/scim-test/bearer", Method: http.MethodPatch,
		SkipOriginCheck: true,
		Handler: func(*betterauth.HookContext) (*betterauth.PluginResponse, error) {
			called.Add(1)
			return betterauth.JSONResponse(http.StatusNoContent, nil)
		},
	})
	handler := newPluginServer(t, nil, nil, betterauth.Plugin{
		ID: "scim-methods", Endpoints: endpoints,
	})
	for _, method := range []string{
		http.MethodPut, http.MethodPatch, http.MethodDelete,
	} {
		response := pluginRequest(
			t, handler, method, "/scim-test/resource", "https://evil.example", `{}`,
		)
		if response.Code != http.StatusForbidden {
			t.Fatalf("%s origin status = %d", method, response.Code)
		}
	}
	if called.Load() != 0 {
		t.Fatalf("unsafe methods reached endpoint before origin validation: %d", called.Load())
	}
	response := pluginRequest(
		t, handler, http.MethodPatch, "/scim-test/bearer", "https://idp.example", `{}`,
	)
	if response.Code != http.StatusNoContent || called.Load() != 1 {
		t.Fatalf("explicit bearer origin exception failed: %d calls=%d",
			response.Code, called.Load())
	}
}

func TestPluginEndpointValidatorsRunBeforeMiddlewareAndHandler(t *testing.T) {
	t.Parallel()
	var calls atomic.Int64
	plugin := betterauth.Plugin{
		ID: "validated",
		Endpoints: []betterauth.PluginEndpoint{{
			Path: "/validated", Method: http.MethodPost,
			BodyValidator: betterauth.ObjectValidator{Fields: map[string]betterauth.FieldValidation{
				"name": {
					Kind: betterauth.ValidationString, Required: true, MinLength: 2, MaxLength: 32,
				},
			}},
			QueryValidator: betterauth.ObjectValidator{Fields: map[string]betterauth.FieldValidation{
				"mode": {
					Kind: betterauth.ValidationString, Required: true, Enum: []string{"safe"},
				},
			}},
			Use: []betterauth.RequestHook{func(*betterauth.HookContext) (*betterauth.PluginResponse, error) {
				calls.Add(1)
				return nil, nil
			}},
			Handler: func(*betterauth.HookContext) (*betterauth.PluginResponse, error) {
				calls.Add(1)
				return betterauth.JSONResponse(http.StatusOK, map[string]bool{"ok": true})
			},
		}},
	}
	handler := newPluginServer(t, nil, nil, plugin)
	invalid := pluginRequest(
		t, handler, http.MethodPost, "/validated?mode=safe", "https://app.example.com", `{"name":"x"}`,
	)
	if invalid.Code != http.StatusBadRequest || calls.Load() != 0 ||
		bytes.Contains(invalid.Body.Bytes(), []byte("invalid length")) {
		t.Fatalf("validator did not fail safely before endpoint code: %d %s calls=%d",
			invalid.Code, invalid.Body.String(), calls.Load())
	}
	trailing := pluginRequest(
		t, handler, http.MethodPost, "/validated?mode=safe", "https://app.example.com",
		`{"name":"Ada"} {"name":"Grace"}`,
	)
	if trailing.Code != http.StatusBadRequest || calls.Load() != 0 {
		t.Fatalf("trailing JSON reached endpoint code: %d %s calls=%d",
			trailing.Code, trailing.Body.String(), calls.Load())
	}
	valid := pluginRequest(
		t, handler, http.MethodPost, "/validated?mode=safe", "https://app.example.com", `{"name":"Ada"}`,
	)
	if valid.Code != http.StatusOK || calls.Load() != 2 {
		t.Fatalf("valid request was rejected: %d %s calls=%d", valid.Code, valid.Body.String(), calls.Load())
	}
}

func TestInvalidDeclarativeValidatorFailsServerConstruction(t *testing.T) {
	t.Parallel()
	_, err := betterauth.New(betterauth.Config{
		PublicURL: "https://auth.example.com", TrustedOrigins: []string{"https://app.example.com"},
		Database: memory.New(), Mailer: discardMailer{}, ImpersonationAuthorizer: denyImpersonation{},
		Plugins: []betterauth.Plugin{{
			ID: "invalid-validator",
			Endpoints: []betterauth.PluginEndpoint{{
				Path: "/invalid-validator", Method: http.MethodPost,
				BodyValidator: betterauth.ObjectValidator{Fields: map[string]betterauth.FieldValidation{
					"value": {Kind: betterauth.ValidationString, MinLength: 4, MaxLength: 2},
				}},
				Handler: func(*betterauth.HookContext) (*betterauth.PluginResponse, error) {
					return betterauth.JSONResponse(http.StatusOK, nil)
				},
			}},
		}},
	})
	if err == nil {
		t.Fatal("invalid endpoint validator was accepted")
	}
}

func TestPluginCanModifyCoreRequestAndResponse(t *testing.T) {
	t.Parallel()
	plugin := betterauth.Plugin{
		ID: "core-hooks",
		Before: []betterauth.PluginBeforeHook{{
			Matcher: func(context *betterauth.HookContext) bool { return context.Path == "/sign-up/email" },
			Handler: func(context *betterauth.HookContext) (*betterauth.PluginResponse, error) {
				context.Body.(map[string]any)["name"] = "Hooked Name"
				return nil, nil
			},
		}},
		After: []betterauth.PluginAfterHook{{
			Matcher: func(context *betterauth.HookContext) bool { return context.Path == "/sign-up/email" },
			Handler: func(_ *betterauth.HookContext, response *betterauth.PluginResponse) error {
				response.Headers.Set("X-Core-Hooked", "yes")
				return nil
			},
		}},
	}
	handler := newPluginServer(t, nil, nil, plugin)
	response := pluginRequest(t, handler, http.MethodPost, "/sign-up/email", "https://app.example.com",
		`{"email":"hooks@example.com","password":"correct horse battery staple","name":"Original"}`)
	if response.Code != http.StatusOK || response.Header().Get("X-Core-Hooked") != "yes" ||
		!bytes.Contains(response.Body.Bytes(), []byte(`"name":"Hooked Name"`)) {
		t.Fatalf("core hook failed: %d %s", response.Code, response.Body.String())
	}
}

func TestEarlyResponseStillRunsOnResponse(t *testing.T) {
	t.Parallel()
	var endpointCalled atomic.Bool
	plugin := betterauth.Plugin{
		ID: "early",
		OnRequest: func(*betterauth.HookContext) (*betterauth.PluginResponse, error) {
			return betterauth.JSONResponse(http.StatusAccepted, map[string]string{"source": "early"})
		},
		OnResponse: func(_ *betterauth.HookContext, response *betterauth.PluginResponse) error {
			response.Headers.Set("X-On-Response", "yes")
			return nil
		},
		Endpoints: []betterauth.PluginEndpoint{{
			Path: "/early", Method: http.MethodGet,
			Handler: func(*betterauth.HookContext) (*betterauth.PluginResponse, error) {
				endpointCalled.Store(true)
				return betterauth.JSONResponse(http.StatusOK, nil)
			},
		}},
	}
	response := pluginRequest(t, newPluginServer(t, nil, nil, plugin), http.MethodGet, "/early", "", "")
	if response.Code != http.StatusAccepted || endpointCalled.Load() ||
		response.Header().Get("X-On-Response") != "yes" {
		t.Fatalf("unexpected early response: %d %s", response.Code, response.Body.String())
	}
}

type captureRateLimiter struct {
	mu       sync.Mutex
	requests []betterauth.RateLimitRequest
	allow    bool
}

func (limiter *captureRateLimiter) Allow(
	_ context.Context,
	request betterauth.RateLimitRequest,
) (betterauth.RateLimitDecision, error) {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	limiter.requests = append(limiter.requests, request)
	return betterauth.RateLimitDecision{Allowed: limiter.allow, RetryAfter: 3 * time.Second}, nil
}

func TestPluginRateLimitRule(t *testing.T) {
	t.Parallel()
	limiter := &captureRateLimiter{allow: false}
	plugin := betterauth.Plugin{
		ID: "limited",
		RateLimits: []betterauth.PluginRateLimitRule{{
			Matcher: func(context *betterauth.HookContext) bool { return context.Path == "/limited" },
			Action:  "limited/read", Window: time.Minute, Max: 7,
			AccountKey: func(*betterauth.HookContext) string { return "account" },
		}},
		Endpoints: []betterauth.PluginEndpoint{{
			Path: "/limited", Method: http.MethodGet,
			Handler: func(*betterauth.HookContext) (*betterauth.PluginResponse, error) {
				return betterauth.JSONResponse(http.StatusOK, nil)
			},
		}},
	}
	response := pluginRequest(t, newPluginServer(t, nil, limiter, plugin), http.MethodGet, "/limited", "", "")
	if response.Code != http.StatusTooManyRequests || response.Header().Get("Retry-After") != "3" {
		t.Fatalf("unexpected limit response: %d %#v", response.Code, response.Header())
	}
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	if len(limiter.requests) != 1 || limiter.requests[0].Window != time.Minute ||
		limiter.requests[0].Max != 7 || limiter.requests[0].AccountKey != "account" {
		t.Fatalf("unexpected rate-limit request: %#v", limiter.requests)
	}
}

func TestPluginSchemaAndDatabaseHooksRunInsideCoreTransaction(t *testing.T) {
	t.Parallel()
	database := memory.New()
	var before, after atomic.Int64
	plugin := betterauth.Plugin{
		ID: "tenant",
		Schema: betterauth.Schema{
			betterauth.ModelUser: {
				Fields: map[string]betterauth.FieldSchema{
					"tenantId": {Type: betterauth.FieldString},
				},
			},
		},
		DatabaseHooks: []betterauth.DatabaseHook{{
			Model: betterauth.ModelUser, Operations: []betterauth.DatabaseOperation{betterauth.DatabaseCreate},
			Before: func(_ context.Context, hook *betterauth.DatabaseHookContext) error {
				before.Add(1)
				hook.Data["tenantId"] = "tenant-1"
				return nil
			},
			After: func(_ context.Context, hook *betterauth.DatabaseHookContext) error {
				after.Add(1)
				if hook.Result["tenantId"] != "tenant-1" {
					return errors.New("tenant field was not persisted")
				}
				return nil
			},
		}},
	}
	handler := newPluginServer(t, database, nil, plugin)
	response := pluginRequest(t, handler, http.MethodPost, "/sign-up/email", "https://app.example.com",
		`{"email":"tenant@example.com","password":"correct horse battery staple","name":"Tenant"}`)
	if response.Code != http.StatusOK || before.Load() != 1 || after.Load() != 1 {
		t.Fatalf("database hooks failed: %d before=%d after=%d %s",
			response.Code, before.Load(), after.Load(), response.Body.String())
	}
	row, err := database.FindOne(context.Background(), betterauth.FindOneQuery{
		Model: betterauth.ModelUser, Where: []betterauth.Where{betterauth.Eq("email", "tenant@example.com")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if row["tenantId"] != "tenant-1" {
		t.Fatalf("plugin schema field not stored: %#v", row)
	}
}

func TestPluginValidationFailsClosed(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		plugins []betterauth.Plugin
	}{
		{"duplicate id", []betterauth.Plugin{{ID: "same"}, {ID: "same"}}},
		{"missing dependency", []betterauth.Plugin{{ID: "one", Dependencies: []string{"missing"}}}},
		{"dependency cycle", []betterauth.Plugin{
			{ID: "one", Dependencies: []string{"two"}},
			{ID: "two", Dependencies: []string{"one"}},
		}},
		{"core collision", []betterauth.Plugin{{
			ID: "collision", Endpoints: []betterauth.PluginEndpoint{{
				Path: "/sign-in/email", Method: http.MethodPost,
				Handler: func(*betterauth.HookContext) (*betterauth.PluginResponse, error) { return nil, nil },
			}},
		}}},
		{"invalid origin", []betterauth.Plugin{{ID: "origin", TrustedOrigins: []string{"https://*.co.uk"}}}},
		{"invalid endpoint path", []betterauth.Plugin{{
			ID: "path", Endpoints: []betterauth.PluginEndpoint{{
				Path: "/Not-Kebab", Method: http.MethodGet,
				Handler: func(*betterauth.HookContext) (*betterauth.PluginResponse, error) {
					return betterauth.JSONResponse(http.StatusOK, nil)
				},
			}},
		}}},
		{"overlapping endpoint templates", []betterauth.Plugin{{
			ID: "paths", Endpoints: []betterauth.PluginEndpoint{
				{
					Path: "/documents/:id", Method: http.MethodGet,
					Handler: func(*betterauth.HookContext) (*betterauth.PluginResponse, error) {
						return betterauth.JSONResponse(http.StatusOK, nil)
					},
				},
				{
					Path: "/:collection/item", Method: http.MethodGet,
					Handler: func(*betterauth.HookContext) (*betterauth.PluginResponse, error) {
						return betterauth.JSONResponse(http.StatusOK, nil)
					},
				},
			},
		}}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			config := validConfig()
			config.Plugins = test.plugins
			if _, err := betterauth.New(config); err == nil {
				t.Fatal("expected plugin configuration error")
			}
		})
	}
}

func TestDatabaseAfterHookFailureIsReportedAfterCommit(t *testing.T) {
	t.Parallel()
	database := memory.New()
	plugin := betterauth.Plugin{
		ID: "rollback",
		DatabaseHooks: []betterauth.DatabaseHook{{
			Model: betterauth.ModelUser, Operations: []betterauth.DatabaseOperation{betterauth.DatabaseCreate},
			After: func(context.Context, *betterauth.DatabaseHookContext) error {
				return errors.New("reject user creation")
			},
		}},
	}
	handler := newPluginServer(t, database, nil, plugin)
	response := pluginRequest(t, handler, http.MethodPost, "/sign-up/email", "https://app.example.com",
		`{"email":"rollback@example.com","password":"correct horse battery staple","name":"Rollback"}`)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("hook failure did not abort signup: %d %s", response.Code, response.Body.String())
	}
	record, err := database.FindOne(context.Background(), betterauth.FindOneQuery{
		Model: betterauth.ModelUser, Where: []betterauth.Where{betterauth.Eq("email", "rollback@example.com")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if record == nil {
		t.Fatal("after-hook failure incorrectly claimed to roll back a committed user")
	}
}

func TestDatabaseAfterHooksAreDiscardedOnRollback(t *testing.T) {
	t.Parallel()
	database := memory.New()
	var after atomic.Int64
	plugin := betterauth.Plugin{
		ID: "commit-boundary",
		DatabaseHooks: []betterauth.DatabaseHook{
			{
				Model:      betterauth.ModelUser,
				Operations: []betterauth.DatabaseOperation{betterauth.DatabaseCreate},
				After: func(context.Context, *betterauth.DatabaseHookContext) error {
					after.Add(1)
					return nil
				},
			},
			{
				Model:      betterauth.ModelAccount,
				Operations: []betterauth.DatabaseOperation{betterauth.DatabaseCreate},
				Before: func(context.Context, *betterauth.DatabaseHookContext) error {
					return errors.New("force transaction rollback")
				},
			},
		},
	}
	handler := newPluginServer(t, database, nil, plugin)
	response := pluginRequest(t, handler, http.MethodPost, "/sign-up/email", "https://app.example.com",
		`{"email":"commit-boundary@example.com","password":"correct horse battery staple","name":"Rollback"}`)
	if response.Code != http.StatusInternalServerError || after.Load() != 0 {
		t.Fatalf("rolled-back after effect executed: status=%d after=%d", response.Code, after.Load())
	}
	record, err := database.FindOne(context.Background(), betterauth.FindOneQuery{
		Model: betterauth.ModelUser,
		Where: []betterauth.Where{betterauth.Eq("email", "commit-boundary@example.com")},
	})
	if err != nil || record != nil {
		t.Fatalf("rollback persisted user: %#v, %v", record, err)
	}
}

func TestOnResponseRunsForUnknownRoutesAndCannotRemoveSecurityHeaders(t *testing.T) {
	t.Parallel()
	var called atomic.Int64
	plugin := betterauth.Plugin{
		ID: "global-response",
		OnResponse: func(_ *betterauth.HookContext, response *betterauth.PluginResponse) error {
			called.Add(1)
			response.Headers.Del("Cache-Control")
			response.Headers.Set("X-Global-Response", "yes")
			return nil
		},
	}
	response := pluginRequest(
		t, newPluginServer(t, nil, nil, plugin), http.MethodGet, "/missing-route", "", "",
	)
	if response.Code != http.StatusNotFound || called.Load() != 1 ||
		response.Header().Get("X-Global-Response") != "yes" ||
		response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("unexpected global response hook behavior: %d %#v", response.Code, response.Header())
	}
}

func TestPluginPanicIsContained(t *testing.T) {
	t.Parallel()
	handler := newPluginServer(t, nil, nil, betterauth.Plugin{
		ID: "panic",
		OnRequest: func(*betterauth.HookContext) (*betterauth.PluginResponse, error) {
			panic("secret panic value")
		},
		Endpoints: []betterauth.PluginEndpoint{{
			Path: "/panic", Method: http.MethodGet,
			Handler: func(*betterauth.HookContext) (*betterauth.PluginResponse, error) {
				return betterauth.JSONResponse(http.StatusOK, nil)
			},
		}},
	})
	response := pluginRequest(t, handler, http.MethodGet, "/panic", "", "")
	if response.Code != http.StatusInternalServerError ||
		bytes.Contains(response.Body.Bytes(), []byte("secret panic value")) {
		t.Fatalf("panic was not safely contained: %d %s", response.Code, response.Body.String())
	}
}

func TestPluginInitDependenciesApplicationHooksAndBackgroundTasks(t *testing.T) {
	t.Parallel()
	var callsMu sync.Mutex
	var calls []string
	appendCall := func(value string) {
		callsMu.Lock()
		defer callsMu.Unlock()
		calls = append(calls, value)
	}
	var initialized atomic.Int64
	var background atomic.Int64
	dependency := betterauth.Plugin{
		ID: "dependency",
		OnRequest: func(*betterauth.HookContext) (*betterauth.PluginResponse, error) {
			appendCall("dependency")
			return nil, nil
		},
	}
	feature := betterauth.Plugin{
		ID: "feature", Dependencies: []string{"dependency"},
		Init: func(context betterauth.PluginInitContext) (betterauth.PluginInitResult, error) {
			initialized.Add(1)
			if context.PluginID != "feature" ||
				context.BaseURL != "https://auth.example.com/api/auth" {
				return betterauth.PluginInitResult{}, errors.New("invalid init context")
			}
			return betterauth.PluginInitResult{
				TrustedOrigins: []string{"https://init.example.com"},
				Schema: betterauth.Schema{
					"featureRecord": {
						Fields: map[string]betterauth.FieldSchema{
							"id": {Type: betterauth.FieldString, Required: true, Unique: true},
						},
					},
				},
			}, nil
		},
		OnRequest: func(*betterauth.HookContext) (*betterauth.PluginResponse, error) {
			appendCall("feature")
			return nil, nil
		},
		OnResponse: func(_ *betterauth.HookContext, _ *betterauth.PluginResponse) error {
			appendCall("feature-response")
			return nil
		},
		Endpoints: []betterauth.PluginEndpoint{{
			Path: "/feature/run", Method: http.MethodPost,
			Handler: func(hookContext *betterauth.HookContext) (*betterauth.PluginResponse, error) {
				appendCall("endpoint")
				if _, exists := hookContext.Schema["featureRecord"]; !exists ||
					!hookContext.IsTrustedOrigin("https://init.example.com") {
					return nil, errors.New("init contributions are unavailable")
				}
				if err := hookContext.RunInBackground(func(context.Context) error {
					background.Add(1)
					return nil
				}); err != nil {
					return nil, err
				}
				return betterauth.JSONResponse(http.StatusOK, map[string]bool{"ok": true})
			},
		}},
	}
	config := validConfig()
	config.Plugins = []betterauth.Plugin{feature, dependency}
	config.Hooks = betterauth.ServerHooks{
		OnRequest: func(*betterauth.HookContext) (*betterauth.PluginResponse, error) {
			appendCall("application-request")
			return nil, nil
		},
		OnResponse: func(_ *betterauth.HookContext, response *betterauth.PluginResponse) error {
			appendCall("application-response")
			response.Headers.Set("X-Application-Hook", "yes")
			return nil
		},
	}
	server, err := betterauth.New(config)
	if err != nil {
		t.Fatal(err)
	}
	response := pluginRequest(
		t, server.Handler(), http.MethodPost, "/feature/run", "https://init.example.com", `{}`,
	)
	if response.Code != http.StatusOK || response.Header().Get("X-Application-Hook") != "yes" ||
		initialized.Load() != 1 || background.Load() != 1 {
		t.Fatalf("plugin init/hooks failed: %d %s", response.Code, response.Body.String())
	}
	expected := []string{
		"application-request", "dependency", "feature", "endpoint",
		"feature-response", "application-response",
	}
	if !reflect.DeepEqual(calls, expected) {
		t.Fatalf("unexpected dependency/application order: %#v", calls)
	}
}

func TestPluginResponseSetCookieEnforcesHostCookieContract(t *testing.T) {
	t.Parallel()
	plugin := betterauth.Plugin{
		ID: "cookie",
		Endpoints: []betterauth.PluginEndpoint{{
			Path: "/cookie", Method: http.MethodGet,
			Handler: func(*betterauth.HookContext) (*betterauth.PluginResponse, error) {
				response, err := betterauth.JSONResponse(http.StatusOK, map[string]bool{"ok": true})
				if err != nil {
					return nil, err
				}
				err = response.SetCookie(&http.Cookie{
					Name: "__Host-plugin-state", Value: "opaque", Path: "/",
					Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
				})
				return response, err
			},
		}},
	}
	response := pluginRequest(t, newPluginServer(t, nil, nil, plugin), http.MethodGet, "/cookie", "", "")
	if response.Code != http.StatusOK {
		t.Fatalf("unexpected cookie endpoint response: %d %s", response.Code, response.Body.String())
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != "__Host-plugin-state" ||
		!cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].Path != "/" ||
		cookies[0].Domain != "" {
		t.Fatalf("unsafe plugin cookie: %#v", cookies)
	}

	invalid, err := betterauth.JSONResponse(http.StatusOK, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := invalid.SetCookie(&http.Cookie{Name: "plugin", Path: "/"}); err == nil {
		t.Fatal("accepted an insecure plugin cookie")
	}
}

func TestPluginDescriptorsAreCopiedDuringNew(t *testing.T) {
	t.Parallel()
	plugin := betterauth.Plugin{
		ID:             "immutable",
		TrustedOrigins: []string{"https://original.example.com"},
		Endpoints: []betterauth.PluginEndpoint{{
			Path: "/immutable", Method: http.MethodPost,
			Handler: func(*betterauth.HookContext) (*betterauth.PluginResponse, error) {
				return betterauth.JSONResponse(http.StatusOK, map[string]string{"value": "original"})
			},
		}},
	}
	config := validConfig()
	config.Plugins = []betterauth.Plugin{plugin}
	server, err := betterauth.New(config)
	if err != nil {
		t.Fatal(err)
	}

	plugin.TrustedOrigins[0] = "https://mutated.example.com"
	plugin.Endpoints[0].Handler = func(*betterauth.HookContext) (*betterauth.PluginResponse, error) {
		return betterauth.JSONResponse(http.StatusOK, map[string]string{"value": "mutated"})
	}

	response := pluginRequest(
		t, server.Handler(), http.MethodPost, "/immutable", "https://original.example.com", `{}`,
	)
	if response.Code != http.StatusOK ||
		!bytes.Contains(response.Body.Bytes(), []byte(`"value":"original"`)) {
		t.Fatalf("compiled plugin changed after descriptor mutation: %d %s", response.Code, response.Body.String())
	}
	mutatedOrigin := pluginRequest(
		t, server.Handler(), http.MethodPost, "/immutable", "https://mutated.example.com", `{}`,
	)
	if mutatedOrigin.Code != http.StatusForbidden {
		t.Fatalf("post-New origin mutation was accepted: %d", mutatedOrigin.Code)
	}
}

func TestDynamicEndpointSessionAndResourceOwnershipMiddleware(t *testing.T) {
	t.Parallel()
	database := memory.New()
	ownership, err := betterauth.RequireResourceOwnership(betterauth.ResourceOwnershipConfig{
		Model: "document", IDSource: betterauth.ResourceIDParams,
	})
	if err != nil {
		t.Fatal(err)
	}
	plugin := betterauth.Plugin{
		ID: "documents",
		Schema: betterauth.Schema{
			"document": {
				Fields: map[string]betterauth.FieldSchema{
					"id":     {Type: betterauth.FieldString, Required: true, Unique: true},
					"userId": {Type: betterauth.FieldString, Required: true, References: betterauth.ModelUser},
					"title":  {Type: betterauth.FieldString, Required: true},
				},
			},
		},
		Endpoints: []betterauth.PluginEndpoint{
			{
				Path: "/documents/:id", Method: http.MethodGet,
				Use: []betterauth.RequestHook{betterauth.SessionMiddleware, ownership},
				Handler: func(context *betterauth.HookContext) (*betterauth.PluginResponse, error) {
					return betterauth.JSONResponse(http.StatusOK, map[string]string{
						"id": context.Params["id"], "userId": context.User.ID,
					})
				},
			},
			{
				Path: "/documents/:id/title", Method: http.MethodPost,
				Use: []betterauth.RequestHook{
					betterauth.SessionMiddleware, betterauth.CSRFMiddleware, ownership,
				},
				Handler: func(*betterauth.HookContext) (*betterauth.PluginResponse, error) {
					return betterauth.JSONResponse(http.StatusOK, map[string]bool{"updated": true})
				},
			},
		},
	}
	handler := newPluginServer(t, database, nil, plugin)
	client := &testClient{handler: handler, database: database}
	signup := client.request(t, http.MethodPost, "/sign-up/email", map[string]any{
		"email": "owner@example.com", "password": "correct horse battery staple", "name": "Owner",
	}, false)
	if signup.Code != http.StatusOK {
		t.Fatal(signup.Body.String())
	}
	var signupBody struct {
		User betterauth.User `json:"user"`
	}
	if err := json.Unmarshal(signup.Body.Bytes(), &signupBody); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Create(context.Background(), betterauth.CreateQuery{
		Model: "document", ForceAllowID: true,
		Data: betterauth.Record{
			"id": "doc-1", "userId": signupBody.User.ID, "title": "Private",
		},
	}); err != nil {
		t.Fatal(err)
	}
	owned := client.request(t, http.MethodGet, "/documents/doc-1", nil, false)
	if owned.Code != http.StatusOK || !bytes.Contains(owned.Body.Bytes(), []byte(`"id":"doc-1"`)) {
		t.Fatalf("owned resource failed: %d %s", owned.Code, owned.Body.String())
	}
	notOwned := client.request(t, http.MethodGet, "/documents/missing", nil, false)
	if notOwned.Code != http.StatusNotFound {
		t.Fatalf("missing resource disclosed unexpectedly: %d %s", notOwned.Code, notOwned.Body.String())
	}
	withoutCSRF := client.request(t, http.MethodPost, "/documents/doc-1/title", map[string]any{}, false)
	if withoutCSRF.Code != http.StatusForbidden {
		t.Fatalf("plugin mutation accepted without CSRF token: %d", withoutCSRF.Code)
	}
	withCSRF := client.request(t, http.MethodPost, "/documents/doc-1/title", map[string]any{}, true)
	if withCSRF.Code != http.StatusOK {
		t.Fatalf("plugin mutation rejected valid CSRF token: %d %s", withCSRF.Code, withCSRF.Body.String())
	}
	anonymous := &testClient{handler: handler, database: database}
	unauthorized := anonymous.request(t, http.MethodGet, "/documents/doc-1", nil, false)
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("session middleware did not reject anonymous request: %d", unauthorized.Code)
	}
}

func TestPluginRuntimeIsConcurrentRequestSafe(t *testing.T) {
	t.Parallel()
	var calls atomic.Int64
	plugin := betterauth.Plugin{
		ID: "concurrent",
		Endpoints: []betterauth.PluginEndpoint{{
			Path: "/concurrent/:id", Method: http.MethodGet,
			Handler: func(context *betterauth.HookContext) (*betterauth.PluginResponse, error) {
				calls.Add(1)
				return betterauth.JSONResponse(http.StatusOK, map[string]string{"id": context.Params["id"]})
			},
		}},
	}
	handler := newPluginServer(t, nil, nil, plugin)
	const requests = 64
	var wait sync.WaitGroup
	wait.Add(requests)
	for index := range requests {
		go func() {
			defer wait.Done()
			response := pluginRequest(
				t, handler, http.MethodGet, "/concurrent/"+string(rune('a'+index%26)), "", "",
			)
			if response.Code != http.StatusOK {
				t.Errorf("unexpected concurrent status %d", response.Code)
			}
		}()
	}
	wait.Wait()
	if calls.Load() != requests {
		t.Fatalf("lost plugin calls: got %d want %d", calls.Load(), requests)
	}
}
