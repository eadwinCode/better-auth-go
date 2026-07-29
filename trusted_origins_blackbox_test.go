package betterauth_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	betterauth "github.com/eadwinCode/better-auth-go"
)

func originPolicyPlugin(
	called *atomic.Int64,
	inspect func(*betterauth.HookContext) error,
) betterauth.Plugin {
	return betterauth.Plugin{
		ID: "origin-policy",
		OnRequest: func(ctx *betterauth.HookContext) (*betterauth.PluginResponse, error) {
			called.Add(1)
			if inspect != nil {
				if err := inspect(ctx); err != nil {
					return nil, err
				}
			}
			return nil, nil
		},
		Endpoints: []betterauth.PluginEndpoint{{
			Path: "/origin-policy", Method: http.MethodPost,
			Handler: func(*betterauth.HookContext) (*betterauth.PluginResponse, error) {
				called.Add(1)
				return betterauth.JSONResponse(http.StatusOK, map[string]bool{"ok": true})
			},
		}},
	}
}

func newOriginPolicyHandler(
	t *testing.T,
	origins []string,
	resolver betterauth.TrustedOriginResolver,
	plugin betterauth.Plugin,
) http.Handler {
	t.Helper()
	config := validConfig()
	config.TrustedOrigins = origins
	config.TrustedOriginResolver = resolver
	config.Plugins = []betterauth.Plugin{plugin}
	server, err := betterauth.New(config)
	if err != nil {
		t.Fatal(err)
	}
	return server.Handler()
}

func TestWildcardTrustedOriginsAreHostAndSchemeBound(t *testing.T) {
	t.Parallel()
	var called atomic.Int64
	handler := newOriginPolicyHandler(
		t,
		[]string{
			"https://*.example.com",
			"https://preview-??.example.net:8443",
			"http://[::1]:3000",
		},
		nil,
		originPolicyPlugin(&called, nil),
	)
	for _, test := range []struct {
		name   string
		origin string
		status int
	}{
		{"subdomain", "https://tenant.example.com", http.StatusOK},
		{"nested subdomain", "https://a.b.example.com", http.StatusOK},
		{"bounded question wildcard", "https://preview-ab.example.net:8443", http.StatusOK},
		{"apex excluded", "https://example.com", http.StatusForbidden},
		{"attacker suffix", "https://tenant.example.com.evil.test", http.StatusForbidden},
		{"prefix confusion", "https://evilexample.com", http.StatusForbidden},
		{"wrong scheme", "http://tenant.example.com", http.StatusForbidden},
		{"wrong port", "https://preview-ab.example.net", http.StatusForbidden},
		{"question wildcard length", "https://preview-a.example.net:8443", http.StatusForbidden},
		{"exact IPv6 loopback", "http://[::1]:3000", http.StatusOK},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			response := pluginRequest(
				t, handler, http.MethodPost, "/origin-policy", test.origin, `{}`,
			)
			if response.Code != test.status {
				t.Fatalf("origin %q status=%d body=%s", test.origin, response.Code, response.Body)
			}
		})
	}
	if called.Load() != 8 {
		t.Fatalf("trusted requests should call onRequest and endpoint: calls=%d", called.Load())
	}
}

func TestWildcardTrustedOriginConfigurationFailsClosed(t *testing.T) {
	t.Parallel()
	for _, origin := range []string{
		"https://*.com",
		"https://*.co.uk",
		"http://*.example.com",
		"https://*",
		"https://*.127.0.0.1",
		"https://*.example.com/path",
		"https://user@*.example.com",
		"https://*.example.com:*",
		"https://*.example.com:",
		"https://bad label*.example.com",
	} {
		origin := origin
		t.Run(origin, func(t *testing.T) {
			config := validConfig()
			config.TrustedOrigins = []string{origin}
			if _, err := betterauth.New(config); err == nil {
				t.Fatalf("accepted unsafe trusted-origin pattern %q", origin)
			}
		})
	}
}

func TestRequestScopedTrustedOriginsResolveOnceAndRemainAdditive(t *testing.T) {
	t.Parallel()
	var resolverCalls atomic.Int64
	var pipelineCalls atomic.Int64
	resolver := betterauth.TrustedOriginResolverFunc(
		func(_ context.Context, request *http.Request) ([]string, error) {
			resolverCalls.Add(1)
			return []string{"https://" + request.Header.Get("X-Tenant") + ".tenant.example"}, nil
		},
	)
	handler := newOriginPolicyHandler(
		t,
		[]string{"https://static.example.com"},
		resolver,
		originPolicyPlugin(&pipelineCalls, func(ctx *betterauth.HookContext) error {
			if len(ctx.TrustedOrigins) != 2 ||
				!ctx.IsTrustedOrigin("https://static.example.com") ||
				!ctx.IsTrustedOrigin("https://alpha.tenant.example") ||
				ctx.IsTrustedOrigin("https://beta.tenant.example") {
				return fmt.Errorf("request-scoped policy mismatch: %#v", ctx.TrustedOrigins)
			}
			return nil
		}),
	)
	request := newPluginOriginRequest(
		http.MethodPost,
		"/origin-policy",
		"https://alpha.tenant.example",
		"alpha",
	)
	response := serveRequest(handler, request)
	if response.Code != http.StatusOK {
		t.Fatalf("dynamic origin status=%d body=%s", response.Code, response.Body)
	}
	if resolverCalls.Load() != 1 || pipelineCalls.Load() != 2 {
		t.Fatalf("resolver/pipeline calls=%d/%d", resolverCalls.Load(), pipelineCalls.Load())
	}

	staticRequest := newPluginOriginRequest(
		http.MethodPost,
		"/origin-policy",
		"https://static.example.com",
		"alpha",
	)
	if response := serveRequest(handler, staticRequest); response.Code != http.StatusOK {
		t.Fatalf("static additive origin status=%d body=%s", response.Code, response.Body)
	}
	if resolverCalls.Load() != 2 {
		t.Fatalf("resolver should run once for each request: calls=%d", resolverCalls.Load())
	}
}

func TestRequestScopedTrustedOriginsDoNotBleedAcrossConcurrentRequests(t *testing.T) {
	t.Parallel()
	var called atomic.Int64
	handler := newOriginPolicyHandler(
		t,
		nil,
		betterauth.TrustedOriginResolverFunc(
			func(_ context.Context, request *http.Request) ([]string, error) {
				return []string{"https://" + request.Header.Get("X-Tenant") + ".example.com"}, nil
			},
		),
		originPolicyPlugin(&called, nil),
	)
	const requests = 100
	failures := make(chan error, requests*2)
	var wait sync.WaitGroup
	for index := range requests {
		index := index
		for _, valid := range []bool{true, false} {
			valid := valid
			wait.Add(1)
			go func() {
				defer wait.Done()
				tenant := fmt.Sprintf("tenant-%d", index)
				originTenant := tenant
				want := http.StatusOK
				if !valid {
					originTenant = fmt.Sprintf("tenant-%d", (index+1)%requests)
					want = http.StatusForbidden
				}
				request := newPluginOriginRequest(
					http.MethodPost,
					"/origin-policy",
					"https://"+originTenant+".example.com",
					tenant,
				)
				response := serveRequest(handler, request)
				if response.Code != want {
					failures <- fmt.Errorf(
						"tenant=%s valid=%v status=%d body=%s",
						tenant, valid, response.Code, response.Body,
					)
				}
			}()
		}
	}
	wait.Wait()
	close(failures)
	for err := range failures {
		t.Error(err)
	}
	if called.Load() != requests*2 {
		t.Fatalf("only valid requests should reach two pipeline stages: calls=%d", called.Load())
	}
}

func TestTrustedOriginResolverFailuresRunNoPluginCode(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name     string
		resolver betterauth.TrustedOriginResolver
	}{
		{
			"error",
			betterauth.TrustedOriginResolverFunc(
				func(context.Context, *http.Request) ([]string, error) {
					return nil, errors.New("resolver unavailable")
				},
			),
		},
		{
			"panic",
			betterauth.TrustedOriginResolverFunc(
				func(context.Context, *http.Request) ([]string, error) {
					panic("resolver panic")
				},
			),
		},
		{
			"invalid result",
			betterauth.TrustedOriginResolverFunc(
				func(context.Context, *http.Request) ([]string, error) {
					return []string{"https://*.co.uk"}, nil
				},
			),
		},
		{
			"too many results",
			betterauth.TrustedOriginResolverFunc(
				func(context.Context, *http.Request) ([]string, error) {
					values := make([]string, 129)
					for index := range values {
						values[index] = fmt.Sprintf("https://tenant-%d.example.com", index)
					}
					return values, nil
				},
			),
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			var called atomic.Int64
			handler := newOriginPolicyHandler(
				t,
				[]string{"https://static.example.com"},
				test.resolver,
				originPolicyPlugin(&called, nil),
			)
			response := pluginRequest(
				t,
				handler,
				http.MethodPost,
				"/origin-policy",
				"https://static.example.com",
				`{}`,
			)
			if response.Code != http.StatusForbidden || called.Load() != 0 {
				t.Fatalf(
					"resolver failure did not fail closed: status=%d calls=%d body=%s",
					response.Code, called.Load(), response.Body,
				)
			}
		})
	}
}

func newPluginOriginRequest(
	method string,
	path string,
	origin string,
	tenant string,
) *http.Request {
	request, err := http.NewRequest(
		method,
		"https://auth.example.com/api/auth"+path,
		http.NoBody,
	)
	if err != nil {
		panic(err)
	}
	request.Header.Set("Origin", origin)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Tenant", tenant)
	return request
}

func serveRequest(handler http.Handler, request *http.Request) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}
