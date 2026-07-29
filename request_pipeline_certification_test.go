package betterauth_test

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	betterauth "github.com/eadwinCode/better-auth-go"
	"github.com/eadwinCode/better-auth-go/adapter/memory"
)

type failingRateLimiter struct {
	panicValue bool
	err        error
	decision   betterauth.RateLimitDecision
}

func (limiter failingRateLimiter) Allow(
	context.Context,
	betterauth.RateLimitRequest,
) (betterauth.RateLimitDecision, error) {
	if limiter.panicValue {
		panic("rate-limiter-secret")
	}
	return limiter.decision, limiter.err
}

func TestPipelineRejectsOversizedRequestsBeforeHooksAndEndpoints(t *testing.T) {
	t.Parallel()
	var called atomic.Int64
	plugin := betterauth.Plugin{
		ID: "request-limit",
		OnRequest: func(*betterauth.HookContext) (*betterauth.PluginResponse, error) {
			called.Add(1)
			return nil, nil
		},
		Endpoints: []betterauth.PluginEndpoint{{
			Path: "/request-limit", Method: http.MethodPost,
			Handler: func(*betterauth.HookContext) (*betterauth.PluginResponse, error) {
				called.Add(1)
				return betterauth.JSONResponse(http.StatusOK, nil)
			},
		}},
	}
	config := validConfig()
	config.MaxRequestBytes = 1024
	config.Plugins = []betterauth.Plugin{plugin}
	server, err := betterauth.New(config)
	if err != nil {
		t.Fatal(err)
	}
	response := pluginRequest(
		t,
		server.Handler(),
		http.MethodPost,
		"/request-limit",
		"https://app.example.com",
		`{"value":"`+strings.Repeat("x", 2048)+`"}`,
	)
	if response.Code != http.StatusRequestEntityTooLarge || called.Load() != 0 {
		t.Fatalf(
			"oversized request reached plugin code: status=%d calls=%d body=%s",
			response.Code, called.Load(), response.Body,
		)
	}
	assertPipelineSecurityHeaders(t, response)
}

func TestPipelineBoundsPluginResponsesAndRestoresSecurityHeaders(t *testing.T) {
	t.Parallel()
	plugin := betterauth.Plugin{
		ID: "response-limit",
		Endpoints: []betterauth.PluginEndpoint{{
			Path: "/response-limit", Method: http.MethodGet,
			Handler: func(*betterauth.HookContext) (*betterauth.PluginResponse, error) {
				return &betterauth.PluginResponse{
					Status: http.StatusOK,
					Headers: http.Header{
						"Cache-Control":          []string{"public"},
						"X-Content-Type-Options": nil,
					},
					Body: bytes.Repeat([]byte("x"), 2048),
				}, nil
			},
		}},
		OnResponse: func(_ *betterauth.HookContext, response *betterauth.PluginResponse) error {
			response.Headers.Del("Cache-Control")
			response.Headers.Del("X-Content-Type-Options")
			return nil
		},
	}
	config := validConfig()
	config.MaxResponseBytes = 1024
	config.Plugins = []betterauth.Plugin{plugin}
	server, err := betterauth.New(config)
	if err != nil {
		t.Fatal(err)
	}
	response := pluginRequest(t, server.Handler(), http.MethodGet, "/response-limit", "", "")
	if response.Code != http.StatusInternalServerError ||
		bytes.Contains(response.Body.Bytes(), bytes.Repeat([]byte("x"), 64)) {
		t.Fatalf("oversized plugin response escaped: status=%d body=%s", response.Code, response.Body)
	}
	assertPipelineSecurityHeaders(t, response)
}

func TestPipelineContainsValidatorLimiterAndAccountKeyFailures(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		validator betterauth.EndpointValidator
		limiter   betterauth.RateLimiter
		account   func(*betterauth.HookContext) string
		status    int
	}{
		{
			name: "validator panic",
			validator: betterauth.EndpointValidatorFunc(func(any) error {
				panic("validator-secret")
			}),
			limiter: betterauth.NopRateLimiter{},
			status:  http.StatusBadRequest,
		},
		{
			name:    "limiter error",
			limiter: failingRateLimiter{err: errors.New("limiter-secret")},
			status:  http.StatusInternalServerError,
		},
		{
			name:    "limiter panic",
			limiter: failingRateLimiter{panicValue: true},
			status:  http.StatusInternalServerError,
		},
		{
			name:    "account key panic",
			limiter: betterauth.NopRateLimiter{},
			account: func(*betterauth.HookContext) string {
				panic("account-key-secret")
			},
			status: http.StatusInternalServerError,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			var endpointCalled atomic.Int64
			plugin := betterauth.Plugin{
				ID: "failure-containment",
				RateLimits: []betterauth.PluginRateLimitRule{{
					Matcher: func(ctx *betterauth.HookContext) bool {
						return ctx.Path == "/failure-containment"
					},
					Action: "failure-containment", Window: time.Minute, Max: 1,
					AccountKey: test.account,
				}},
				Endpoints: []betterauth.PluginEndpoint{{
					Path: "/failure-containment", Method: http.MethodPost,
					BodyValidator: test.validator,
					Handler: func(*betterauth.HookContext) (*betterauth.PluginResponse, error) {
						endpointCalled.Add(1)
						return betterauth.JSONResponse(http.StatusOK, nil)
					},
				}},
			}
			response := pluginRequest(
				t,
				newPluginServer(t, nil, test.limiter, plugin),
				http.MethodPost,
				"/failure-containment",
				"https://app.example.com",
				`{}`,
			)
			if response.Code != test.status || endpointCalled.Load() != 0 {
				t.Fatalf(
					"failure escaped pipeline: status=%d calls=%d body=%s",
					response.Code, endpointCalled.Load(), response.Body,
				)
			}
			for _, secret := range []string{
				"validator-secret", "limiter-secret", "rate-limiter-secret", "account-key-secret",
			} {
				if bytes.Contains(response.Body.Bytes(), []byte(secret)) {
					t.Fatalf("internal failure leaked %q: %s", secret, response.Body)
				}
			}
			assertPipelineSecurityHeaders(t, response)
		})
	}
}

func TestPipelineBoundsRetryAfterAndCoreLimiterFailureRollsBack(t *testing.T) {
	t.Parallel()
	limited := failingRateLimiter{decision: betterauth.RateLimitDecision{
		Allowed: false, RetryAfter: 365 * 24 * time.Hour,
	}}
	plugin := betterauth.Plugin{
		ID: "retry-limit",
		RateLimits: []betterauth.PluginRateLimitRule{{
			Matcher: func(ctx *betterauth.HookContext) bool { return ctx.Path == "/retry-limit" },
			Action:  "retry-limit", Window: time.Minute, Max: 1,
		}},
		Endpoints: []betterauth.PluginEndpoint{{
			Path: "/retry-limit", Method: http.MethodGet,
			Handler: func(*betterauth.HookContext) (*betterauth.PluginResponse, error) {
				return betterauth.JSONResponse(http.StatusOK, nil)
			},
		}},
	}
	response := pluginRequest(
		t, newPluginServer(t, nil, limited, plugin), http.MethodGet, "/retry-limit", "", "",
	)
	if response.Code != http.StatusTooManyRequests ||
		response.Header().Get("Retry-After") != "86400" {
		t.Fatalf("retry metadata was not bounded: status=%d headers=%v", response.Code, response.Header())
	}

	database := memory.New()
	handler := newPluginServer(
		t,
		database,
		failingRateLimiter{panicValue: true},
	)
	signup := pluginRequest(
		t,
		handler,
		http.MethodPost,
		"/sign-up/email",
		"https://app.example.com",
		`{"email":"limit@example.com","password":"correct horse battery staple","name":"Limited"}`,
	)
	if signup.Code != http.StatusInternalServerError {
		t.Fatalf("core limiter panic status=%d body=%s", signup.Code, signup.Body)
	}
	user, err := database.FindOne(context.Background(), betterauth.FindOneQuery{
		Model: betterauth.ModelUser,
		Where: []betterauth.Where{betterauth.Eq("email", "limit@example.com")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if user != nil {
		t.Fatalf("core limiter failure persisted a user: %#v", user)
	}
}

func assertPipelineSecurityHeaders(t *testing.T, response interface {
	Header() http.Header
}) {
	t.Helper()
	header := response.Header()
	if header.Get("Cache-Control") != "no-store" ||
		header.Get("Pragma") != "no-cache" ||
		header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("mandatory security headers missing: %#v", header)
	}
}
