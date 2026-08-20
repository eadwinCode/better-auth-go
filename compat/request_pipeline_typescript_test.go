package betterauth_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	betterauth "github.com/eadwinCode/better-auth-go"
)

func TestBetterAuthV170TrustedOriginPolicyCompatibility(t *testing.T) {
	oracle := newTypeScriptOracle(t)
	wildcardOracle := oracle.clone(t)
	wildcardOracle.basePath += "-origin-wildcard"
	dynamicOracle := oracle.clone(t)
	dynamicOracle.basePath += "-origin-dynamic"

	wildcardGo, _ := newBlackBoxServerConfig(t, func(config *betterauth.Config) {
		config.TrustedOrigins = []string{"https://*.example.com"}
	})
	dynamicGo, _ := newBlackBoxServerConfig(t, func(config *betterauth.Config) {
		config.TrustedOrigins = nil
		config.TrustedOriginResolver = betterauth.TrustedOriginResolverFunc(
			func(_ context.Context, request *http.Request) ([]string, error) {
				return []string{request.Header.Get("X-Tenant-Origin")}, nil
			},
		)
	})

	for _, test := range []struct {
		name         string
		origin       string
		dynamic      string
		goClient     *testClient
		oracleClient *typescriptOracle
		want         int
	}{
		{
			name: "wildcard match", origin: "https://tenant.example.com",
			goClient: wildcardGo, oracleClient: wildcardOracle, want: http.StatusOK,
		},
		{
			name: "wildcard attacker suffix", origin: "https://tenant.example.com.evil.test",
			goClient: wildcardGo, oracleClient: wildcardOracle, want: http.StatusForbidden,
		},
		{
			name: "dynamic match", origin: "https://tenant.example.net",
			dynamic:  "https://tenant.example.net",
			goClient: dynamicGo, oracleClient: dynamicOracle, want: http.StatusOK,
		},
		{
			name: "dynamic mismatch", origin: "https://other.example.net",
			dynamic:  "https://tenant.example.net",
			goClient: dynamicGo, oracleClient: dynamicOracle, want: http.StatusForbidden,
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			email := uniqueCompatibilityEmail("origin")
			body := map[string]any{
				"email": email, "password": "Correct-Horse-123!", "name": "Origin User",
			}
			goResult := compatibilityOriginRequest(
				t, test.goClient.handler, "/sign-up/email", test.origin, test.dynamic, body,
			)
			tsResult := test.oracleClient.requestWithHeaders(
				t,
				http.MethodPost,
				"/sign-up/email",
				body,
				test.origin,
				http.Header{
					"Cookie":          []string{"compatibility=1"},
					"X-Tenant-Origin": []string{test.dynamic},
				},
			)
			for implementation, result := range map[string]oracleResponse{
				"Go": goResult, "TypeScript": tsResult,
			} {
				if result.status != test.want {
					t.Fatalf(
						"%s trusted-origin status=%d want=%d body=%s",
						implementation, result.status, test.want, result.body,
					)
				}
			}
		})
	}
}

func compatibilityOriginRequest(
	t *testing.T,
	handler http.Handler,
	path string,
	origin string,
	dynamic string,
	body any,
) oracleResponse {
	t.Helper()
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(
		http.MethodPost,
		"https://auth.example.com/api/auth"+path,
		bytes.NewReader(payload),
	)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", origin)
	request.Header.Set("Cookie", "compatibility=1")
	request.Header.Set("X-Tenant-Origin", dynamic)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return goResponse(recorder)
}
