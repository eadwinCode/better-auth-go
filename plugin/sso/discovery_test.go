package sso

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type doerFunc func(*http.Request) (*http.Response, error)

func (function doerFunc) Do(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestDiscoverOIDCValidatesAndReturnsDocument(t *testing.T) {
	t.Parallel()
	client := doerFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.String() !=
			"https://idp.example.com/.well-known/openid-configuration" {
			t.Fatalf("discovery URL = %q", request.URL)
		}
		return discoveryResponse(`{
			"issuer":"https://idp.example.com",
			"authorization_endpoint":"https://idp.example.com/authorize",
			"token_endpoint":"https://idp.example.com/token",
			"userinfo_endpoint":"https://idp.example.com/userinfo",
			"jwks_uri":"https://idp.example.com/jwks",
			"response_types_supported":["code"],
			"id_token_signing_alg_values_supported":["RS256"],
			"token_endpoint_auth_methods_supported":["client_secret_basic"],
			"claims_supported":["sub","email"]
		}`), nil
	})
	document, err := DiscoverOIDC(
		context.Background(), client, PublicHTTPSURLPolicy,
		"https://idp.example.com", defaultDiscoveryLimit,
	)
	if err != nil {
		t.Fatal(err)
	}
	if document.TokenEndpoint != "https://idp.example.com/token" {
		t.Fatalf("token endpoint = %q", document.TokenEndpoint)
	}
}

func TestDiscoverOIDCRejectsIssuerMismatch(t *testing.T) {
	t.Parallel()
	client := doerFunc(func(*http.Request) (*http.Response, error) {
		return discoveryResponse(`{
			"issuer":"https://attacker.example",
			"authorization_endpoint":"https://idp.example.com/authorize",
			"token_endpoint":"https://idp.example.com/token",
			"jwks_uri":"https://idp.example.com/jwks"
		}`), nil
	})
	if _, err := DiscoverOIDC(
		context.Background(), client, PublicHTTPSURLPolicy,
		"https://idp.example.com", defaultDiscoveryLimit,
	); err == nil || !strings.Contains(err.Error(), "issuer mismatch") {
		t.Fatalf("expected issuer mismatch, got %v", err)
	}
}

func TestDiscoverOIDCRejectsUntrustedDiscoveredEndpoint(t *testing.T) {
	t.Parallel()
	client := doerFunc(func(*http.Request) (*http.Response, error) {
		return discoveryResponse(`{
			"issuer":"https://idp.example.com",
			"authorization_endpoint":"https://idp.example.com/authorize",
			"token_endpoint":"http://127.0.0.1/token",
			"jwks_uri":"https://idp.example.com/jwks"
		}`), nil
	})
	if _, err := DiscoverOIDC(
		context.Background(), client, PublicHTTPSURLPolicy,
		"https://idp.example.com", defaultDiscoveryLimit,
	); err == nil || !strings.Contains(err.Error(), "untrusted token") {
		t.Fatalf("expected untrusted token endpoint, got %v", err)
	}
}

func TestDiscoverOIDCRejectsImplicitOnlyProvider(t *testing.T) {
	t.Parallel()
	client := doerFunc(func(*http.Request) (*http.Response, error) {
		return discoveryResponse(`{
			"issuer":"https://idp.example.com",
			"authorization_endpoint":"https://idp.example.com/authorize",
			"token_endpoint":"https://idp.example.com/token",
			"jwks_uri":"https://idp.example.com/jwks",
			"response_types_supported":["id_token"]
		}`), nil
	})
	if _, err := DiscoverOIDC(
		context.Background(), client, PublicHTTPSURLPolicy,
		"https://idp.example.com", defaultDiscoveryLimit,
	); err == nil || !strings.Contains(err.Error(), "authorization code") {
		t.Fatalf("expected authorization-code failure, got %v", err)
	}
}

func TestDiscoverOIDCRejectsOversizedDocument(t *testing.T) {
	t.Parallel()
	client := doerFunc(func(*http.Request) (*http.Response, error) {
		return discoveryResponse(strings.Repeat("x", 1025)), nil
	})
	if _, err := DiscoverOIDC(
		context.Background(), client, PublicHTTPSURLPolicy,
		"https://idp.example.com", 1024,
	); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("expected size failure, got %v", err)
	}
}

func discoveryResponse(body string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}
