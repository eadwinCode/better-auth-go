package sso

import (
	"context"
	"errors"
	"net/url"
	"testing"

	betterauth "github.com/eadwinCode/better-auth-go"
)

func TestNewRequiresCipher(t *testing.T) {
	t.Parallel()
	if _, err := New(Config{}); err == nil {
		t.Fatal("expected a missing-cipher error")
	}
}

func TestNewContributesNonSecretProviderSchema(t *testing.T) {
	t.Parallel()
	plugin, err := New(Config{Cipher: testCipher(t), DomainVerification: true, DNSResolver: stubDNS{}})
	if err != nil {
		t.Fatal(err)
	}
	if plugin.ID != "sso" {
		t.Fatalf("plugin id = %q", plugin.ID)
	}
	model, exists := plugin.Schema[ModelSSOProvider]
	if !exists {
		t.Fatal("ssoProvider schema is missing")
	}
	for _, field := range []string{
		"id", "issuer", "oidcConfig", "samlConfig", "userId", "providerId",
		"organizationId", "domain", "domainVerified", "createdAt", "updatedAt",
	} {
		if _, exists = model.Fields[field]; !exists {
			t.Fatalf("schema field %q is missing", field)
		}
	}
	if model.Fields["oidcConfig"].Returned || model.Fields["samlConfig"].Returned {
		t.Fatal("secret provider configuration must not be returned")
	}
	if !model.Fields["providerId"].Unique {
		t.Fatal("provider id must be unique")
	}
}

func TestNewRejectsInvalidDefaultProviders(t *testing.T) {
	t.Parallel()
	base := Config{Cipher: testCipher(t)}
	cases := []struct {
		name     string
		provider ProviderRegistration
	}{
		{
			name: "reserved id",
			provider: ProviderRegistration{
				ProviderID: "credential", Domain: "example.com",
				OIDC: &OIDCConfig{
					Issuer: "https://idp.example.com", ClientID: "id", ClientSecret: "secret",
				},
			},
		},
		{
			name: "public suffix",
			provider: ProviderRegistration{
				ProviderID: "work", Domain: "com",
				OIDC: &OIDCConfig{
					Issuer: "https://idp.example.com", ClientID: "id", ClientSecret: "secret",
				},
			},
		},
		{
			name: "two protocols",
			provider: ProviderRegistration{
				ProviderID: "work", Domain: "example.com",
				OIDC: &OIDCConfig{
					Issuer: "https://idp.example.com", ClientID: "id", ClientSecret: "secret",
				},
				SAML: &SAMLConfig{
					Issuer: "issuer", EntryPoint: "https://idp.example.com/sso",
					Certificate: "certificate", SPEntityID: "sp",
				},
			},
		},
	}
	for _, test := range cases {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			config := base
			config.DefaultProviders = []ProviderRegistration{test.provider}
			if _, err := New(config); err == nil {
				t.Fatal("expected provider validation to fail")
			}
		})
	}
}

func TestNewRequiresAuthorizerForOrganizationProvider(t *testing.T) {
	t.Parallel()
	_, err := New(Config{
		Cipher: testCipher(t),
		DefaultProviders: []ProviderRegistration{{
			ProviderID: "work", Domain: "example.com", OrganizationID: "org",
			OIDC: &OIDCConfig{
				Issuer: "https://idp.example.com", ClientID: "id", ClientSecret: "secret",
			},
		}},
	})
	if err == nil {
		t.Fatal("expected missing organization authorizer to fail")
	}
}

func TestSharedRedirectMustBeTrustedAtInitialization(t *testing.T) {
	t.Parallel()
	plugin, err := New(Config{
		Cipher: testCipher(t), RedirectURI: "https://app.example.com/sso/callback",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = plugin.Init(betterauth.PluginInitContext{
		BaseURL: "https://auth.example.com/api/auth",
	})
	if err == nil {
		t.Fatal("expected untrusted redirect to fail")
	}
	_, err = plugin.Init(betterauth.PluginInitContext{
		BaseURL:        "https://auth.example.com/api/auth",
		TrustedOrigins: []string{"https://app.example.com"},
	})
	if err != nil {
		t.Fatalf("trusted redirect failed: %v", err)
	}
}

func TestPublicHTTPSURLPolicy(t *testing.T) {
	t.Parallel()
	for _, value := range []string{
		"http://idp.example.com", "https://localhost", "https://127.0.0.1",
		"https://10.0.0.1", "https://[::1]",
	} {
		target, err := url.Parse(value)
		if err != nil {
			t.Fatal(err)
		}
		if err = PublicHTTPSURLPolicy(context.Background(), target); err == nil {
			t.Fatalf("expected %q to be rejected", value)
		}
	}
	target, _ := url.Parse("https://idp.example.com")
	if err := PublicHTTPSURLPolicy(context.Background(), target); err != nil {
		t.Fatalf("public HTTPS URL failed: %v", err)
	}
}

func testCipher(t *testing.T) betterauth.TokenCipher {
	t.Helper()
	cipher, err := betterauth.NewAESGCMTokenCipher(
		[]byte("0123456789abcdef0123456789abcdef"),
	)
	if err != nil {
		t.Fatal(err)
	}
	return cipher
}

type stubDNS struct{}

func (stubDNS) LookupTXT(context.Context, string) ([]string, error) {
	return nil, errors.New("not implemented")
}
