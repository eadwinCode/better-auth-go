package betterauth_test

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	betterauth "github.com/eadwinCode/better-auth-go"
	"github.com/eadwinCode/better-auth-go/adapter/memory"
)

type discardMailer struct{}

func (discardMailer) Send(context.Context, betterauth.Mail) error { return nil }

type denyImpersonation struct{}

func (denyImpersonation) CanImpersonate(context.Context, betterauth.User, betterauth.User) error {
	return errors.New("denied")
}

type nonTransactionalAdapter struct{ *memory.Adapter }

func (nonTransactionalAdapter) Capabilities() betterauth.AdapterCapabilities {
	return betterauth.AdapterCapabilities{}
}

func validConfig() betterauth.Config {
	return betterauth.Config{
		PublicURL: "https://auth.example.com", TrustedOrigins: []string{"https://app.example.com"},
		Database: memory.New(), Mailer: discardMailer{}, ImpersonationAuthorizer: denyImpersonation{},
	}
}

func TestConfigFailsClosed(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*betterauth.Config)
	}{
		{"missing database", func(config *betterauth.Config) { config.Database = nil }},
		{"database without native transactions", func(config *betterauth.Config) {
			config.Database = nonTransactionalAdapter{Adapter: memory.New()}
		}},
		{"missing mailer", func(config *betterauth.Config) { config.Mailer = nil }},
		{"missing authorizer", func(config *betterauth.Config) { config.ImpersonationAuthorizer = nil }},
		{"public suffix wildcard", func(config *betterauth.Config) {
			config.TrustedOrigins = []string{"https://*.co.uk"}
		}},
		{"insecure origin", func(config *betterauth.Config) { config.TrustedOrigins = []string{"http://app.example.com"} }},
		{"same site none", func(config *betterauth.Config) { config.Cookie.SameSite = http.SameSiteNoneMode }},
		{"non-host cookie", func(config *betterauth.Config) { config.Cookie.Name = "session" }},
		{"delete verification without deletion", func(config *betterauth.Config) {
			config.User.SendDeleteAccountVerification = true
		}},
		{"delete verification TTL too short", func(config *betterauth.Config) {
			config.DeleteUserTTL = time.Minute - time.Nanosecond
		}},
		{"delete verification TTL too long", func(config *betterauth.Config) {
			config.DeleteUserTTL = 7*24*time.Hour + time.Nanosecond
		}},
		{"trusted provider is not configured", func(config *betterauth.Config) {
			config.Account.TrustedProviders = []string{"google"}
		}},
		{"admin roles without resolver", func(config *betterauth.Config) {
			config.Admin.AdminRoles = []string{"admin"}
		}},
		{"invalid default admin role", func(config *betterauth.Config) {
			config.Admin.DefaultRole = "Admin Role"
		}},
		{"invalid admin user ID", func(config *betterauth.Config) {
			config.Admin.AdminUserIDs = []string{""}
		}},
		{"static and dynamic trusted providers", func(config *betterauth.Config) {
			config.Account.TrustedProviders = []string{"test"}
			config.Account.TrustedProviderResolver = betterauth.TrustedProviderResolverFunc(
				func(context.Context, *http.Request) ([]string, error) { return []string{"test"}, nil },
			)
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			config := validConfig()
			test.mutate(&config)
			if _, err := betterauth.New(config); err == nil {
				t.Fatal("expected configuration error")
			}
		})
	}
}

func TestConfigAcceptsLoopbackDevelopment(t *testing.T) {
	t.Parallel()
	config := validConfig()
	config.PublicURL = "http://localhost:8080"
	config.TrustedOrigins = []string{"http://localhost:3000"}
	if _, err := betterauth.New(config); err != nil {
		t.Fatal(err)
	}
}
