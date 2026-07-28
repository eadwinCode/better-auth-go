package scim

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	betterauth "github.com/eadwinCode/better-auth-go"
	"github.com/eadwinCode/better-auth-go/adapter/memory"
)

func TestMetadataEndpointsUseSCIMMediaTypeAndLocations(t *testing.T) {
	t.Parallel()
	plugin, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	server, err := betterauth.New(betterauth.Config{
		PublicURL:      "https://auth.example.com",
		TrustedOrigins: []string{"https://app.example.com"},
		Database:       memory.New(), Mailer: discardMailer{},
		ImpersonationAuthorizer: denyImpersonation{},
		Plugins:                 []betterauth.Plugin{plugin},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		"/scim/v2/ServiceProviderConfig",
		"/scim/v2/Schemas",
		"/scim/v2/Schemas/" + SchemaUser,
		"/scim/v2/ResourceTypes",
		"/scim/v2/ResourceTypes/User",
	} {
		request := httptest.NewRequest(
			http.MethodGet, "https://auth.example.com/api/auth"+path, nil,
		)
		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, request)
		if recorder.Code != http.StatusOK {
			t.Fatalf("%s status = %d: %s", path, recorder.Code, recorder.Body.String())
		}
		if recorder.Header().Get("Content-Type") !=
			"application/scim+json; charset=utf-8" {
			t.Fatalf("%s content type = %q", path, recorder.Header().Get("Content-Type"))
		}
	}
}

type discardMailer struct{}

func (discardMailer) Send(context.Context, betterauth.Mail) error { return nil }

type denyImpersonation struct{}

func (denyImpersonation) CanImpersonate(
	context.Context, betterauth.User, betterauth.User,
) error {
	return betterauth.NewError(
		betterauth.CodeForbidden, "Forbidden.", http.StatusForbidden, nil,
	)
}
