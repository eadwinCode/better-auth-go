package betterauth_test

import (
	"errors"
	"strings"
	"testing"

	betterauth "github.com/eadwinCode/better-auth-go"
)

func TestCreatePlaceholderEmail(t *testing.T) {
	t.Parallel()
	options := betterauth.PlaceholderEmailOptions{
		Identifier: "account-id",
		Namespace:  "provider",
	}
	first, err := betterauth.CreatePlaceholderEmail(options)
	if err != nil {
		t.Fatal(err)
	}
	second, err := betterauth.CreatePlaceholderEmail(options)
	if err != nil {
		t.Fatal(err)
	}
	if first != "account-id@provider.placeholder.invalid" || second != first {
		t.Fatalf("placeholder email is not stable: first=%q second=%q", first, second)
	}

	other, err := betterauth.CreatePlaceholderEmail(betterauth.PlaceholderEmailOptions{
		Identifier: options.Identifier,
		Namespace:  "other-provider",
	})
	if err != nil {
		t.Fatal(err)
	}
	if other == first {
		t.Fatalf("namespaces collided: %q", other)
	}
}

func TestCreatePlaceholderEmailRejectsInvalidAddress(t *testing.T) {
	t.Parallel()
	tests := []betterauth.PlaceholderEmailOptions{
		{},
		{Identifier: "account-id"},
		{Identifier: "account id", Namespace: "provider"},
		{Identifier: ".account", Namespace: "provider"},
		{Identifier: "account..id", Namespace: "provider"},
		{Identifier: strings.Repeat("a", 65), Namespace: "provider"},
		{Identifier: "account-id", Namespace: "-provider"},
		{Identifier: "account-id", Namespace: "provider_1"},
		{Identifier: "account-id", Namespace: strings.Repeat("a", 64)},
	}
	for _, options := range tests {
		options := options
		t.Run(options.Identifier+"@"+options.Namespace, func(t *testing.T) {
			if value, err := betterauth.CreatePlaceholderEmail(options); value != "" || !errors.Is(err, betterauth.ErrInvalidPlaceholderEmail) {
				t.Fatalf("CreatePlaceholderEmail(%#v) = %q, %v", options, value, err)
			}
		})
	}
}
