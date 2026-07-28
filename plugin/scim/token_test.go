package scim

import (
	"strings"
	"testing"

	betterauth "github.com/eadwinCode/better-auth-go"
)

func TestBearerTokenRoundTripHashesOnlySecret(t *testing.T) {
	t.Parallel()
	secret := strings.Repeat("s", 32)
	raw, err := encodeBearerToken(secret, "directory", "org-1")
	if err != nil {
		t.Fatal(err)
	}
	claims, err := parseBearerToken(raw, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Secret != secret || claims.ProviderID != "directory" ||
		claims.OrganizationID != "org-1" {
		t.Fatalf("unexpected claims: %#v", claims)
	}
	if claims.TokenHash != betterauth.HashToken(secret) ||
		strings.Contains(claims.TokenHash, secret) {
		t.Fatal("bearer secret was not reduced to its fixed hash")
	}
	if !tokenHashMatches(claims.TokenHash, betterauth.HashToken(secret)) ||
		tokenHashMatches(claims.TokenHash, betterauth.HashToken("wrong")) {
		t.Fatal("constant-time token comparison failed")
	}
}

func TestBearerTokenParserFailsClosed(t *testing.T) {
	t.Parallel()
	values := []string{
		"", "not-base64", strings.Repeat("a", 3000),
	}
	encoded, err := encodeBearerToken(strings.Repeat("s", 32), "directory", "")
	if err != nil {
		t.Fatal(err)
	}
	values = append(values, encoded+"corrupt")
	for _, value := range values {
		if _, err = parseBearerToken(value, 2048); err == nil {
			t.Fatalf("accepted malformed bearer %q", value)
		}
	}
}

func FuzzParseBearerToken(f *testing.F) {
	valid, _ := encodeBearerToken(strings.Repeat("s", 32), "directory", "org")
	f.Add(valid)
	f.Add("not-base64")
	f.Fuzz(func(t *testing.T, value string) {
		claims, err := parseBearerToken(value, 2048)
		if err == nil {
			if claims.ProviderID == "" || claims.Secret == "" ||
				claims.TokenHash != betterauth.HashToken(claims.Secret) {
				t.Fatalf("invalid successful parse: %#v", claims)
			}
		}
	})
}
