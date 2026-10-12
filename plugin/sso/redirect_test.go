package sso

import (
	"testing"

	betterauth "github.com/eadwinCode/better-auth-go"
)

// The cases follow Better Auth v1.7.7's relative callback URL rules
// (#10979, #10041, #10983).
func TestRelativeRedirectURLsFollowBetterAuth(t *testing.T) {
	for value, want := range map[string]bool{
		"/dashboard":         true,
		"/dashboard?tab=1":   true,
		"/dashboard#section": true,
		"/dashboard?x=1#s":   true,
		"/~user":             true,
		"/a b":               true,
		"/é":                 true,
		"/dash%20board":      true,
		"/a/../dashboard":    true,
		"/.//evil.com":       true,
		"/next?u=%2F%2Fevil": true,
		"//evil.com":         false,
		"/\\evil.com":        false,
		"/%2F%2Fevil.com":    false,
		"/%2f%2fevil.com":    false,
		"/%5Cevil.com":       false,
		"/\tevil":            false,
		"/evil\u0085":        false,
		"dashboard":          false,
		"":                   false,
		"https:evil.com":     false,
	} {
		if got := isSafeRelativeURL(value); got != want {
			t.Errorf("isSafeRelativeURL(%q)=%v want %v", value, got, want)
		}
	}
}

func TestRelativeReturnToResolvesAgainstSiteOrigin(t *testing.T) {
	ctx := &betterauth.HookContext{BaseURL: "https://auth.example.com/api/auth"}
	got, err := safeReturnTo(ctx, "/dashboard?tab=1#top")
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://auth.example.com/dashboard?tab=1#top" {
		t.Fatalf("returnTo=%q", got)
	}
	if _, err := safeReturnTo(ctx, "/\\evil.com"); err == nil {
		t.Fatal("backslash return path accepted")
	}
}
