package betterauth_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	betterauth "github.com/eadwinCode/better-auth-go"
	"github.com/eadwinCode/better-auth-go/plugin/twofactor"
)

const compatibilityPassword = "Correct-Horse-123!"

// TestBetterAuthV177PasswordTooLongCompatibility checks that an over-long
// password gets 400 PASSWORD_TOO_LONG before any lookup, as in Better Auth
// 1.7.6 (#11324).
func TestBetterAuthV177PasswordTooLongCompatibility(t *testing.T) {
	oracle := newTypeScriptOracle(t)
	tsClient := oracle.clone(t)
	goClient, _ := managementCompatibilityServer(t)
	email := uniqueCompatibilityEmail("too-long")
	signupCompatibilityUser(t, goClient, tsClient, email, "Too Long", compatibilityPassword)
	tooLong := strings.Repeat("a", 129)

	for _, test := range []struct {
		name        string
		path        string
		body        map[string]any
		csrf        bool
		wantCode    string
		wantMessage string
	}{
		{
			name: "sign-in", path: "/sign-in/email",
			body:     map[string]any{"email": email, "password": tooLong},
			wantCode: "PASSWORD_TOO_LONG", wantMessage: "Password too long",
		},
		{
			name: "change-password current password", path: "/change-password",
			body: map[string]any{
				"currentPassword": tooLong, "newPassword": "Updated-Horse-456!",
			},
			csrf:     true,
			wantCode: "PASSWORD_TOO_LONG", wantMessage: "Password too long",
		},
		{
			name: "change-password new password checked first", path: "/change-password",
			body:     map[string]any{"currentPassword": tooLong, "newPassword": "short"},
			csrf:     true,
			wantCode: "PASSWORD_TOO_SHORT", wantMessage: "Password too short",
		},
		{
			name: "delete-user", path: "/delete-user",
			body:     map[string]any{"password": tooLong},
			csrf:     true,
			wantCode: "PASSWORD_TOO_LONG", wantMessage: "Password too long",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			goResult := goResponse(goClient.request(t, http.MethodPost, test.path, test.body, test.csrf))
			tsResult := tsClient.request(t, http.MethodPost, test.path, test.body, "")
			assertCode(t, http.StatusBadRequest, test.wantCode, test.wantMessage, map[string]oracleResponse{
				"Go": goResult, "TypeScript": tsResult,
			})
		})
	}

	// The account is untouched: the real password still signs in.
	signIn := map[string]any{"email": email, "password": compatibilityPassword}
	assertBothStatus(t, "sign-in after rejected requests",
		goResponse(goClient.request(t, http.MethodPost, "/sign-in/email", signIn, false)),
		tsClient.request(t, http.MethodPost, "/sign-in/email", signIn, ""),
		http.StatusOK)
}

// twoFactorPair drives a Go server with the two-factor plugin and the
// matching TypeScript oracle instance, selected by base-path suffix.
type twoFactorPair struct {
	goClient *testClient
	ts       *typescriptOracle
}

func newTwoFactorPair(t *testing.T, oracle *typescriptOracle, suffix string, skipVerification bool) *twoFactorPair {
	t.Helper()
	cipher, err := betterauth.NewAESGCMTokenCipher([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	manager, err := twofactor.NewManager(twofactor.Config{
		Issuer: "Compatibility", Cipher: cipher, SkipVerificationOnEnable: skipVerification,
	})
	if err != nil {
		t.Fatal(err)
	}
	goClient, _ := newBlackBoxServerConfig(t, func(config *betterauth.Config) {
		config.Plugins = []betterauth.Plugin{manager.Plugin()}
	})
	ts := oracle.clone(t)
	ts.basePath += suffix
	pair := &twoFactorPair{goClient: goClient, ts: ts}
	email := uniqueCompatibilityEmail("two-factor" + suffix)
	signupCompatibilityUser(t, goClient, ts, email, "Two Factor", compatibilityPassword)
	return pair
}

func (pair *twoFactorPair) enable(t *testing.T, password string) (oracleResponse, oracleResponse) {
	t.Helper()
	body := map[string]any{"password": password}
	return goResponse(pair.goClient.request(t, http.MethodPost, "/two-factor/enable", body, true)),
		pair.ts.request(t, http.MethodPost, "/two-factor/enable", body, "")
}

func totpSecret(t *testing.T, implementation string, result oracleResponse) string {
	t.Helper()
	raw, _ := decodeObject(t, result.body)["totpURI"].(string)
	uri, err := url.Parse(raw)
	if err != nil || uri.Query().Get("secret") == "" {
		t.Fatalf("%s enable returned no TOTP URI: %s", implementation, result.body)
	}
	return uri.Query().Get("secret")
}

// TestBetterAuthV177TwoFactorReEnrollmentCompatibility checks that a verified
// TOTP factor cannot be replaced by enabling again, while a pending one can,
// as in Better Auth 1.7.3 (#11037).
func TestBetterAuthV177TwoFactorReEnrollmentCompatibility(t *testing.T) {
	oracle := newTypeScriptOracle(t)

	t.Run("pending enrollment is replaced", func(t *testing.T) {
		pair := newTwoFactorPair(t, oracle, "-2fa", false)
		goFirst, tsFirst := pair.enable(t, compatibilityPassword)
		assertBothStatus(t, "first enable", goFirst, tsFirst, http.StatusOK)
		goSecond, tsSecond := pair.enable(t, compatibilityPassword)
		assertBothStatus(t, "second enable", goSecond, tsSecond, http.StatusOK)
		for implementation, results := range map[string][2]oracleResponse{
			"Go": {goFirst, goSecond}, "TypeScript": {tsFirst, tsSecond},
		} {
			if totpSecret(t, implementation, results[0]) == totpSecret(t, implementation, results[1]) {
				t.Fatalf("%s did not replace the pending secret", implementation)
			}
		}
	})

	t.Run("verified enrollment is kept", func(t *testing.T) {
		pair := newTwoFactorPair(t, oracle, "-2fa-skip", true)
		goFirst, tsFirst := pair.enable(t, compatibilityPassword)
		assertBothStatus(t, "first enable", goFirst, tsFirst, http.StatusOK)
		goSecond, tsSecond := pair.enable(t, compatibilityPassword)
		assertCode(t, http.StatusBadRequest, "TOTP_ALREADY_ENABLED", "TOTP is already enabled",
			map[string]oracleResponse{"Go": goSecond, "TypeScript": tsSecond})
	})

	t.Run("over-long password", func(t *testing.T) {
		pair := newTwoFactorPair(t, oracle, "-2fa", false)
		goResult, tsResult := pair.enable(t, strings.Repeat("a", 129))
		assertCode(t, http.StatusBadRequest, "PASSWORD_TOO_LONG", "Password too long",
			map[string]oracleResponse{"Go": goResult, "TypeScript": tsResult})
	})
}
