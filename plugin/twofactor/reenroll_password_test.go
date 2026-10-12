package twofactor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	betterauth "github.com/eadwinCode/better-auth-go"
)

const ownerPassword = "correct horse battery staple"

func enableTOTP(t *testing.T, browser *testBrowser) *httptest.ResponseRecorder {
	t.Helper()
	return browser.request(t, http.MethodPost, "/two-factor/enable", map[string]any{
		"password": ownerPassword,
	}, true)
}

func totpSecretFrom(t *testing.T, response *httptest.ResponseRecorder) string {
	t.Helper()
	if response.Code != http.StatusOK {
		t.Fatalf("enable: %d %s", response.Code, response.Body.String())
	}
	uri, err := url.Parse(decodeBody(t, response)["totpURI"].(string))
	if err != nil {
		t.Fatal(err)
	}
	return uri.Query().Get("secret")
}

func assertTOTPAlreadyEnabled(t *testing.T, response *httptest.ResponseRecorder) {
	t.Helper()
	if response.Code != http.StatusBadRequest {
		t.Fatalf("re-enroll status %d: %s", response.Code, response.Body.String())
	}
	body := decodeBody(t, response)
	if body["code"] != "TOTP_ALREADY_ENABLED" || body["message"] != "TOTP is already enabled" {
		t.Fatalf("re-enroll error: %#v", body)
	}
}

func storedTwoFactor(t *testing.T, database betterauth.DatabaseAdapter) betterauth.Record {
	t.Helper()
	rows, err := database.FindMany(context.Background(), betterauth.FindManyQuery{
		Model: ModelTwoFactor,
	})
	if err != nil || len(rows) != 1 {
		t.Fatalf("two-factor rows: %#v %v", rows, err)
	}
	return rows[0]
}

func TestTOTPReEnrollmentIsRejectedWhileVerified(t *testing.T) {
	handler, database, clock, _, _ := newTwoFactorTestServer(t, nil)
	browser := newTestBrowser(handler)
	signUp(t, browser)
	secret, backupCodes := enrollTOTP(t, browser, clock)
	before := storedTwoFactor(t, database)

	assertTOTPAlreadyEnabled(t, enableTOTP(t, browser))
	after := storedTwoFactor(t, database)
	if after["id"] != before["id"] || after["secret"] != before["secret"] ||
		after["backupCodes"] != before["backupCodes"] || after["verified"] != true {
		t.Fatalf("rejected re-enroll changed the stored factor: before=%#v after=%#v", before, after)
	}

	// The old authenticator and backup codes still work.
	signOut(t, browser)
	signInChallenge(t, browser)
	code, err := totpCode(secret, clock.Now(), 30*time.Second, 6)
	if err != nil {
		t.Fatal(err)
	}
	verified := browser.request(t, http.MethodPost, "/two-factor/verify-totp", map[string]any{
		"code": code,
	}, false)
	if verified.Code != http.StatusOK {
		t.Fatalf("old TOTP secret: %d %s", verified.Code, verified.Body.String())
	}
	signOut(t, browser)
	signInChallenge(t, browser)
	backup := browser.request(t, http.MethodPost, "/two-factor/verify-backup-code", map[string]any{
		"code": backupCodes[0],
	}, false)
	if backup.Code != http.StatusOK {
		t.Fatalf("old backup code: %d %s", backup.Code, backup.Body.String())
	}
}

func TestTOTPReEnrollmentReplacesUnverifiedEnrollment(t *testing.T) {
	handler, database, _, _, _ := newTwoFactorTestServer(t, nil)
	browser := newTestBrowser(handler)
	signUp(t, browser)
	first := totpSecretFrom(t, enableTOTP(t, browser))
	firstRow := storedTwoFactor(t, database)
	second := totpSecretFrom(t, enableTOTP(t, browser))
	secondRow := storedTwoFactor(t, database)
	if first == second || firstRow["secret"] == secondRow["secret"] {
		t.Fatal("pending enrollment was not replaced")
	}
	if secondRow["verified"] != false {
		t.Fatalf("replacement enrollment is verified: %#v", secondRow)
	}
}

func TestTOTPReEnrollmentIsRejectedAfterSkippedVerification(t *testing.T) {
	handler, database, _, _, _ := newTwoFactorTestServer(t, func(config *Config) {
		config.SkipVerificationOnEnable = true
	})
	browser := newTestBrowser(handler)
	signUp(t, browser)
	totpSecretFrom(t, enableTOTP(t, browser))
	before := storedTwoFactor(t, database)
	if before["verified"] != true {
		t.Fatalf("skip-verification enrollment is not verified: %#v", before)
	}
	assertTOTPAlreadyEnabled(t, enableTOTP(t, browser))
	if after := storedTwoFactor(t, database); after["secret"] != before["secret"] {
		t.Fatal("rejected re-enroll replaced the secret")
	}
}

func TestTOTPReEnrollmentAfterOTPEnableIsAllowed(t *testing.T) {
	handler, _, _, _, _ := newTwoFactorTestServer(t, nil)
	browser := newTestBrowser(handler)
	signUp(t, browser)
	otp := browser.request(t, http.MethodPost, "/two-factor/enable", map[string]any{
		"password": ownerPassword, "method": "otp",
	}, true)
	if otp.Code != http.StatusOK {
		t.Fatalf("enable OTP: %d %s", otp.Code, otp.Body.String())
	}
	// OTP keeps no TOTP row, so TOTP enrollment is still open, like upstream.
	totpSecretFrom(t, enableTOTP(t, browser))
	// Enabling OTP again is never blocked by this rule.
	again := browser.request(t, http.MethodPost, "/two-factor/enable", map[string]any{
		"password": ownerPassword, "method": "otp",
	}, true)
	if again.Code != http.StatusOK {
		t.Fatalf("enable OTP again: %d %s", again.Code, again.Body.String())
	}
}

// countingVerifier counts every Hash and Verify call.
type countingVerifier struct {
	mu       sync.Mutex
	delegate betterauth.PasswordVerifier
	hashes   int
	verifies int
}

func (verifier *countingVerifier) Hash(ctx context.Context, password string) (string, error) {
	verifier.mu.Lock()
	verifier.hashes++
	verifier.mu.Unlock()
	return verifier.delegate.Hash(ctx, password)
}

func (verifier *countingVerifier) Verify(
	ctx context.Context,
	hash string,
	password string,
) (betterauth.PasswordVerification, error) {
	verifier.mu.Lock()
	verifier.verifies++
	verifier.mu.Unlock()
	return verifier.delegate.Verify(ctx, hash, password)
}

func (verifier *countingVerifier) calls() (int, int) {
	verifier.mu.Lock()
	defer verifier.mu.Unlock()
	return verifier.hashes, verifier.verifies
}

func TestTwoFactorRejectsOverLongPasswordsBeforeHashing(t *testing.T) {
	tooLong := strings.Repeat("p", 129)
	for _, allowPasswordless := range []bool{false, true} {
		for _, path := range []string{
			"/two-factor/enable",
			"/two-factor/disable",
			"/two-factor/get-totp-uri",
			"/two-factor/generate-backup-codes",
		} {
			name := path
			if allowPasswordless {
				name += " allow passwordless"
			}
			t.Run(name, func(t *testing.T) {
				verifier := &countingVerifier{}
				handler, _, _, _, _ := newTwoFactorTestServerWith(t, func(config *Config) {
					config.AllowPasswordless = allowPasswordless
				}, func(config *betterauth.Config) {
					delegate, err := betterauth.NewArgon2idVerifier(betterauth.Argon2Params{
						Memory: 19 * 1024, Iterations: 2, Parallelism: 1, SaltLength: 16, KeyLength: 32,
					}, 128)
					if err != nil {
						t.Fatal(err)
					}
					verifier.delegate = delegate
					config.Passwords = verifier
				})
				browser := newTestBrowser(handler)
				signUp(t, browser)
				hashesBefore, verifiesBefore := verifier.calls()
				response := browser.request(t, http.MethodPost, path, map[string]any{
					"password": tooLong,
				}, true)
				if response.Code != http.StatusBadRequest {
					t.Fatalf("status %d: %s", response.Code, response.Body.String())
				}
				body := decodeBody(t, response)
				if body["code"] != "PASSWORD_TOO_LONG" || body["message"] != "Password too long" {
					t.Fatalf("error: %#v", body)
				}
				if hashes, verifies := verifier.calls(); hashes != hashesBefore || verifies != verifiesBefore {
					t.Fatalf("password work ran: hashes %d->%d verifies %d->%d",
						hashesBefore, hashes, verifiesBefore, verifies)
				}
			})
		}
	}
}

func TestHookContextPasswordLengthDefault(t *testing.T) {
	context := &betterauth.HookContext{}
	if err := context.CheckPasswordNotTooLong(strings.Repeat("p", 128)); err != nil {
		t.Fatalf("128 bytes rejected: %v", err)
	}
	if err := context.CheckPasswordNotTooLong(strings.Repeat("p", 129)); err == nil {
		t.Fatal("129 bytes accepted with the default limit")
	}
	context.MaxPasswordBytes = 200
	if err := context.CheckPasswordNotTooLong(strings.Repeat("p", 129)); err != nil {
		t.Fatalf("129 bytes rejected with a 200-byte limit: %v", err)
	}
}
