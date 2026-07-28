package passkey

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	betterauth "github.com/eadwinCode/better-auth-go"
	"github.com/eadwinCode/better-auth-go/adapter/memory"
)

const (
	testOrigin = "https://example.org"
	testCookie = "__Host-better_auth_passkey"
)

type fixedClock struct{ now time.Time }

func (clock fixedClock) Now() time.Time { return clock.now }

type sequenceTokens struct {
	mu      sync.Mutex
	counter uint64
}

func (source *sequenceTokens) Token(byteLength int) (string, error) {
	source.mu.Lock()
	defer source.mu.Unlock()
	source.counter++
	return fmt.Sprintf("passkey-token-%03d-%0*d", source.counter, byteLength, source.counter), nil
}

type discardMailer struct{}

func (discardMailer) Send(context.Context, betterauth.Mail) error { return nil }

type denyImpersonation struct{}

func (denyImpersonation) CanImpersonate(context.Context, betterauth.User, betterauth.User) error {
	return errors.New("denied")
}

type browserClient struct {
	handler http.Handler
	cookies map[string]*http.Cookie
	csrf    string
}

func (client *browserClient) request(
	t *testing.T,
	method string,
	path string,
	origin string,
	body []byte,
) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, "https://auth.example.org/api/auth"+path, bytes.NewReader(body))
	if origin != "" {
		request.Header.Set("Origin", origin)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if client.csrf != "" {
		request.Header.Set("X-CSRF-Token", client.csrf)
	}
	for _, cookie := range client.cookies {
		request.AddCookie(cookie)
	}
	response := httptest.NewRecorder()
	client.handler.ServeHTTP(response, request)
	for _, cookie := range response.Result().Cookies() {
		if cookie.MaxAge < 0 {
			delete(client.cookies, cookie.Name)
		} else {
			client.cookies[cookie.Name] = cookie
		}
	}
	if csrf := response.Header().Get("X-CSRF-Token"); csrf != "" {
		client.csrf = csrf
	}
	return response
}

func newPasskeyServerConfig(
	t *testing.T,
	passkeyConfig Config,
) (*browserClient, *memory.Adapter) {
	t.Helper()
	plugin, err := New(passkeyConfig)
	if err != nil {
		t.Fatal(err)
	}
	passwords, err := betterauth.NewArgon2idVerifier(betterauth.Argon2Params{
		Memory: 19 * 1024, Iterations: 2, Parallelism: 1, SaltLength: 16, KeyLength: 32,
	}, 1024)
	if err != nil {
		t.Fatal(err)
	}
	database := memory.New()
	server, err := betterauth.New(betterauth.Config{
		PublicURL: "https://auth.example.org", TrustedOrigins: []string{testOrigin},
		Database: database, Mailer: discardMailer{}, ImpersonationAuthorizer: denyImpersonation{},
		Clock:  fixedClock{now: time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)},
		Tokens: &sequenceTokens{}, Passwords: passwords, Plugins: []betterauth.Plugin{plugin},
	})
	if err != nil {
		t.Fatal(err)
	}
	return &browserClient{handler: server.Handler(), cookies: map[string]*http.Cookie{}}, database
}

func signUp(t *testing.T, client *browserClient, email string) string {
	t.Helper()
	response := client.request(
		t, http.MethodPost, "/sign-up/email", testOrigin,
		[]byte(fmt.Sprintf(
			`{"email":%q,"password":"correct horse battery","name":"Ada"}`, email,
		)),
	)
	if response.Code != http.StatusOK {
		t.Fatalf("signup failed: %d %s", response.Code, response.Body.String())
	}
	var result struct {
		User struct {
			ID string `json:"id"`
		} `json:"user"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.User.ID == "" || client.cookies["__Host-better_auth_session"] == nil ||
		client.cookies["__Host-better_auth_csrf"] == nil || client.csrf == "" {
		t.Fatal("signup did not establish session and CSRF cookies")
	}
	return result.User.ID
}

func TestPasskeyW3CRegistrationAndAuthenticationFlow(t *testing.T) {
	var registrationCallbacks atomic.Int64
	var authenticationCallbacks atomic.Int64
	client, database := newPasskeyServerConfig(t, Config{
		RPID: "example.org", RPDisplayName: "Example",
		Origins: []string{testOrigin}, UserVerification: VerificationPreferred,
		Registration: RegistrationConfig{
			AfterVerification: func(
				_ *betterauth.HookContext,
				verification RegistrationVerification,
			) (RegistrationResolution, error) {
				if verification.CredentialID == "" || verification.User.ID == "" ||
					verification.ClientData["type"] != "public-key" {
					t.Fatalf("incomplete registration callback: %#v", verification)
				}
				registrationCallbacks.Add(1)
				return RegistrationResolution{Name: "callback default"}, nil
			},
		},
		Authentication: AuthenticationConfig{
			AfterVerification: func(
				_ *betterauth.HookContext,
				verification AuthenticationVerification,
			) error {
				if verification.UserID == "" || verification.CredentialID == "" ||
					verification.ClientData["type"] != "public-key" {
					t.Fatalf("incomplete authentication callback: %#v", verification)
				}
				authenticationCallbacks.Add(1)
				return nil
			},
		},
	})
	userID := signUp(t, client, "ada@example.org")
	originalSession := client.cookies["__Host-better_auth_session"].Value

	generated := client.request(
		t, http.MethodGet,
		"/passkey/generate-register-options?authenticatorAttachment=platform",
		"", nil,
	)
	if generated.Code != http.StatusOK {
		t.Fatalf("generate registration failed: %d %s", generated.Code, generated.Body.String())
	}
	var options map[string]any
	if err := json.Unmarshal(generated.Body.Bytes(), &options); err != nil {
		t.Fatal(err)
	}
	selection, _ := options["authenticatorSelection"].(map[string]any)
	if selection["userVerification"] != "preferred" ||
		selection["authenticatorAttachment"] != "platform" {
		t.Fatalf("unexpected registration policy: %#v", selection)
	}
	challengeCookie := client.cookies[testCookie]
	if challengeCookie == nil || !challengeCookie.Secure || !challengeCookie.HttpOnly ||
		challengeCookie.Path != "/" || challengeCookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("insecure challenge cookie: %#v", challengeCookie)
	}
	challengeRow := challengeRowForCookie(t, database, challengeCookie.Value)
	if challengeRow["value"] == challengeCookie.Value ||
		challengeRow["value"] != betterauth.HashToken(challengeCookie.Value) {
		t.Fatal("challenge handle was not hash-at-rest")
	}

	wrongCeremony := client.request(
		t, http.MethodPost, "/passkey/verify-authentication", testOrigin,
		[]byte(`{"response":{}}`),
	)
	if wrongCeremony.Code != http.StatusBadRequest ||
		!strings.Contains(wrongCeremony.Body.String(), "Challenge not found") {
		t.Fatalf("cross-ceremony challenge was accepted: %d %s",
			wrongCeremony.Code, wrongCeremony.Body.String())
	}

	registrationResponse, registrationChallenge, fixtureCredentialID := registrationFixture(t)
	setStoredChallenge(t, database, challengeRow, registrationChallenge)
	csrf := client.csrf
	client.csrf = ""
	missingCSRF := client.request(
		t, http.MethodPost, "/passkey/verify-registration", testOrigin,
		wrapResponse(t, registrationResponse, "Laptop"),
	)
	client.csrf = csrf
	if missingCSRF.Code != http.StatusForbidden {
		t.Fatalf("registration without CSRF reached verifier: %d %s",
			missingCSRF.Code, missingCSRF.Body.String())
	}
	evil := client.request(
		t, http.MethodPost, "/passkey/verify-registration", "https://evil.example",
		wrapResponse(t, registrationResponse, "Laptop"),
	)
	if evil.Code != http.StatusForbidden {
		t.Fatalf("untrusted origin reached verifier: %d %s", evil.Code, evil.Body.String())
	}
	registered := client.request(
		t, http.MethodPost, "/passkey/verify-registration", testOrigin,
		wrapResponse(t, registrationResponse, "Laptop"),
	)
	if registered.Code != http.StatusOK {
		t.Fatalf("registration verification failed: %d %s", registered.Code, registered.Body.String())
	}
	var passkey Passkey
	if err := json.Unmarshal(registered.Body.Bytes(), &passkey); err != nil {
		t.Fatal(err)
	}
	if passkey.UserID != userID || passkey.Name != "Laptop" {
		t.Fatalf("unexpected passkey response: %#v", passkey)
	}
	if passkey.CredentialID != base64.RawURLEncoding.EncodeToString(fixtureCredentialID) {
		t.Fatalf("unexpected credential ID: %s", passkey.CredentialID)
	}
	replay := client.request(
		t, http.MethodPost, "/passkey/verify-registration", testOrigin,
		wrapResponse(t, registrationResponse, "Laptop"),
	)
	if replay.Code != http.StatusBadRequest ||
		!strings.Contains(replay.Body.String(), "Challenge not found") {
		t.Fatalf("registration challenge replay succeeded: %d %s", replay.Code, replay.Body.String())
	}

	listed := client.request(t, http.MethodGet, "/passkey/list-user-passkeys", "", nil)
	if listed.Code != http.StatusOK || strings.Contains(listed.Body.String(), "credentialData") ||
		strings.Contains(listed.Body.String(), "userHandle") {
		t.Fatalf("passkey listing leaked internal verifier data: %d %s",
			listed.Code, listed.Body.String())
	}
	other := &browserClient{handler: client.handler, cookies: map[string]*http.Cookie{}}
	_ = signUp(t, other, "grace@example.org")
	crossUser := other.request(
		t, http.MethodPost, "/passkey/update-passkey", testOrigin,
		[]byte(fmt.Sprintf(`{"id":%q,"name":"Stolen"}`, passkey.ID)),
	)
	if crossUser.Code != http.StatusNotFound {
		t.Fatalf("cross-user passkey update was not hidden: %d %s",
			crossUser.Code, crossUser.Body.String())
	}

	authOptions := client.request(
		t, http.MethodGet, "/passkey/generate-authenticate-options", "", nil,
	)
	if authOptions.Code != http.StatusOK {
		t.Fatalf("generate authentication failed: %d %s", authOptions.Code, authOptions.Body.String())
	}
	authCookie := client.cookies[testCookie]
	authRow := challengeRowForCookie(t, database, authCookie.Value)
	assertion, authenticationChallenge := authenticationFixture(t)
	setStoredChallenge(t, database, authRow, authenticationChallenge)
	authenticated := client.request(
		t, http.MethodPost, "/passkey/verify-authentication", testOrigin,
		wrapResponse(t, assertion, ""),
	)
	if authenticated.Code != http.StatusOK {
		t.Fatalf("authentication verification failed: %d %s",
			authenticated.Code, authenticated.Body.String())
	}
	replacement := client.cookies["__Host-better_auth_session"]
	if replacement == nil || replacement.Value == originalSession ||
		replacement.Value == "" || client.csrf == "" {
		t.Fatal("passkey authentication did not rotate session and CSRF credentials")
	}
	oldRequest := httptest.NewRequest(
		http.MethodGet, "https://auth.example.org/api/auth/get-session", nil,
	)
	oldRequest.AddCookie(&http.Cookie{
		Name: "__Host-better_auth_session", Value: originalSession,
	})
	oldSession := httptest.NewRecorder()
	client.handler.ServeHTTP(oldSession, oldRequest)
	if oldSession.Code != http.StatusOK ||
		strings.TrimSpace(oldSession.Body.String()) != "null" {
		t.Fatalf("old session survived passkey rotation: %d %s",
			oldSession.Code, oldSession.Body.String())
	}

	updated := client.request(
		t, http.MethodPost, "/passkey/update-passkey", testOrigin,
		[]byte(fmt.Sprintf(`{"id":%q,"name":"Security key"}`, passkey.ID)),
	)
	if updated.Code != http.StatusOK || !strings.Contains(updated.Body.String(), "Security key") {
		t.Fatalf("passkey update failed: %d %s", updated.Code, updated.Body.String())
	}
	deleted := client.request(
		t, http.MethodPost, "/passkey/delete-passkey", testOrigin,
		[]byte(fmt.Sprintf(`{"id":%q}`, passkey.ID)),
	)
	if deleted.Code != http.StatusOK || !strings.Contains(deleted.Body.String(), `"status":true`) {
		t.Fatalf("passkey delete failed: %d %s", deleted.Code, deleted.Body.String())
	}
	if registrationCallbacks.Load() != 1 || authenticationCallbacks.Load() != 1 {
		t.Fatalf("unexpected callback counts: registration=%d authentication=%d",
			registrationCallbacks.Load(), authenticationCallbacks.Load())
	}
}

func TestPasskeyConfigurationFailsClosed(t *testing.T) {
	t.Parallel()
	tests := []Config{
		{},
		{RPID: "com", RPDisplayName: "Example", Origins: []string{"https://example.com"}},
		{RPID: "example.com", RPDisplayName: "Example", Origins: []string{"https://evil.test"}},
		{RPID: "example.com", RPDisplayName: "Example", Origins: []string{"http://example.com"}},
		{RPID: "example.com", RPDisplayName: "Example", Origins: []string{"https://*.example.com"}},
		{
			RPID: "example.com", RPDisplayName: "Example",
			Origins: []string{"https://example.com"}, UserVerification: "discouraged",
		},
		{
			RPID: "example.com", RPDisplayName: "Example",
			Origins:      []string{"https://example.com"},
			Registration: RegistrationConfig{AllowWithoutSession: true},
		},
	}
	for index, config := range tests {
		if _, err := New(config); err == nil {
			t.Fatalf("invalid configuration %d was accepted: %#v", index, config)
		}
	}
	normalized, webAuthn, err := normalizeConfig(Config{
		RPID: "example.com", RPDisplayName: "Example",
		Origins: []string{"https://app.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if normalized.UserVerification != VerificationRequired ||
		webAuthn.Config.AuthenticatorSelection.UserVerification != "required" ||
		webAuthn.Config.RPAllowCrossOrigin {
		t.Fatalf("secure defaults were not applied: %#v", normalized)
	}
	customFields := map[string]betterauth.FieldSchema{
		"credentialID": {FieldName: "credential_id"},
	}
	plugin, err := New(Config{
		RPID: "example.com", RPDisplayName: "Example",
		Origins: []string{"https://app.example.com"},
		Schema: betterauth.ModelSchema{
			ModelName: "auth_passkeys", Fields: customFields,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	customFields["credentialID"] = betterauth.FieldSchema{FieldName: "mutated"}
	model := plugin.Schema[ModelPasskey]
	if model.ModelName != "auth_passkeys" ||
		model.Fields["credentialID"].FieldName != "credential_id" {
		t.Fatalf("passkey schema mapping was not copied: %#v", model)
	}
}

func TestPasskeySessionlessRegistrationResolverAndExtensions(t *testing.T) {
	t.Parallel()
	var resolved atomic.Int64
	client, _ := newPasskeyServerConfig(t, Config{
		RPID: "example.org", RPDisplayName: "Example", Origins: []string{testOrigin},
		Registration: RegistrationConfig{
			AllowWithoutSession: true,
			ResolveUser: func(
				_ *betterauth.HookContext,
				registrationContext string,
			) (RegistrationUser, error) {
				if registrationContext != "invite-1" {
					t.Fatalf("unexpected registration context %q", registrationContext)
				}
				resolved.Add(1)
				return RegistrationUser{
					ID: "pending-user", Name: "pending@example.org",
					DisplayName: "Pending User",
				}, nil
			},
			Extensions: func(*betterauth.HookContext) (map[string]any, error) {
				return map[string]any{"credProps": true}, nil
			},
		},
	})
	response := client.request(
		t, http.MethodGet,
		"/passkey/generate-register-options?context=invite-1", "", nil,
	)
	if response.Code != http.StatusOK {
		t.Fatalf("sessionless registration options failed: %d %s",
			response.Code, response.Body.String())
	}
	var options map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &options); err != nil {
		t.Fatal(err)
	}
	extensions, _ := options["extensions"].(map[string]any)
	if extensions["credProps"] != true || resolved.Load() != 1 ||
		client.cookies["__Host-better_auth_session"] != nil {
		t.Fatalf("sessionless resolver/extensions contract failed: %#v", options)
	}
}

func TestPasskeyCounterGuardHasOneNonzeroWinner(t *testing.T) {
	t.Parallel()
	database := memory.New()
	credential := webauthn.Credential{
		ID: []byte("credential"), PublicKey: []byte("public-key"),
		Flags: webauthn.NewCredentialFlags(
			protocol.FlagUserPresent | protocol.FlagUserVerified,
		),
		Authenticator: webauthn.Authenticator{SignCount: 2},
	}
	data, err := credentialRecord(&credential)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Create(context.Background(), betterauth.CreateQuery{
		Model: ModelPasskey,
		Data: betterauth.Record{
			"id": "passkey-id", "userId": "user-id",
			"credentialID": encodeCredentialID(credential.ID),
			"counter":      float64(1), "backedUp": false,
			"credentialData": data, "updatedAt": time.Now().UTC(),
		},
		ForceAllowID: true,
	}); err != nil {
		t.Fatal(err)
	}
	instance := &runtime{}
	hookContext := &betterauth.HookContext{
		Context: context.Background(), Database: database,
		Clock: fixedClock{now: time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)},
	}
	var successes atomic.Int64
	var replays atomic.Int64
	var wait sync.WaitGroup
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			copyCredential := credential
			err := instance.persistAuthentication(
				hookContext, "user-id", 1, &copyCredential,
			)
			switch {
			case err == nil:
				successes.Add(1)
			case errors.Is(err, betterauth.ErrReplay):
				replays.Add(1)
			default:
				t.Errorf("unexpected guarded update error: %v", err)
			}
		}()
	}
	wait.Wait()
	if successes.Load() != 1 || replays.Load() != 1 {
		t.Fatalf("guarded counter update winners=%d replays=%d",
			successes.Load(), replays.Load())
	}
}

func FuzzChallengeHandle(f *testing.F) {
	f.Add("__Host-better_auth_passkey=value")
	f.Add("__Host-better_auth_passkey=")
	f.Add("other=value")
	f.Fuzz(func(t *testing.T, raw string) {
		request := httptest.NewRequest(http.MethodGet, "https://auth.example.org/", nil)
		request.Header.Set("Cookie", raw)
		handle, err := challengeHandle(request, testCookie)
		if err == nil && (handle == "" || len(handle) > 512) {
			t.Fatalf("accepted invalid challenge handle of length %d", len(handle))
		}
	})
}

func challengeRowForCookie(
	t *testing.T,
	database *memory.Adapter,
	handle string,
) betterauth.Record {
	t.Helper()
	row, err := database.FindOne(context.Background(), betterauth.FindOneQuery{
		Model: betterauth.ModelVerification,
		Where: []betterauth.Where{betterauth.Eq("value", betterauth.HashToken(handle))},
	})
	if err != nil || row == nil {
		t.Fatalf("challenge row not found: %v", err)
	}
	return row
}

func setStoredChallenge(
	t *testing.T,
	database *memory.Adapter,
	row betterauth.Record,
	challenge string,
) {
	t.Helper()
	metadata, ok := row["metadata"].(map[string]any)
	if !ok {
		t.Fatalf("unexpected metadata: %#v", row["metadata"])
	}
	session, ok := metadata["session"].(map[string]any)
	if !ok {
		t.Fatalf("unexpected session metadata: %#v", metadata["session"])
	}
	session["challenge"] = challenge
	id, _ := row["id"].(string)
	if _, err := database.Update(context.Background(), betterauth.UpdateQuery{
		Model:  betterauth.ModelVerification,
		Where:  []betterauth.Where{betterauth.Eq("id", id)},
		Update: betterauth.Record{"metadata": metadata},
	}); err != nil {
		t.Fatal(err)
	}
}

func wrapResponse(t *testing.T, response []byte, name string) []byte {
	t.Helper()
	var value any
	if err := json.Unmarshal(response, &value); err != nil {
		t.Fatal(err)
	}
	body := map[string]any{"response": value}
	if name != "" {
		body["name"] = name
	}
	result, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func registrationFixture(t *testing.T) ([]byte, string, []byte) {
	t.Helper()
	const (
		attestationObjectHex = "a363666d74646e6f6e656761747453746d74a068617574684461746158a4bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b559000000008446ccb9ab1db374750b2367ff6f3a1f0020f91f391db4c9b2fde0ea70189cba3fb63f579ba6122b33ad94ff3ec330084be4a5010203262001215820afefa16f97ca9b2d23eb86ccb64098d20db90856062eb249c33a9b672f26df61225820930a56b87a2fca66334b03458abf879717c12cc68ed73290af2e2664796b9220"
		clientDataJSONHex    = "7b2274797065223a22776562617574686e2e637265617465222c226368616c6c656e6765223a22414d4d507434557878475453746e63647134313759447742466938767049612d7077386f4f755657345441222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73652c22657874726144617461223a22636c69656e74446174614a534f4e206d617920626520657874656e6465642077697468206164646974696f6e616c206669656c647320696e20746865206675747572652c207375636820617320746869733a20426b5165446a646354427258426941774a544c453551227d"
		credentialIDHex      = "f91f391db4c9b2fde0ea70189cba3fb63f579ba6122b33ad94ff3ec330084be4"
		challengeHex         = "00c30fb78531c464d2b6771dab8d7b603c01162f2fa486bea70f283ae556e130"
	)
	credentialID := mustHex(t, credentialIDHex)
	id := base64.RawURLEncoding.EncodeToString(credentialID)
	response := map[string]any{
		"id": id, "rawId": id, "type": "public-key",
		"response": map[string]any{
			"attestationObject": base64.RawURLEncoding.EncodeToString(mustHex(t, attestationObjectHex)),
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(mustHex(t, clientDataJSONHex)),
		},
	}
	body, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	return body, base64.RawURLEncoding.EncodeToString(mustHex(t, challengeHex)), credentialID
}

func authenticationFixture(t *testing.T) ([]byte, string) {
	t.Helper()
	const (
		authenticatorDataHex = "bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b51900000000"
		clientDataJSONHex    = "7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a224f63446e55685158756c5455506f334a5558543049393770767a7a59425039745a63685879617630314167222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73657d"
		signatureHex         = "3046022100f50a4e2e4409249c4a853ba361282f09841df4dd4547a13a87780218deffcd380221008480ac0f0b93538174f575bf11a1dd5d78c6e486013f937295ea13653e331e87"
		credentialIDHex      = "f91f391db4c9b2fde0ea70189cba3fb63f579ba6122b33ad94ff3ec330084be4"
		challengeHex         = "39c0e7521417ba54d43e8dc95174f423dee9bf3cd804ff6d65c857c9abf4d408"
	)
	id := base64.RawURLEncoding.EncodeToString(mustHex(t, credentialIDHex))
	response := map[string]any{
		"id": id, "rawId": id, "type": "public-key",
		"response": map[string]any{
			"authenticatorData": base64.RawURLEncoding.EncodeToString(mustHex(t, authenticatorDataHex)),
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(mustHex(t, clientDataJSONHex)),
			"signature":         base64.RawURLEncoding.EncodeToString(mustHex(t, signatureHex)),
		},
	}
	body, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	return body, base64.RawURLEncoding.EncodeToString(mustHex(t, challengeHex))
}

func mustHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}
