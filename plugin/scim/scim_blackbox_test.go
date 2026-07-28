package scim

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	betterauth "github.com/eadwinCode/better-auth-go"
	"github.com/eadwinCode/better-auth-go/adapter/memory"
)

type scimBrowser struct {
	handler http.Handler
	cookies map[string]*http.Cookie
}

type trackingOrganizationAuthorizer struct {
	mu      sync.Mutex
	members map[string]map[string]bool
	roles   []string
}

func (authorizer *trackingOrganizationAuthorizer) AuthorizeSCIMConnectionRoles(
	_ *betterauth.HookContext,
	_ string,
	roles []string,
) error {
	authorizer.mu.Lock()
	defer authorizer.mu.Unlock()
	authorizer.roles = slices.Clone(roles)
	return nil
}

func (authorizer *trackingOrganizationAuthorizer) AuthorizeSCIMConnection(
	*betterauth.HookContext,
	string,
) error {
	return nil
}

func (authorizer *trackingOrganizationAuthorizer) IsSCIMMember(
	_ *betterauth.HookContext,
	organizationID, userID string,
) (bool, error) {
	authorizer.mu.Lock()
	defer authorizer.mu.Unlock()
	return authorizer.members[organizationID][userID], nil
}

func (authorizer *trackingOrganizationAuthorizer) AddSCIMMember(
	_ *betterauth.HookContext,
	organizationID, userID string,
) error {
	authorizer.mu.Lock()
	defer authorizer.mu.Unlock()
	if authorizer.members[organizationID] == nil {
		authorizer.members[organizationID] = map[string]bool{}
	}
	authorizer.members[organizationID][userID] = true
	return nil
}

func (authorizer *trackingOrganizationAuthorizer) RemoveSCIMMember(
	_ *betterauth.HookContext,
	organizationID, userID string,
) error {
	authorizer.mu.Lock()
	defer authorizer.mu.Unlock()
	delete(authorizer.members[organizationID], userID)
	return nil
}

func (browser *scimBrowser) request(
	t *testing.T,
	method, path string,
	body any,
	csrf bool,
) *httptest.ResponseRecorder {
	t.Helper()
	var payload []byte
	if body != nil {
		var err error
		payload, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	request := httptest.NewRequest(
		method, "https://auth.example.com/api/auth"+path, bytes.NewReader(payload),
	)
	request.Header.Set("Origin", "https://app.example.com")
	request.Header.Set("Content-Type", "application/json")
	for _, cookie := range browser.cookies {
		request.AddCookie(cookie)
	}
	if csrf {
		request.Header.Set("X-CSRF-Token", browser.cookies["__Host-better_auth_csrf"].Value)
	}
	recorder := httptest.NewRecorder()
	browser.handler.ServeHTTP(recorder, request)
	for _, cookie := range recorder.Result().Cookies() {
		browser.cookies[cookie.Name] = cookie
	}
	return recorder
}

func protocolRequest(
	t *testing.T,
	handler http.Handler,
	method, path, bearer, contentType string,
	body any,
) *httptest.ResponseRecorder {
	t.Helper()
	var payload []byte
	if body != nil {
		var err error
		payload, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	request := httptest.NewRequest(
		method, "https://auth.example.com/api/auth"+path, bytes.NewReader(payload),
	)
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if got := recorder.Header().Get("Content-Type"); recorder.Code != http.StatusNoContent &&
		!strings.HasPrefix(got, "application/scim+json") {
		t.Fatalf("%s %s content type = %q: %s", method, path, got, recorder.Body.String())
	}
	return recorder
}

func TestSCIMConnectionAndUserLifecycleBlackBox(t *testing.T) {
	t.Parallel()
	plugin, err := New(Config{
		ProviderOwnership: true,
		CanGenerateToken: func(*betterauth.HookContext, string, string) (bool, error) {
			return true, nil
		},
	})
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
		PublicURL: "https://auth.example.com", TrustedOrigins: []string{"https://app.example.com"},
		Database: database, Mailer: discardMailer{}, ImpersonationAuthorizer: denyImpersonation{},
		Passwords: passwords, Plugins: []betterauth.Plugin{plugin},
	})
	if err != nil {
		t.Fatal(err)
	}
	browser := &scimBrowser{handler: server.Handler(), cookies: map[string]*http.Cookie{}}
	signup := browser.request(t, http.MethodPost, "/sign-up/email", map[string]any{
		"email": "owner@example.com", "password": "correct horse battery staple",
		"name": "Directory Owner",
	}, false)
	if signup.Code != http.StatusOK {
		t.Fatalf("signup = %d: %s", signup.Code, signup.Body.String())
	}
	generated := browser.request(t, http.MethodPost, "/scim/generate-token", map[string]any{
		"providerId": "workforce-directory",
	}, true)
	if generated.Code != http.StatusCreated {
		t.Fatalf("generate = %d: %s", generated.Code, generated.Body.String())
	}
	var tokenBody struct {
		Token string `json:"scimToken"`
	}
	if err = json.Unmarshal(generated.Body.Bytes(), &tokenBody); err != nil || tokenBody.Token == "" {
		t.Fatalf("decode token: %v, %#v", err, tokenBody)
	}
	provider, err := database.FindOne(context.Background(), betterauth.FindOneQuery{
		Model: ModelSCIMProvider,
		Where: []betterauth.Where{betterauth.Eq("providerId", "workforce-directory")},
	})
	if err != nil || provider == nil {
		t.Fatalf("provider persistence: %v %#v", err, provider)
	}
	claims, err := parseBearerToken(tokenBody.Token, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if provider["tokenHash"] != claims.TokenHash ||
		strings.Contains(provider["tokenHash"].(string), claims.Secret) {
		t.Fatal("provider did not persist only the bearer secret hash")
	}
	listConnections := browser.request(
		t, http.MethodGet, "/scim/list-provider-connections", nil, false,
	)
	if listConnections.Code != http.StatusOK ||
		!strings.Contains(listConnections.Body.String(), "workforce-directory") {
		t.Fatalf("list connections = %d: %s", listConnections.Code, listConnections.Body.String())
	}
	getConnection := browser.request(
		t, http.MethodGet,
		"/scim/get-provider-connection?providerId=workforce-directory", nil, false,
	)
	if getConnection.Code != http.StatusOK ||
		strings.Contains(getConnection.Body.String(), "tokenHash") {
		t.Fatalf("get connection = %d: %s", getConnection.Code, getConnection.Body.String())
	}
	other := &scimBrowser{handler: server.Handler(), cookies: map[string]*http.Cookie{}}
	otherSignup := other.request(t, http.MethodPost, "/sign-up/email", map[string]any{
		"email": "other@example.com", "password": "correct horse battery staple",
		"name": "Other Owner",
	}, false)
	if otherSignup.Code != http.StatusOK {
		t.Fatalf("other signup = %d: %s", otherSignup.Code, otherSignup.Body.String())
	}
	hidden := other.request(
		t, http.MethodGet,
		"/scim/get-provider-connection?providerId=workforce-directory", nil, false,
	)
	if hidden.Code != http.StatusNotFound {
		t.Fatalf("cross-owner get = %d: %s", hidden.Code, hidden.Body.String())
	}
	rotated := browser.request(t, http.MethodPost, "/scim/generate-token", map[string]any{
		"providerId": "workforce-directory",
	}, true)
	if rotated.Code != http.StatusCreated {
		t.Fatalf("rotate = %d: %s", rotated.Code, rotated.Body.String())
	}
	oldToken := tokenBody.Token
	if err = json.Unmarshal(rotated.Body.Bytes(), &tokenBody); err != nil ||
		tokenBody.Token == "" || tokenBody.Token == oldToken {
		t.Fatalf("decode rotated token: %v %#v", err, tokenBody)
	}
	replayed := protocolRequest(
		t, server.Handler(), http.MethodGet, "/scim/v2/Users", oldToken, "", nil,
	)
	if replayed.Code != http.StatusUnauthorized {
		t.Fatalf("rotated token replay = %d: %s", replayed.Code, replayed.Body.String())
	}

	create := protocolRequest(
		t, server.Handler(), http.MethodPost, "/scim/v2/Users",
		tokenBody.Token, "application/scim+json",
		UserInput{
			Schemas: []string{SchemaUser}, UserName: "person@example.com",
			ExternalID: "directory-42", Name: &Name{GivenName: "Ada", FamilyName: "Lovelace"},
			Emails: []Email{{Value: "person@example.com", Primary: true}},
		},
	)
	if create.Code != http.StatusCreated {
		t.Fatalf("create = %d: %s", create.Code, create.Body.String())
	}
	var created UserResource
	if err = json.Unmarshal(create.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.ID == "" || created.ExternalID != "directory-42" || !created.Active {
		t.Fatalf("created resource = %#v", created)
	}

	list := protocolRequest(
		t, server.Handler(), http.MethodGet,
		`/scim/v2/Users?filter=externalId%20eq%20%22directory-42%22&count=1`,
		tokenBody.Token, "", nil,
	)
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), created.ID) {
		t.Fatalf("list = %d: %s", list.Code, list.Body.String())
	}
	replace := protocolRequest(
		t, server.Handler(), http.MethodPut, "/scim/v2/Users/"+created.ID,
		tokenBody.Token, "application/json",
		UserInput{
			Schemas: []string{SchemaUser}, UserName: "new-person@example.com",
			ExternalID: "directory-84", Name: &Name{Formatted: "Ada Byron"},
			Emails: []Email{{Value: "new-person@example.com", Primary: true}},
		},
	)
	if replace.Code != http.StatusOK || !strings.Contains(replace.Body.String(), "directory-84") {
		t.Fatalf("replace = %d: %s", replace.Code, replace.Body.String())
	}

	now := time.Now().UTC()
	if _, err = database.Create(context.Background(), betterauth.CreateQuery{
		Model: betterauth.ModelSession, ForceAllowID: true,
		Data: betterauth.Record{
			"id": "managed-session", "userId": created.ID, "tokenHash": betterauth.HashToken("managed"),
			"expiresAt": now.Add(time.Hour), "createdAt": now, "updatedAt": now, "lastSeenAt": now,
			"revokedAt": nil,
		},
	}); err != nil {
		t.Fatal(err)
	}
	patch := protocolRequest(
		t, server.Handler(), http.MethodPatch, "/scim/v2/Users/"+created.ID,
		tokenBody.Token, "application/scim+json",
		PatchRequest{
			Schemas:    []string{SchemaPatch},
			Operations: []PatchOperation{{Operation: "replace", Path: "active", Value: false}},
		},
	)
	if patch.Code != http.StatusNoContent {
		t.Fatalf("patch = %d: %s", patch.Code, patch.Body.String())
	}
	session, err := database.FindOne(context.Background(), betterauth.FindOneQuery{
		Model: betterauth.ModelSession,
		Where: []betterauth.Where{betterauth.Eq("id", "managed-session")},
	})
	if err != nil || session["revokedAt"] == nil {
		t.Fatalf("session was not revoked: %v %#v", err, session)
	}
	get := protocolRequest(
		t, server.Handler(), http.MethodGet, "/scim/v2/Users/"+created.ID,
		tokenBody.Token, "", nil,
	)
	if get.Code != http.StatusOK || !strings.Contains(get.Body.String(), `"active":false`) {
		t.Fatalf("get = %d: %s", get.Code, get.Body.String())
	}
	deleted := protocolRequest(
		t, server.Handler(), http.MethodDelete, "/scim/v2/Users/"+created.ID,
		tokenBody.Token, "", nil,
	)
	if deleted.Code != http.StatusNoContent {
		t.Fatalf("delete = %d: %s", deleted.Code, deleted.Body.String())
	}
	user, err := database.FindOne(context.Background(), betterauth.FindOneQuery{
		Model: betterauth.ModelUser, Where: []betterauth.Where{betterauth.Eq("id", created.ID)},
	})
	if err != nil || user != nil {
		t.Fatalf("sole-identity user survived SCIM delete: %v %#v", err, user)
	}
	audits, err := database.Count(context.Background(), betterauth.CountQuery{
		Model: betterauth.ModelAuditEvent,
	})
	if err != nil || audits < 5 {
		t.Fatalf("audit count = %d, err = %v", audits, err)
	}
	deletedConnection := browser.request(
		t, http.MethodPost, "/scim/delete-provider-connection",
		map[string]any{"providerId": "workforce-directory"}, true,
	)
	if deletedConnection.Code != http.StatusOK {
		t.Fatalf(
			"delete connection = %d: %s",
			deletedConnection.Code, deletedConnection.Body.String(),
		)
	}
	invalidated := protocolRequest(
		t, server.Handler(), http.MethodGet, "/scim/v2/Users", tokenBody.Token, "", nil,
	)
	if invalidated.Code != http.StatusUnauthorized {
		t.Fatalf("deleted token use = %d: %s", invalidated.Code, invalidated.Body.String())
	}
}

func TestSCIMProtocolFailsClosed(t *testing.T) {
	t.Parallel()
	secret := strings.Repeat("s", 32)
	token, err := encodeBearerToken(secret, "directory", "")
	if err != nil {
		t.Fatal(err)
	}
	plugin, err := New(Config{DefaultConnections: []DefaultConnection{{
		ProviderID: "directory", TokenHash: betterauth.HashToken(secret), UserID: "owner",
	}}})
	if err != nil {
		t.Fatal(err)
	}
	server, err := betterauth.New(betterauth.Config{
		PublicURL: "https://auth.example.com", TrustedOrigins: []string{"https://app.example.com"},
		Database: memory.New(), Mailer: discardMailer{},
		ImpersonationAuthorizer: denyImpersonation{}, Plugins: []betterauth.Plugin{plugin},
	})
	if err != nil {
		t.Fatal(err)
	}
	unauthorized := protocolRequest(
		t, server.Handler(), http.MethodGet, "/scim/v2/Users", "invalid", "", nil,
	)
	if unauthorized.Code != http.StatusUnauthorized ||
		!strings.Contains(unauthorized.Body.String(), SchemaError) {
		t.Fatalf("unauthorized = %d: %s", unauthorized.Code, unauthorized.Body.String())
	}
	unsupported := protocolRequest(
		t, server.Handler(), http.MethodPost, "/scim/v2/Users",
		token, "text/plain", map[string]any{"userName": "person@example.com"},
	)
	if unsupported.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("unsupported = %d: %s", unsupported.Code, unsupported.Body.String())
	}
}

func TestOrganizationSCIMDeletePreservesGlobalUser(t *testing.T) {
	t.Parallel()
	secret := strings.Repeat("o", 32)
	token, err := encodeBearerToken(secret, "organization-directory", "org-1")
	if err != nil {
		t.Fatal(err)
	}
	authorizer := &trackingOrganizationAuthorizer{members: map[string]map[string]bool{}}
	plugin, err := New(Config{
		OrganizationAuthorizer: authorizer,
		DefaultConnections: []DefaultConnection{{
			ProviderID: "organization-directory", OrganizationID: "org-1",
			TokenHash: betterauth.HashToken(secret), UserID: "owner",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	database := memory.New()
	server, err := betterauth.New(betterauth.Config{
		PublicURL: "https://auth.example.com", TrustedOrigins: []string{"https://app.example.com"},
		Database: database, Mailer: discardMailer{},
		ImpersonationAuthorizer: denyImpersonation{}, Plugins: []betterauth.Plugin{plugin},
	})
	if err != nil {
		t.Fatal(err)
	}
	create := protocolRequest(
		t, server.Handler(), http.MethodPost, "/scim/v2/Users",
		token, "application/scim+json",
		UserInput{
			Schemas: []string{SchemaUser}, UserName: "member@example.com",
			ExternalID: "member-1",
		},
	)
	if create.Code != http.StatusCreated {
		t.Fatalf("create = %d: %s", create.Code, create.Body.String())
	}
	var resource UserResource
	if err = json.Unmarshal(create.Body.Bytes(), &resource); err != nil {
		t.Fatal(err)
	}
	deleted := protocolRequest(
		t, server.Handler(), http.MethodDelete, "/scim/v2/Users/"+resource.ID,
		token, "", nil,
	)
	if deleted.Code != http.StatusNoContent {
		t.Fatalf("delete = %d: %s", deleted.Code, deleted.Body.String())
	}
	user, err := database.FindOne(context.Background(), betterauth.FindOneQuery{
		Model: betterauth.ModelUser, Where: []betterauth.Where{betterauth.Eq("id", resource.ID)},
	})
	if err != nil || user == nil {
		t.Fatalf("organization SCIM deleted global user: %v %#v", err, user)
	}
	account, err := database.FindOne(context.Background(), betterauth.FindOneQuery{
		Model: betterauth.ModelAccount,
		Where: []betterauth.Where{
			betterauth.Eq("providerId", "organization-directory"),
			betterauth.Eq("userId", resource.ID),
		},
	})
	if err != nil || account != nil {
		t.Fatalf("organization SCIM account survived delete: %v %#v", err, account)
	}
	member, err := authorizer.IsSCIMMember(nil, "org-1", resource.ID)
	if err != nil || member {
		t.Fatalf("organization membership survived delete: %v %v", member, err)
	}
}

func TestConcurrentSCIMCreateHasOneWinner(t *testing.T) {
	t.Parallel()
	secret := strings.Repeat("c", 32)
	token, err := encodeBearerToken(secret, "concurrent-directory", "")
	if err != nil {
		t.Fatal(err)
	}
	plugin, err := New(Config{DefaultConnections: []DefaultConnection{{
		ProviderID: "concurrent-directory", TokenHash: betterauth.HashToken(secret), UserID: "owner",
	}}})
	if err != nil {
		t.Fatal(err)
	}
	database := memory.New()
	server, err := betterauth.New(betterauth.Config{
		PublicURL: "https://auth.example.com", TrustedOrigins: []string{"https://app.example.com"},
		Database: database, Mailer: discardMailer{},
		ImpersonationAuthorizer: denyImpersonation{}, Plugins: []betterauth.Plugin{plugin},
	})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(UserInput{
		Schemas: []string{SchemaUser}, UserName: "concurrent@example.com",
		ExternalID: "concurrent-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	statuses := make(chan int, 2)
	var group sync.WaitGroup
	for range 2 {
		group.Add(1)
		go func() {
			defer group.Done()
			request := httptest.NewRequest(
				http.MethodPost, "https://auth.example.com/api/auth/scim/v2/Users",
				bytes.NewReader(payload),
			)
			request.Header.Set("Authorization", "Bearer "+token)
			request.Header.Set("Content-Type", "application/scim+json")
			recorder := httptest.NewRecorder()
			server.Handler().ServeHTTP(recorder, request)
			statuses <- recorder.Code
		}()
	}
	group.Wait()
	close(statuses)
	created, conflicts := 0, 0
	for status := range statuses {
		switch status {
		case http.StatusCreated:
			created++
		case http.StatusConflict:
			conflicts++
		default:
			t.Fatalf("unexpected concurrent create status %d", status)
		}
	}
	if created != 1 || conflicts != 1 {
		t.Fatalf("concurrent outcomes created=%d conflicts=%d", created, conflicts)
	}
	users, err := database.Count(context.Background(), betterauth.CountQuery{
		Model: betterauth.ModelUser,
	})
	if err != nil || users != 1 {
		t.Fatalf("concurrent create persisted %d users: %v", users, err)
	}
}
