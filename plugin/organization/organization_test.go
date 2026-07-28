package organization

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	betterauth "github.com/eadwinCode/better-auth-go"
	"github.com/eadwinCode/better-auth-go/adapter/memory"
	sqliteadapter "github.com/eadwinCode/better-auth-go/adapter/sqlite"
	_ "modernc.org/sqlite"
)

type organizationClock struct{ now time.Time }

func (clock organizationClock) Now() time.Time { return clock.now }

type organizationMailer struct{}

func (organizationMailer) Send(context.Context, betterauth.Mail) error { return nil }

type organizationImpersonation struct{}

func (organizationImpersonation) CanImpersonate(
	context.Context, betterauth.User, betterauth.User,
) error {
	return errors.New("denied")
}

type organizationBrowser struct {
	handler http.Handler
	cookies map[string]*http.Cookie
}

func (browser *organizationBrowser) request(
	t *testing.T,
	method, path string,
	value map[string]any,
	csrf bool,
) *httptest.ResponseRecorder {
	t.Helper()
	var payload []byte
	var err error
	if value != nil {
		payload, err = json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
	}
	request := httptest.NewRequest(
		method, "https://auth.example.com/api/auth"+path, bytes.NewReader(payload),
	)
	request.Header.Set("Origin", "https://app.example.com")
	if value != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	for _, cookie := range browser.cookies {
		request.AddCookie(cookie)
	}
	if csrf {
		if cookie := browser.cookies["__Host-better_auth_csrf"]; cookie != nil {
			request.Header.Set("X-CSRF-Token", cookie.Value)
		}
	}
	response := httptest.NewRecorder()
	browser.handler.ServeHTTP(response, request)
	for _, cookie := range response.Result().Cookies() {
		if cookie.MaxAge < 0 || cookie.Value == "" {
			delete(browser.cookies, cookie.Name)
		} else {
			copyCookie := *cookie
			browser.cookies[cookie.Name] = &copyCookie
		}
	}
	return response
}

func newOrganizationServer(
	t *testing.T,
	configure func(*Config),
) (http.Handler, *memory.Adapter, organizationClock) {
	t.Helper()
	config := Config{}
	if configure != nil {
		configure(&config)
	}
	plugin, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	passwords, err := betterauth.NewArgon2idVerifier(betterauth.Argon2Params{
		Memory: 19 * 1024, Iterations: 2, Parallelism: 1,
		SaltLength: 16, KeyLength: 32,
	}, 1024)
	if err != nil {
		t.Fatal(err)
	}
	database := memory.New()
	clock := organizationClock{
		now: time.Date(2026, 7, 28, 10, 0, 0, 0, time.UTC),
	}
	server, err := betterauth.New(betterauth.Config{
		PublicURL: "https://auth.example.com",
		TrustedOrigins: []string{
			"https://app.example.com",
		},
		Database: database, Clock: clock, Passwords: passwords,
		Mailer: organizationMailer{}, ImpersonationAuthorizer: organizationImpersonation{},
		Plugins: []betterauth.Plugin{plugin},
	})
	if err != nil {
		t.Fatal(err)
	}
	return server.Handler(), database, clock
}

func organizationSignUp(
	t *testing.T,
	browser *organizationBrowser,
	email string,
) string {
	t.Helper()
	response := browser.request(t, http.MethodPost, "/sign-up/email", map[string]any{
		"email": email, "password": "correct horse battery staple", "name": email,
	}, false)
	if response.Code != http.StatusOK {
		t.Fatalf("sign up: %d %s", response.Code, response.Body.String())
	}
	var result struct {
		User betterauth.User `json:"user"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.User.ID == "" ||
		browser.cookies["__Host-better_auth_session"] == nil ||
		browser.cookies["__Host-better_auth_csrf"] == nil {
		t.Fatal("sign up did not establish an authenticated browser")
	}
	return result.User.ID
}

func responseObject(t *testing.T, response *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var result map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode response %d %q: %v", response.Code, response.Body.String(), err)
	}
	return result
}

func createTestOrganization(
	t *testing.T,
	browser *organizationBrowser,
	name, slug string,
) string {
	t.Helper()
	response := browser.request(t, http.MethodPost, "/organization/create", map[string]any{
		"name": name, "slug": slug,
	}, true)
	if response.Code != http.StatusOK {
		t.Fatalf("create organization: %d %s", response.Code, response.Body.String())
	}
	id, _ := responseObject(t, response)["id"].(string)
	if id == "" {
		t.Fatal("organization response omitted id")
	}
	return id
}

func TestOrganizationRuntimeAuthorizationCSRFAndOwnerInvariant(t *testing.T) {
	handler, database, _ := newOrganizationServer(t, nil)
	owner := &organizationBrowser{handler: handler, cookies: map[string]*http.Cookie{}}
	outsider := &organizationBrowser{handler: handler, cookies: map[string]*http.Cookie{}}
	ownerID := organizationSignUp(t, owner, "owner@example.com")
	organizationID := createTestOrganization(t, owner, "Example", "Example")

	rows, err := database.FindMany(context.Background(), betterauth.FindManyQuery{
		Model: ModelMember,
		Where: []betterauth.Where{
			betterauth.Eq("organizationId", organizationID),
			betterauth.Eq("userId", ownerID),
		},
	})
	if err != nil || len(rows) != 1 || rows[0]["role"] != "owner" {
		t.Fatalf("owner membership not committed: %#v, %v", rows, err)
	}
	audits, err := database.FindMany(context.Background(), betterauth.FindManyQuery{
		Model: betterauth.ModelAuditEvent,
		Where: []betterauth.Where{
			betterauth.Eq("action", "organization.created"),
		},
	})
	if err != nil || len(audits) != 1 {
		t.Fatalf("organization audit not committed: %#v, %v", audits, err)
	}

	missingCSRF := owner.request(
		t, http.MethodPost, "/organization/update", map[string]any{
			"organizationId": organizationID, "name": "Changed",
		}, false,
	)
	if missingCSRF.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF = %d, want 403: %s", missingCSRF.Code, missingCSRF.Body.String())
	}

	organizationSignUp(t, outsider, "outsider@example.com")
	forbidden := outsider.request(
		t, http.MethodPost, "/organization/update", map[string]any{
			"organizationId": organizationID, "name": "Taken",
		}, true,
	)
	if forbidden.Code != http.StatusForbidden {
		t.Fatalf("cross-organization update = %d, want 403: %s", forbidden.Code, forbidden.Body.String())
	}

	leave := owner.request(t, http.MethodPost, "/organization/leave", map[string]any{
		"organizationId": organizationID,
	}, true)
	if leave.Code != http.StatusConflict {
		t.Fatalf("final owner leave = %d, want 409: %s", leave.Code, leave.Body.String())
	}
}

func TestActiveOrganizationRotatesSessionAndPersistsScopedState(t *testing.T) {
	handler, database, _ := newOrganizationServer(t, nil)
	browser := &organizationBrowser{handler: handler, cookies: map[string]*http.Cookie{}}
	organizationSignUp(t, browser, "owner@example.com")
	organizationID := createTestOrganization(t, browser, "Example", "example")
	previous := browser.cookies["__Host-better_auth_session"].Value

	response := browser.request(
		t, http.MethodPost, "/organization/set-active", map[string]any{
			"organizationId": organizationID,
		}, true,
	)
	if response.Code != http.StatusOK {
		t.Fatalf("set active = %d: %s", response.Code, response.Body.String())
	}
	current := browser.cookies["__Host-better_auth_session"].Value
	if current == "" || current == previous {
		t.Fatal("active organization change did not rotate the session")
	}
	oldRow, err := database.FindOne(context.Background(), betterauth.FindOneQuery{
		Model: betterauth.ModelSession,
		Where: []betterauth.Where{
			betterauth.Eq("tokenHash", betterauth.HashToken(previous)),
		},
	})
	if err != nil || oldRow == nil || oldRow["revokedAt"] == nil {
		t.Fatalf("previous session was not revoked: %#v, %v", oldRow, err)
	}
	newRow, err := database.FindOne(context.Background(), betterauth.FindOneQuery{
		Model: betterauth.ModelSession,
		Where: []betterauth.Where{
			betterauth.Eq("tokenHash", betterauth.HashToken(current)),
		},
	})
	if err != nil || newRow == nil ||
		newRow["activeOrganizationId"] != organizationID ||
		newRow["activeTeamId"] != nil {
		t.Fatalf("rotated session has invalid active scope: %#v, %v", newRow, err)
	}
	audits, err := database.FindMany(context.Background(), betterauth.FindManyQuery{
		Model: betterauth.ModelAuditEvent,
		Where: []betterauth.Where{
			betterauth.Eq("action", "organization.active.changed"),
		},
	})
	if err != nil || len(audits) != 1 {
		t.Fatalf("active-context audit missing: %#v, %v", audits, err)
	}
}

func TestInvitationAcceptanceIsEmailBoundAndSingleUse(t *testing.T) {
	var delivered Invitation
	handler, database, _ := newOrganizationServer(t, func(config *Config) {
		config.DeliverInvitation = func(
			_ *betterauth.HookContext,
			invitation Invitation,
			_ Organization,
			_ betterauth.User,
		) error {
			delivered = invitation
			return nil
		}
	})
	owner := &organizationBrowser{handler: handler, cookies: map[string]*http.Cookie{}}
	invitee := &organizationBrowser{handler: handler, cookies: map[string]*http.Cookie{}}
	attacker := &organizationBrowser{handler: handler, cookies: map[string]*http.Cookie{}}
	organizationSignUp(t, owner, "owner@example.com")
	inviteeID := organizationSignUp(t, invitee, "invitee@example.com")
	organizationSignUp(t, attacker, "attacker@example.com")
	organizationID := createTestOrganization(t, owner, "Example", "example")

	invite := owner.request(t, http.MethodPost, "/organization/invite-member", map[string]any{
		"organizationId": organizationID, "email": "INVITEE@example.com",
		"role": "member",
	}, true)
	if invite.Code != http.StatusOK {
		t.Fatalf("invite = %d: %s", invite.Code, invite.Body.String())
	}
	if delivered.ID == "" || delivered.Email != "invitee@example.com" {
		t.Fatalf("delivery did not receive canonical invitation: %#v", delivered)
	}

	wrongEmail := attacker.request(
		t, http.MethodPost, "/organization/accept-invitation", map[string]any{
			"invitationId": delivered.ID,
		}, true,
	)
	if wrongEmail.Code != http.StatusForbidden {
		t.Fatalf("wrong email accept = %d, want 403: %s", wrongEmail.Code, wrongEmail.Body.String())
	}

	_, err := database.Update(context.Background(), betterauth.UpdateQuery{
		Model:  betterauth.ModelUser,
		Where:  []betterauth.Where{betterauth.Eq("id", inviteeID)},
		Update: betterauth.Record{"emailVerified": true},
	})
	if err != nil {
		t.Fatal(err)
	}
	// The authenticated request context is hydrated per request, so the next
	// request observes the verified-email transition.
	const workers = 2
	codes := make(chan int, workers)
	var wait sync.WaitGroup
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			response := invitee.request(
				t, http.MethodPost, "/organization/accept-invitation", map[string]any{
					"invitationId": delivered.ID,
				}, true,
			)
			codes <- response.Code
		}()
	}
	wait.Wait()
	close(codes)
	var success, rejected int
	for code := range codes {
		switch code {
		case http.StatusOK:
			success++
		case http.StatusBadRequest:
			rejected++
		default:
			t.Fatalf("unexpected acceptance status %d", code)
		}
	}
	if success != 1 || rejected != 1 {
		t.Fatalf("acceptance results success=%d rejected=%d", success, rejected)
	}
	count, err := database.Count(context.Background(), betterauth.CountQuery{
		Model: ModelMember,
		Where: []betterauth.Where{
			betterauth.Eq("organizationId", organizationID),
			betterauth.Eq("userId", inviteeID),
		},
	})
	if err != nil || count != 1 {
		t.Fatalf("accepted member count = %d, %v", count, err)
	}
}

func TestTeamMembershipCannotCrossOrganizationBoundary(t *testing.T) {
	handler, _, _ := newOrganizationServer(t, nil)
	owner := &organizationBrowser{handler: handler, cookies: map[string]*http.Cookie{}}
	other := &organizationBrowser{handler: handler, cookies: map[string]*http.Cookie{}}
	organizationSignUp(t, owner, "owner@example.com")
	otherID := organizationSignUp(t, other, "other@example.com")
	firstID := createTestOrganization(t, owner, "First", "first")
	createTestOrganization(t, other, "Second", "second")

	teamResponse := owner.request(t, http.MethodPost, "/organization/create-team", map[string]any{
		"organizationId": firstID, "name": "Core",
	}, true)
	if teamResponse.Code != http.StatusOK {
		t.Fatalf("create team = %d: %s", teamResponse.Code, teamResponse.Body.String())
	}
	teamID, _ := responseObject(t, teamResponse)["id"].(string)
	add := owner.request(t, http.MethodPost, "/organization/add-team-member", map[string]any{
		"teamId": teamID, "userId": otherID,
	}, true)
	if add.Code != http.StatusBadRequest {
		t.Fatalf("cross-organization team add = %d, want 400: %s", add.Code, add.Body.String())
	}
}

func TestOrganizationValidatorsRejectUnknownAndOversizedFields(t *testing.T) {
	handler, _, _ := newOrganizationServer(t, nil)
	browser := &organizationBrowser{handler: handler, cookies: map[string]*http.Cookie{}}
	organizationSignUp(t, browser, "owner@example.com")
	for name, input := range map[string]map[string]any{
		"unknown": {"name": "Example", "slug": "example", "admin": true},
		"oversized": {
			"name": "Example", "slug": fmt.Sprintf("%0130d", 1),
		},
	} {
		t.Run(name, func(t *testing.T) {
			response := browser.request(
				t, http.MethodPost, "/organization/create", input, true,
			)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: %s", response.Code, response.Body.String())
			}
		})
	}
}

func TestOrganizationBeforeHookFailureRollsBackEverything(t *testing.T) {
	hookFailure := errors.New("provisioning unavailable")
	handler, database, _ := newOrganizationServer(t, func(config *Config) {
		config.Hooks.BeforeMutation = func(
			_ *betterauth.HookContext,
			event MutationEvent,
		) error {
			if event.Action == "organization.created" {
				return hookFailure
			}
			return nil
		}
	})
	browser := &organizationBrowser{handler: handler, cookies: map[string]*http.Cookie{}}
	userID := organizationSignUp(t, browser, "owner@example.com")
	response := browser.request(
		t, http.MethodPost, "/organization/create",
		map[string]any{"name": "Example", "slug": "example"}, true,
	)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("hook failure = %d, want 500: %s", response.Code, response.Body.String())
	}
	for _, query := range []betterauth.CountQuery{
		{Model: ModelOrganization},
		{Model: ModelMember, Where: []betterauth.Where{betterauth.Eq("userId", userID)}},
		{
			Model: betterauth.ModelAuditEvent,
			Where: []betterauth.Where{
				betterauth.Eq("action", "organization.created"),
			},
		},
	} {
		count, err := database.Count(context.Background(), query)
		if err != nil || count != 0 {
			t.Fatalf("hook rollback left %s rows: %d, %v", query.Model, count, err)
		}
	}
}

func TestOrganizationHookCannotBypassAuthorizationInvariant(t *testing.T) {
	handler, database, _ := newOrganizationServer(t, func(config *Config) {
		config.Hooks.BeforeMutation = func(
			context *betterauth.HookContext,
			event MutationEvent,
		) error {
			if event.Action != "organization.updated" {
				return nil
			}
			_, err := context.Database.DeleteMany(context.Context, betterauth.DeleteQuery{
				Model: ModelMember,
				Where: []betterauth.Where{
					betterauth.Eq("organizationId", event.OrganizationID),
					betterauth.Eq("userId", context.User.ID),
				},
			})
			return err
		}
	})
	browser := &organizationBrowser{handler: handler, cookies: map[string]*http.Cookie{}}
	userID := organizationSignUp(t, browser, "owner@example.com")
	organizationID := createTestOrganization(t, browser, "Original", "original")
	response := browser.request(
		t, http.MethodPost, "/organization/update", map[string]any{
			"organizationId": organizationID, "name": "Bypassed",
		}, true,
	)
	if response.Code != http.StatusForbidden {
		t.Fatalf("post-hook authorization = %d, want 403: %s", response.Code, response.Body.String())
	}
	memberCount, err := database.Count(context.Background(), betterauth.CountQuery{
		Model: ModelMember,
		Where: []betterauth.Where{
			betterauth.Eq("organizationId", organizationID),
			betterauth.Eq("userId", userID),
		},
	})
	if err != nil || memberCount != 1 {
		t.Fatalf("authorization rollback lost membership: %d, %v", memberCount, err)
	}
	row, err := database.FindOne(context.Background(), betterauth.FindOneQuery{
		Model: ModelOrganization,
		Where: []betterauth.Where{betterauth.Eq("id", organizationID)},
	})
	if err != nil || row["name"] != "Original" {
		t.Fatalf("hook bypass changed organization: %#v, %v", row, err)
	}
}

func TestManagerAddMemberIsDeterministicTransactionalAndAudited(t *testing.T) {
	manager, err := NewManager(Config{})
	if err != nil {
		t.Fatal(err)
	}
	database := memory.New()
	now := time.Date(2026, 7, 28, 14, 0, 0, 0, time.UTC)
	for _, record := range []struct {
		model string
		data  betterauth.Record
	}{
		{
			model: betterauth.ModelUser,
			data: betterauth.Record{
				"id": "actor", "email": "actor@example.com", "name": "Actor",
				"emailVerified": true, "createdAt": now, "updatedAt": now,
			},
		},
		{
			model: betterauth.ModelUser,
			data: betterauth.Record{
				"id": "subject", "email": "subject@example.com", "name": "Subject",
				"emailVerified": true, "createdAt": now, "updatedAt": now,
			},
		},
		{
			model: ModelOrganization,
			data: betterauth.Record{
				"id": "org", "name": "Example", "slug": "example",
				"createdAt": now, "updatedAt": now,
			},
		},
	} {
		if _, err = database.Create(context.Background(), betterauth.CreateQuery{
			Model: record.model, Data: record.data, ForceAllowID: true,
		}); err != nil {
			t.Fatal(err)
		}
	}
	ids := []string{"member-id", "audit-id"}
	index := 0
	member, err := manager.AddMember(context.Background(), AddMemberInput{
		Database: database, OrganizationID: "org", UserID: "subject",
		ActorUserID: "actor", Roles: []string{"member"}, Clock: organizationClock{now: now},
		GenerateID: func() (string, error) {
			value := ids[index]
			index++
			return value, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if member.ID != "member-id" || member.CreatedAt != now {
		t.Fatalf("unexpected deterministic member: %#v", member)
	}
	audit, err := database.FindOne(context.Background(), betterauth.FindOneQuery{
		Model: betterauth.ModelAuditEvent,
		Where: []betterauth.Where{betterauth.Eq("id", "audit-id")},
	})
	if err != nil || audit == nil || audit["actorUserId"] != "actor" ||
		audit["subjectUserId"] != "subject" {
		t.Fatalf("manager audit missing or invalid: %#v, %v", audit, err)
	}
}

func TestOrganizationSchemaMigratesAndEnforcesCompoundKeysOnSQLite(t *testing.T) {
	plugin, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	schema, err := betterauth.MergeSchema(betterauth.CoreSchema(), plugin.Schema)
	if err != nil {
		t.Fatal(err)
	}
	database, err := sql.Open(
		"sqlite",
		"file:"+filepath.Join(t.TempDir(), "organizations.db")+
			"?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)",
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	adapter, err := sqliteadapter.New(database)
	if err != nil {
		t.Fatal(err)
	}
	if err = adapter.Migrate(t.Context(), schema); err != nil {
		t.Fatal(err)
	}
	configured, err := adapter.WithSchema(schema)
	if err != nil {
		t.Fatal(err)
	}
	indexRows, err := database.QueryContext(
		t.Context(), `PRAGMA index_list("member")`,
	)
	if err != nil {
		t.Fatal(err)
	}
	var foundCompound bool
	for indexRows.Next() {
		var sequence, unique, partial int
		var name, origin string
		if err = indexRows.Scan(&sequence, &name, &unique, &origin, &partial); err != nil {
			t.Fatal(err)
		}
		if name == "member_organization_user_unique" && unique == 1 {
			foundCompound = true
		}
	}
	if err = indexRows.Close(); err != nil {
		t.Fatal(err)
	}
	if !foundCompound {
		t.Fatal("SQLite migration omitted the member compound unique index")
	}
	now := time.Date(2026, 7, 28, 15, 0, 0, 0, time.UTC)
	if _, err = configured.Create(t.Context(), betterauth.CreateQuery{
		Model: betterauth.ModelUser, ForceAllowID: true,
		Data: betterauth.Record{
			"id": "user", "email": "user@example.com", "name": "User",
			"emailVerified": true, "createdAt": now, "updatedAt": now,
		},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err = configured.Create(t.Context(), betterauth.CreateQuery{
		Model: ModelOrganization, ForceAllowID: true,
		Data: betterauth.Record{
			"id": "org", "name": "Example", "slug": "example",
			"createdAt": now, "updatedAt": now,
		},
	}); err != nil {
		t.Fatal(err)
	}
	createMembership := func(id string) error {
		_, createErr := configured.Create(t.Context(), betterauth.CreateQuery{
			Model: ModelMember, ForceAllowID: true,
			Data: betterauth.Record{
				"id": id, "organizationId": "org", "userId": "user",
				"role": "member", "createdAt": now, "updatedAt": now,
			},
		})
		return createErr
	}
	if err = createMembership("member-1"); err != nil {
		t.Fatal(err)
	}
	if err = createMembership("member-2"); !errors.Is(err, betterauth.ErrConflict) {
		t.Fatalf("duplicate organization/user membership = %v, want conflict", err)
	}
}

func FuzzCanonicalRoles(f *testing.F) {
	for _, seed := range []string{"owner", "member,admin", " admin , member ", "", "🚫"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		value, err := canonicalRoles([]string{input})
		if err == nil {
			reparsed, reparsedErr := canonicalRoles([]string{value})
			if reparsedErr != nil || reparsed != value {
				t.Fatalf(
					"canonical role set is unstable: %q => %q, %v",
					value, reparsed, reparsedErr,
				)
			}
		}
	})
}
