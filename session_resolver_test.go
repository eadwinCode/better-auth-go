package betterauth_test

import (
	"bytes"
	"context"
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

	betterauth "github.com/eadwinCode/better-auth-go"
	"github.com/eadwinCode/better-auth-go/adapter/memory"
)

type resolverFaultAdapter struct {
	betterauth.DatabaseAdapter
	fail atomic.Bool
	err  error
}

func (adapter *resolverFaultAdapter) FindOne(
	ctx context.Context,
	query betterauth.FindOneQuery,
) (betterauth.Record, error) {
	if adapter.fail.Load() && query.Model == betterauth.ModelSession {
		return nil, adapter.err
	}
	return adapter.DatabaseAdapter.FindOne(ctx, query)
}

type resolverFixture struct {
	server   *betterauth.Server
	client   *testClient
	database *memory.Adapter
	fault    *resolverFaultAdapter
	now      time.Time
}

func newResolverFixture(
	t *testing.T,
	configure func(*betterauth.Config),
) resolverFixture {
	t.Helper()
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	database := memory.New()
	fault := &resolverFaultAdapter{
		DatabaseAdapter: database,
		err:             errors.New("resolver database unavailable: private detail"),
	}
	params := betterauth.Argon2Params{
		Memory: 19 * 1024, Iterations: 2, Parallelism: 1, SaltLength: 16, KeyLength: 32,
	}
	passwords, err := betterauth.NewArgon2idVerifier(params, 1024)
	if err != nil {
		t.Fatal(err)
	}
	config := betterauth.Config{
		PublicURL:               "https://auth.example.com",
		TrustedOrigins:          []string{"https://app.example.com"},
		Database:                fault,
		Mailer:                  &captureMailer{},
		ImpersonationAuthorizer: allowImpersonation{},
		Clock:                   fixedClock{now: now},
		Tokens:                  &sequenceTokens{},
		Passwords:               passwords,
	}
	if configure != nil {
		configure(&config)
	}
	server, err := betterauth.New(config)
	if err != nil {
		t.Fatal(err)
	}
	return resolverFixture{
		server:   server,
		client:   &testClient{handler: server.Handler(), database: database},
		database: database,
		fault:    fault,
		now:      now,
	}
}

func (fixture resolverFixture) signUp(
	t *testing.T,
	email string,
) (betterauth.Session, betterauth.User) {
	t.Helper()
	response := fixture.client.request(t, http.MethodPost, "/sign-up/email", map[string]any{
		"email": email, "password": "correct horse battery staple", "name": "Resolver User",
	}, false)
	if response.Code != http.StatusOK {
		t.Fatalf("signup response %d: %s", response.Code, response.Body.String())
	}
	var body struct {
		User betterauth.User `json:"user"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	row, err := fixture.database.FindOne(context.Background(), betterauth.FindOneQuery{
		Model: betterauth.ModelSession,
		Where: []betterauth.Where{
			betterauth.Eq("tokenHash", betterauth.HashToken(fixture.client.session.Value)),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	sessionID, _ := row["id"].(string)
	userID, _ := row["userId"].(string)
	if sessionID == "" || userID == "" {
		t.Fatalf("signup session record = %#v", row)
	}
	return betterauth.Session{ID: sessionID, UserID: userID}, body.User
}

func sessionRequest(cookie *http.Cookie) *http.Request {
	request := httptest.NewRequest(http.MethodGet, "https://app.example.com/dashboard", nil)
	if cookie != nil {
		request.AddCookie(cookie)
	}
	return request
}

func TestResolveSessionMissingAndInvalidCookie(t *testing.T) {
	t.Parallel()
	fixture := newResolverFixture(t, nil)
	tests := []struct {
		name    string
		request *http.Request
	}{
		{name: "nil request"},
		{name: "missing cookie", request: sessionRequest(nil)},
		{
			name: "unknown token",
			request: sessionRequest(&http.Cookie{
				Name: "__Host-better_auth_session", Value: "not-a-session",
			}),
		},
		{
			name: "oversized token",
			request: sessionRequest(&http.Cookie{
				Name: "__Host-better_auth_session", Value: strings.Repeat("x", 2049),
			}),
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := fixture.server.ResolveSession(context.Background(), test.request)
			if !errors.Is(err, betterauth.ErrNoSession) {
				t.Fatalf("ResolveSession error = %v, want ErrNoSession", err)
			}
		})
	}
}

func TestResolveSessionReturnsPublicSessionAndUser(t *testing.T) {
	t.Parallel()
	fixture := newResolverFixture(t, nil)
	wantSession, wantUser := fixture.signUp(t, "valid-resolver@example.com")
	result, err := fixture.server.ResolveSession(
		context.Background(),
		sessionRequest(fixture.client.session),
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.Session.ID != wantSession.ID || result.Session.UserID != wantUser.ID {
		t.Fatalf("resolved session = %#v, want ID %q and user %q", result.Session, wantSession.ID, wantUser.ID)
	}
	if result.User.ID != wantUser.ID || result.User.Email != "valid-resolver@example.com" {
		t.Fatalf("resolved user = %#v, want %#v", result.User, wantUser)
	}
	if result.Session.TokenHash != betterauth.HashToken(fixture.client.session.Value) {
		t.Fatal("resolved session did not retain its stored token hash")
	}
	if result.Session.TokenHash == fixture.client.session.Value {
		t.Fatal("resolver returned the opaque token instead of its stored hash")
	}
}

func TestResolveSessionUsesConfiguredCookieName(t *testing.T) {
	t.Parallel()
	const sessionCookie = "__Host-clevix_session"
	fixture := newResolverFixture(t, func(config *betterauth.Config) {
		config.Cookie = betterauth.CookieConfig{
			Name: sessionCookie, CSRFName: "__Host-clevix_csrf",
		}
	})
	response := fixture.client.request(t, http.MethodPost, "/sign-up/email", map[string]any{
		"email":    "configured-cookie@example.com",
		"password": "correct horse battery staple",
		"name":     "Configured Cookie",
	}, false)
	if response.Code != http.StatusOK {
		t.Fatalf("signup response %d: %s", response.Code, response.Body.String())
	}
	var configured *http.Cookie
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == sessionCookie {
			configured = cookie
			break
		}
	}
	if configured == nil {
		t.Fatal("signup did not issue the configured session cookie")
	}
	request := sessionRequest(configured)
	request.AddCookie(&http.Cookie{
		Name: "__Host-better_auth_session", Value: "wrong-default-cookie",
	})
	result, err := fixture.server.ResolveSession(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if result.User.Email != "configured-cookie@example.com" {
		t.Fatalf("resolved user = %#v", result.User)
	}
}

func TestResolveSessionRejectsInactiveState(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(resolverFixture, betterauth.Session, betterauth.User) error
	}{
		{
			name: "expired",
			mutate: func(fixture resolverFixture, session betterauth.Session, _ betterauth.User) error {
				_, err := fixture.database.Update(context.Background(), betterauth.UpdateQuery{
					Model:  betterauth.ModelSession,
					Where:  []betterauth.Where{betterauth.Eq("id", session.ID)},
					Update: betterauth.Record{"expiresAt": fixture.now},
				})
				return err
			},
		},
		{
			name: "revoked",
			mutate: func(fixture resolverFixture, session betterauth.Session, _ betterauth.User) error {
				_, err := fixture.database.Update(context.Background(), betterauth.UpdateQuery{
					Model:  betterauth.ModelSession,
					Where:  []betterauth.Where{betterauth.Eq("id", session.ID)},
					Update: betterauth.Record{"revokedAt": fixture.now},
				})
				return err
			},
		},
		{
			name: "disabled user",
			mutate: func(fixture resolverFixture, _ betterauth.Session, user betterauth.User) error {
				_, err := fixture.database.Update(context.Background(), betterauth.UpdateQuery{
					Model:  betterauth.ModelUser,
					Where:  []betterauth.Where{betterauth.Eq("id", user.ID)},
					Update: betterauth.Record{"disabledAt": fixture.now},
				})
				return err
			},
		},
	}
	for index, test := range tests {
		index := index
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newResolverFixture(t, nil)
			session, user := fixture.signUp(t, fmt.Sprintf("inactive-%d@example.com", index))
			if err := test.mutate(fixture, session, user); err != nil {
				t.Fatal(err)
			}
			_, err := fixture.server.ResolveSession(
				context.Background(),
				sessionRequest(fixture.client.session),
			)
			if !errors.Is(err, betterauth.ErrNoSession) {
				t.Fatalf("ResolveSession error = %v, want ErrNoSession", err)
			}
		})
	}
}

func TestResolveSessionPreservesImpersonationFields(t *testing.T) {
	t.Parallel()
	fixture := newResolverFixture(t, nil)
	_, actor := fixture.signUp(t, "resolver-admin@example.com")
	targetClient := &testClient{handler: fixture.server.Handler(), database: fixture.database}
	targetSignup := targetClient.request(t, http.MethodPost, "/sign-up/email", map[string]any{
		"email":    "resolver-target@example.com",
		"password": "correct horse battery staple",
		"name":     "Resolver Target",
	}, false)
	if targetSignup.Code != http.StatusOK {
		t.Fatalf("target signup response %d: %s", targetSignup.Code, targetSignup.Body.String())
	}
	var target struct {
		User betterauth.User `json:"user"`
	}
	if err := json.Unmarshal(targetSignup.Body.Bytes(), &target); err != nil {
		t.Fatal(err)
	}
	start := fixture.client.request(t, http.MethodPost, "/admin/impersonate-user", map[string]any{
		"userId": target.User.ID,
	}, true)
	if start.Code != http.StatusOK {
		t.Fatalf("impersonation response %d: %s", start.Code, start.Body.String())
	}
	result, err := fixture.server.ResolveSession(
		context.Background(),
		sessionRequest(fixture.client.session),
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.User.ID != target.User.ID {
		t.Fatalf("resolved subject = %q, want %q", result.User.ID, target.User.ID)
	}
	if result.Session.ImpersonatorID != actor.ID || result.Session.ImpersonationID == "" {
		t.Fatalf("missing impersonation metadata: %#v", result.Session)
	}
}

func TestResolveSessionDistinguishesAdapterFailureAndKeepsHTTPGeneric(t *testing.T) {
	t.Parallel()
	fixture := newResolverFixture(t, nil)
	fixture.signUp(t, "resolver-outage@example.com")
	fixture.fault.fail.Store(true)

	_, err := fixture.server.ResolveSession(
		context.Background(),
		sessionRequest(fixture.client.session),
	)
	if err == nil || !errors.Is(err, fixture.fault.err) {
		t.Fatalf("ResolveSession error = %v, want wrapped adapter failure", err)
	}
	if errors.Is(err, betterauth.ErrNoSession) {
		t.Fatalf("adapter failure unexpectedly matched ErrNoSession: %v", err)
	}

	getSession := fixture.client.request(t, http.MethodGet, "/get-session", nil, false)
	if getSession.Code != http.StatusOK || getSession.Body.String() != "null\n" {
		t.Fatalf("get-session response = %d %s", getSession.Code, getSession.Body.String())
	}
	refresh := fixture.client.request(t, http.MethodPost, "/refresh-session", map[string]any{}, true)
	if refresh.Code != http.StatusUnauthorized {
		t.Fatalf("refresh response = %d %s", refresh.Code, refresh.Body.String())
	}
	if bytes.Contains(refresh.Body.Bytes(), []byte("private detail")) ||
		bytes.Contains(refresh.Body.Bytes(), []byte("database unavailable")) {
		t.Fatalf("HTTP response leaked adapter failure: %s", refresh.Body.String())
	}
}

func TestResolveSessionConcurrent(t *testing.T) {
	t.Parallel()
	fixture := newResolverFixture(t, nil)
	wantSession, wantUser := fixture.signUp(t, "resolver-race@example.com")

	const readers = 64
	errs := make(chan error, readers)
	var group sync.WaitGroup
	group.Add(readers)
	for index := 0; index < readers; index++ {
		go func() {
			defer group.Done()
			result, err := fixture.server.ResolveSession(
				context.Background(),
				sessionRequest(fixture.client.session),
			)
			if err != nil {
				errs <- err
				return
			}
			if result.Session.ID != wantSession.ID || result.User.ID != wantUser.ID {
				errs <- fmt.Errorf("unexpected result: %#v", result)
			}
		}()
	}
	group.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}
