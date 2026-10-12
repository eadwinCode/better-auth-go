package onetimetoken

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	betterauth "github.com/eadwinCode/better-auth-go"
)

const (
	// PluginID matches Better Auth's plugin id.
	PluginID = "one-time-token"
	// HeaderName is the response header used by SetOTTHeaderOnNewSession.
	HeaderName = "set-ott"

	verificationIdentifier = "one-time-token"
	metadataSession        = "session"
)

type runtime struct {
	config Config
}

// Manager exposes the plugin descriptor and the server-only Generate API.
type Manager struct {
	runtime *runtime
}

// New returns the common descriptor-only integration.
func New(config Config) (betterauth.Plugin, error) {
	manager, err := NewManager(config)
	if err != nil {
		return betterauth.Plugin{}, err
	}
	return manager.Plugin(), nil
}

// NewManager returns an integration with the server-only Generate API.
func NewManager(config Config) (*Manager, error) {
	normalized, err := normalizeConfig(config)
	if err != nil {
		return nil, err
	}
	return &Manager{runtime: &runtime{config: normalized}}, nil
}

// Plugin returns the immutable server plugin descriptor.
func (manager *Manager) Plugin() betterauth.Plugin {
	if manager == nil || manager.runtime == nil {
		return betterauth.Plugin{}
	}
	return manager.runtime.plugin()
}

// Generate creates a token for an active session from server code. It is the
// Go form of calling auth.api.generateOneTimeToken on the server, and it works
// when DisableClientRequest is set. session usually comes from
// Server.ResolveSession, and sessionToken is the raw value of the same
// request's session cookie. database must be the adapter the server uses.
func (manager *Manager) Generate(
	ctx context.Context,
	database betterauth.DatabaseAdapter,
	session betterauth.SessionResult,
	sessionToken string,
) (string, error) {
	if manager == nil || manager.runtime == nil || database == nil {
		return "", errors.New("onetimetoken: manager and database are required")
	}
	now := manager.runtime.config.Clock.Now().UTC()
	if sessionToken == "" || session.Session.TokenHash == "" ||
		subtle.ConstantTimeCompare(
			[]byte(betterauth.HashToken(sessionToken)), []byte(session.Session.TokenHash),
		) != 1 ||
		session.Session.RevokedAt != nil || !session.Session.ExpiresAt.After(now) {
		return "", betterauth.ErrNoSession
	}
	return manager.runtime.issue(ctx, database, now, randomID, session, sessionToken)
}

func (instance *runtime) plugin() betterauth.Plugin {
	plugin := betterauth.Plugin{
		ID: PluginID,
		Endpoints: []betterauth.PluginEndpoint{
			{
				Name: "generateOneTimeToken", Path: "/one-time-token/generate",
				Method:  http.MethodGet,
				Use:     []betterauth.RequestHook{betterauth.SessionMiddleware},
				Handler: instance.generate,
			},
			{
				Name: "verifyOneTimeToken", Path: "/one-time-token/verify",
				Method: http.MethodPost,
				// Better Auth checks the Origin only when the request carries
				// cookies, so server-to-server callers need not send one.
				// cookieOriginCheck applies that same rule.
				SkipOriginCheck: true,
				Use:             []betterauth.RequestHook{cookieOriginCheck},
				BodyValidator: betterauth.ObjectValidator{
					Fields: map[string]betterauth.FieldValidation{
						"token": {
							Kind: betterauth.ValidationString, Required: true,
							MaxLength: maxTokenLength,
						},
					},
					// Better Auth's body schema ignores unknown fields.
					AllowUnknown: true,
				},
				Handler: instance.verify,
			},
		},
	}
	if instance.config.SetOTTHeaderOnNewSession {
		plugin.After = []betterauth.PluginAfterHook{{Handler: instance.attachHeader}}
	}
	return plugin
}

func (instance *runtime) generate(context *betterauth.HookContext) (*betterauth.PluginResponse, error) {
	if instance.config.DisableClientRequest {
		return nil, badRequest("Client requests are disabled")
	}
	cookie, err := context.Request.Cookie(context.Cookies.Name)
	if err != nil || context.Session == nil || context.User == nil ||
		subtle.ConstantTimeCompare(
			[]byte(betterauth.HashToken(cookie.Value)), []byte(context.Session.TokenHash),
		) != 1 {
		return nil, betterauth.NewError(
			betterauth.CodeUnauthorized, "Authentication required.", http.StatusUnauthorized, err,
		)
	}
	token, err := instance.issue(
		context.Context, context.Database, context.Clock.Now().UTC(), context.GenerateID,
		betterauth.SessionResult{Session: *context.Session, User: *context.User}, cookie.Value,
	)
	if err != nil {
		return nil, err
	}
	return betterauth.JSONResponse(http.StatusOK, map[string]string{"token": token})
}

// cookieOriginCheck requires a trusted Origin when the request carries
// cookies, like Better Auth's origin check. It runs before the token is
// consumed, so a rejected request does not burn the token.
func cookieOriginCheck(context *betterauth.HookContext) (*betterauth.PluginResponse, error) {
	if context.Headers.Get("Cookie") == "" {
		return nil, nil
	}
	origin := betterauth.InferNullOrigin(context.Request, context.BaseURL)
	if origin == "" || origin == "null" || context.IsTrustedOrigin == nil || !context.IsTrustedOrigin(origin) {
		return nil, betterauth.NewError(
			betterauth.CodeInvalidOrigin, "Invalid origin", http.StatusForbidden, nil,
		)
	}
	return nil, nil
}

func (instance *runtime) verify(context *betterauth.HookContext) (*betterauth.PluginResponse, error) {
	body, _ := context.Body.(map[string]any)
	token, _ := body["token"].(string)
	stored, err := instance.storedValue(context.Context, token)
	if err != nil {
		return nil, err
	}
	// Deleting the record and reading it are one step, so two concurrent
	// redemptions of the same token cannot both succeed.
	row, err := context.Database.ConsumeOne(context.Context, betterauth.DeleteQuery{
		Model: betterauth.ModelVerification,
		Where: []betterauth.Where{
			betterauth.Eq("identifier", verificationIdentifier),
			betterauth.Eq("value", stored),
			{Field: "expiresAt", Operator: betterauth.WhereGT, Value: context.Clock.Now().UTC()},
		},
	})
	if err != nil && !errors.Is(err, betterauth.ErrNotFound) {
		return nil, err
	}
	if row == nil {
		return nil, badRequest("Invalid token")
	}
	rawSession, err := openSession(token, stored, metadataString(row["metadata"], metadataSession))
	if err != nil {
		return nil, badRequest("Invalid token")
	}
	issued, err := context.ResumeSession(rawSession)
	switch {
	case errors.Is(err, betterauth.ErrSessionExpired):
		return nil, badRequest("Session expired")
	case errors.Is(err, betterauth.ErrNoSession):
		return nil, badRequest("Session not found")
	case err != nil:
		return nil, err
	}
	response, err := betterauth.JSONResponse(http.StatusOK, issued)
	if err != nil {
		return nil, err
	}
	if !instance.config.DisableSetSessionCookie {
		if err := issued.Apply(response); err != nil {
			return nil, err
		}
	}
	return response, nil
}

// attachHeader adds a token for any session cookie the response sets, like
// Better Auth does for every new session when setOttHeaderOnNewSession is on.
func (instance *runtime) attachHeader(
	context *betterauth.HookContext,
	response *betterauth.PluginResponse,
) error {
	rawSession := responseSessionToken(response, context.Cookies.Name)
	if rawSession == "" {
		return nil
	}
	issued, err := context.ResumeSession(rawSession)
	if errors.Is(err, betterauth.ErrNoSession) {
		// Another hook may have revoked the session (two-factor does this
		// for a provisional sign-in). A token for it would never verify.
		return nil
	}
	if err != nil {
		return err
	}
	token, err := instance.issue(
		context.Context, context.Database, context.Clock.Now().UTC(), context.GenerateID,
		betterauth.SessionResult{Session: issued.Session, User: issued.User}, rawSession,
	)
	if err != nil {
		return err
	}
	exposed := []string{}
	seen := map[string]bool{}
	for _, value := range response.Headers.Values("Access-Control-Expose-Headers") {
		for _, name := range strings.Split(value, ",") {
			name = strings.TrimSpace(name)
			if name != "" && !seen[strings.ToLower(name)] {
				seen[strings.ToLower(name)] = true
				exposed = append(exposed, name)
			}
		}
	}
	if !seen[HeaderName] {
		exposed = append(exposed, HeaderName)
	}
	response.Headers.Set(HeaderName, token)
	response.Headers.Set("Access-Control-Expose-Headers", strings.Join(exposed, ", "))
	return nil
}

// issue creates and stores a token for a session. The verification record
// keeps the session token sealed under a key derived from the one-time
// token, so the database alone never reveals a usable session token.
func (instance *runtime) issue(
	ctx context.Context,
	database betterauth.DatabaseAdapter,
	now time.Time,
	generateID func() (string, error),
	session betterauth.SessionResult,
	rawSession string,
) (string, error) {
	var token string
	var err error
	if instance.config.GenerateToken != nil {
		token, err = instance.config.GenerateToken(ctx, session)
		if err != nil {
			return "", fmt.Errorf("onetimetoken: generate token: %w", err)
		}
		if token == "" || len(token) > maxTokenLength {
			return "", errors.New("onetimetoken: generated token is empty or too long")
		}
	} else if token, err = randomToken(); err != nil {
		return "", err
	}
	stored, err := instance.storedValue(ctx, token)
	if err != nil {
		return "", err
	}
	sealed, err := sealSession(token, stored, rawSession)
	if err != nil {
		return "", err
	}
	id, err := generateID()
	if err != nil {
		return "", err
	}
	_, err = database.Create(ctx, betterauth.CreateQuery{
		Model: betterauth.ModelVerification, ForceAllowID: true,
		Data: betterauth.Record{
			"id": id, "identifier": verificationIdentifier, "value": stored,
			"expiresAt": now.Add(instance.config.ExpiresIn), "createdAt": now,
			"metadata": map[string]any{metadataSession: sealed},
		},
	})
	if err != nil {
		return "", fmt.Errorf("onetimetoken: store token: %w", err)
	}
	return token, nil
}

func (instance *runtime) storedValue(ctx context.Context, token string) (string, error) {
	switch instance.config.StoreToken {
	case TokenStoragePlain:
		return token, nil
	case TokenStorageCustom:
		stored, err := instance.config.HashToken(ctx, token)
		if err != nil {
			return "", fmt.Errorf("onetimetoken: hash token: %w", err)
		}
		if stored == "" {
			return "", errors.New("onetimetoken: hashed token is empty")
		}
		return stored, nil
	default:
		return betterauth.HashToken(token), nil
	}
}

// randomToken returns 32 characters from the same URL-safe alphabet Better
// Auth uses (a-z, A-Z, 0-9, "-" and "_"), carrying 192 random bits.
func randomToken() (string, error) {
	value := make([]byte, 24)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("onetimetoken: random token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func randomID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("onetimetoken: random id: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func responseSessionToken(response *betterauth.PluginResponse, name string) string {
	if response == nil {
		return ""
	}
	found := ""
	for _, value := range response.Headers.Values("Set-Cookie") {
		cookie, err := http.ParseSetCookie(value)
		if err != nil || cookie.Name != name {
			continue
		}
		if cookie.Value == "" || cookie.MaxAge < 0 {
			found = ""
			continue
		}
		found = cookie.Value
	}
	return found
}

func metadataString(metadata any, key string) string {
	switch typed := metadata.(type) {
	case betterauth.Record:
		value, _ := typed[key].(string)
		return value
	case map[string]any:
		value, _ := typed[key].(string)
		return value
	case map[string]string:
		return typed[key]
	default:
		return ""
	}
}

func badRequest(message string) error {
	return betterauth.NewError(betterauth.CodeBadRequest, message, http.StatusBadRequest, nil)
}
