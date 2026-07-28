package betterauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

// HookMatcher selects requests using their normalized path and request-scoped
// context. A nil matcher selects every request.
type HookMatcher func(*HookContext) bool

// RequestHook runs before an endpoint. A non-nil response stops the remaining
// request pipeline and becomes the response.
type RequestHook func(*HookContext) (*PluginResponse, error)

// ResponseHook runs after an endpoint and may replace response fields.
type ResponseHook func(*HookContext, *PluginResponse) error

// PluginEndpointHandler serves one plugin endpoint.
type PluginEndpointHandler func(*HookContext) (*PluginResponse, error)

// EndpointValidator validates a decoded endpoint input. Body validators
// receive JSON-compatible values; query validators receive url.Values.
// Implementations must be concurrency-safe.
type EndpointValidator interface {
	Validate(any) error
}

// EndpointValidatorFunc adapts a function to EndpointValidator.
type EndpointValidatorFunc func(any) error

func (validator EndpointValidatorFunc) Validate(value any) error {
	if validator == nil {
		return errors.New("betterauth: endpoint validator is nil")
	}
	return validator(value)
}

// PluginEndpoint declares a collision-checked HTTP route relative to the
// configured authentication base path. SkipOriginCheck is only for
// non-browser protocol callbacks or bearer-authenticated endpoints; enabling it
// does not skip endpoint middleware, validators, hooks, or rate limits.
type PluginEndpoint struct {
	Name            string
	Path            string
	Method          string
	SkipOriginCheck bool
	// AllowNonKebabPath permits protocol-mandated case-sensitive literals such
	// as SCIM's ServiceProviderConfig. Ordinary plugin routes should remain
	// lowercase kebab-case.
	AllowNonKebabPath bool
	Use               []RequestHook
	BodyValidator     EndpointValidator
	QueryValidator    EndpointValidator
	Handler           PluginEndpointHandler
}

// PluginMiddleware runs before endpoint-specific middleware and before hooks.
type PluginMiddleware struct {
	Matcher HookMatcher
	Handler RequestHook
}

// PluginBeforeHook runs immediately before a matching endpoint.
type PluginBeforeHook struct {
	Matcher HookMatcher
	Handler RequestHook
}

// PluginAfterHook runs after a matching endpoint has returned a response.
type PluginAfterHook struct {
	Matcher HookMatcher
	Handler ResponseHook
}

// PluginRateLimitRule adds a matcher-specific rule to the configured limiter.
type PluginRateLimitRule struct {
	Matcher    HookMatcher
	Action     string
	AccountKey func(*HookContext) string
	Window     time.Duration
	Max        int
}

// BackgroundTask is submitted through an application-owned runner. The
// request context passed to Submit is detached from cancellation before Run.
type BackgroundTask func(context.Context) error

// BackgroundTaskRunner accepts request-detached non-critical work.
type BackgroundTaskRunner interface {
	Submit(context.Context, BackgroundTask) error
}

// InlineBackgroundTasks runs submitted work synchronously with cancellation
// detached. Applications can replace it with a durable asynchronous runner.
type InlineBackgroundTasks struct{}

func (InlineBackgroundTasks) Submit(ctx context.Context, task BackgroundTask) error {
	return task(context.WithoutCancel(ctx))
}

// PluginInitContext contains immutable construction-time capabilities.
type PluginInitContext struct {
	PluginID       string
	BaseURL        string
	Database       DatabaseAdapter
	Schema         Schema
	TrustedOrigins []string
}

// PluginInitResult contains validated contributions produced at construction.
type PluginInitResult struct {
	Schema         Schema
	TrustedOrigins []string
}

// PluginInit initializes a plugin once during New.
type PluginInit func(PluginInitContext) (PluginInitResult, error)

// ServerHooks configures application-owned lifecycle hooks outside a plugin.
type ServerHooks struct {
	OnRequest  RequestHook
	Before     []PluginBeforeHook
	After      []PluginAfterHook
	OnResponse ResponseHook
}

// Plugin is an immutable descriptor compiled during New. Callbacks must be
// concurrency-safe and must not retain HookContext values.
type Plugin struct {
	ID             string
	Dependencies   []string
	Init           PluginInit
	Schema         Schema
	Endpoints      []PluginEndpoint
	Middlewares    []PluginMiddleware
	Before         []PluginBeforeHook
	After          []PluginAfterHook
	OnRequest      RequestHook
	OnResponse     ResponseHook
	TrustedOrigins []string
	RateLimits     []PluginRateLimitRule
	DatabaseHooks  []DatabaseHook
}

// HookContext is unique to one request.
type HookContext struct {
	Context         context.Context
	Request         *http.Request
	Path            string
	PluginID        string
	Params          map[string]string
	Headers         http.Header
	Query           url.Values
	Body            any
	RawBody         []byte
	Database        DatabaseAdapter
	Clock           Clock
	BaseURL         string
	Schema          Schema
	Cookies         CookieConfig
	Passwords       PasswordVerifier
	TrustedOrigins  []string
	SessionFreshAge time.Duration
	Session         *Session
	User            *User
	Response        *PluginResponse
	Failure         error
	GenerateID      func() (string, error)
	GenerateToken   func(int) (string, error)
	IsTrustedOrigin func(string) bool
	ValidateCSRF    func() error
	IssueSession    func(string) (*IssuedSession, error)
	BackgroundTasks BackgroundTaskRunner
	bodyDecodeError error
}

func (ctx *HookContext) RunInBackground(task BackgroundTask) error {
	if task == nil {
		return errors.New("betterauth: background task is nil")
	}
	return ctx.BackgroundTasks.Submit(ctx.Context, task)
}

type PluginResponse struct {
	Status  int
	Headers http.Header
	Body    []byte
}

// IssuedSession is the result of a plugin authentication transition. Bearer
// values remain private and can only be attached to a response through Apply.
type IssuedSession struct {
	Session Session `json:"session"`
	User    User    `json:"user"`
	cookies []*http.Cookie
	csrf    string
}

// Apply attaches the secure session transition to a plugin response. It may be
// called once; a second call fails instead of duplicating bearer cookies.
func (issued *IssuedSession) Apply(response *PluginResponse) error {
	if issued == nil {
		return errors.New("betterauth: issued session is nil")
	}
	if response == nil {
		return errors.New("betterauth: plugin response is nil")
	}
	if len(issued.cookies) == 0 {
		return errors.New("betterauth: issued session was already applied")
	}
	if response.Headers == nil {
		response.Headers = make(http.Header)
	}
	for _, cookie := range issued.cookies {
		if cookie == nil || !strings.HasPrefix(cookie.Name, "__Host-") ||
			!cookie.Secure || cookie.Domain != "" || cookie.Path != "/" ||
			(cookie.SameSite != http.SameSiteLaxMode &&
				cookie.SameSite != http.SameSiteStrictMode) {
			return errors.New("betterauth: invalid issued session cookie")
		}
		if err := cookie.Valid(); err != nil {
			return fmt.Errorf("betterauth: invalid issued session cookie: %w", err)
		}
		response.Headers.Add("Set-Cookie", cookie.String())
	}
	if issued.csrf != "" {
		response.Headers.Set("X-CSRF-Token", issued.csrf)
	}
	issued.cookies = nil
	issued.csrf = ""
	return nil
}

// SetCookie appends a secure, host-only cookie to a plugin response. Plugin
// cookies use the __Host- prefix so they cannot be scoped to a parent domain or
// a path outside the authentication server.
func (response *PluginResponse) SetCookie(cookie *http.Cookie) error {
	if response == nil {
		return errors.New("betterauth: plugin response is nil")
	}
	if cookie == nil {
		return errors.New("betterauth: plugin cookie is nil")
	}
	if !strings.HasPrefix(cookie.Name, "__Host-") || !cookie.Secure || !cookie.HttpOnly ||
		cookie.Domain != "" || cookie.Path != "/" ||
		(cookie.SameSite != http.SameSiteLaxMode && cookie.SameSite != http.SameSiteStrictMode) {
		return errors.New(
			"betterauth: plugin cookie must be __Host-, Secure, HttpOnly, host-only, Path=/, and SameSite Lax or Strict",
		)
	}
	if err := cookie.Valid(); err != nil {
		return fmt.Errorf("betterauth: invalid plugin cookie: %w", err)
	}
	if response.Headers == nil {
		response.Headers = make(http.Header)
	}
	response.Headers.Add("Set-Cookie", cookie.String())
	return nil
}

// JSONResponse creates a JSON plugin response.
func JSONResponse(status int, value any) (*PluginResponse, error) {
	body, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("betterauth: encode plugin response: %w", err)
	}
	body = append(body, '\n')
	return &PluginResponse{
		Status: status,
		Headers: http.Header{
			"Content-Type": []string{"application/json; charset=utf-8"},
		},
		Body: body,
	}, nil
}

// DecodeJSON decodes a plugin response body and rejects unknown fields.
func (response *PluginResponse) DecodeJSON(dst any) error {
	if response == nil {
		return errors.New("betterauth: plugin response is nil")
	}
	decoder := json.NewDecoder(strings.NewReader(string(response.Body)))
	decoder.DisallowUnknownFields()
	return decoder.Decode(dst)
}

// SetJSON replaces a plugin response body with encoded JSON.
func (response *PluginResponse) SetJSON(value any) error {
	encoded, err := JSONResponse(response.Status, value)
	if err != nil {
		return err
	}
	response.Body = encoded.Body
	if response.Headers == nil {
		response.Headers = make(http.Header)
	}
	response.Headers.Set("Content-Type", "application/json; charset=utf-8")
	return nil
}

type compiledEndpoint struct {
	pluginID string
	endpoint PluginEndpoint
	template string
	shape    string
}

type compiledRequestHook struct {
	pluginID string
	matcher  HookMatcher
	handler  RequestHook
}

type compiledResponseHook struct {
	pluginID string
	matcher  HookMatcher
	handler  ResponseHook
}

type compiledRateLimit struct {
	pluginID string
	rule     PluginRateLimitRule
}

type pluginRuntime struct {
	plugins     []Plugin
	endpoints   map[string]map[string]compiledEndpoint
	dynamic     []compiledEndpoint
	onRequest   []compiledRequestHook
	middlewares []compiledRequestHook
	before      []compiledRequestHook
	after       []compiledResponseHook
	onResponse  []compiledResponseHook
	rateLimits  []compiledRateLimit
}

func compilePlugins(plugins []Plugin) ([]Plugin, error) {
	if len(plugins) == 0 {
		return nil, nil
	}
	byID := make(map[string]Plugin, len(plugins))
	index := make(map[string]int, len(plugins))
	for position, plugin := range plugins {
		plugin = clonePluginDescriptor(plugin)
		plugin.ID = strings.TrimSpace(plugin.ID)
		if !validPluginID(plugin.ID) {
			return nil, fmt.Errorf("betterauth: invalid plugin id %q", plugin.ID)
		}
		if _, exists := byID[plugin.ID]; exists {
			return nil, fmt.Errorf("betterauth: duplicate plugin id %q", plugin.ID)
		}
		plugin.Dependencies = slices.Clone(plugin.Dependencies)
		byID[plugin.ID] = plugin
		index[plugin.ID] = position
	}
	visited := make(map[string]uint8, len(plugins))
	ordered := make([]Plugin, 0, len(plugins))
	var visit func(string) error
	visit = func(id string) error {
		switch visited[id] {
		case 1:
			return fmt.Errorf("betterauth: plugin dependency cycle includes %q", id)
		case 2:
			return nil
		}
		plugin, exists := byID[id]
		if !exists {
			return fmt.Errorf("betterauth: plugin dependency %q is not configured", id)
		}
		visited[id] = 1
		dependencies := slices.Clone(plugin.Dependencies)
		slices.SortStableFunc(dependencies, func(a, b string) int {
			return index[a] - index[b]
		})
		for _, dependency := range dependencies {
			if dependency == id {
				return fmt.Errorf("betterauth: plugin %q depends on itself", id)
			}
			if err := visit(dependency); err != nil {
				return err
			}
		}
		visited[id] = 2
		ordered = append(ordered, plugin)
		return nil
	}
	for _, plugin := range plugins {
		if err := visit(plugin.ID); err != nil {
			return nil, err
		}
	}
	return ordered, nil
}

func clonePluginDescriptor(plugin Plugin) Plugin {
	plugin.Dependencies = slices.Clone(plugin.Dependencies)
	plugin.Schema = cloneSchema(plugin.Schema)
	plugin.Endpoints = slices.Clone(plugin.Endpoints)
	for index := range plugin.Endpoints {
		plugin.Endpoints[index].Use = slices.Clone(plugin.Endpoints[index].Use)
		plugin.Endpoints[index].BodyValidator = cloneEndpointValidator(plugin.Endpoints[index].BodyValidator)
		plugin.Endpoints[index].QueryValidator = cloneEndpointValidator(plugin.Endpoints[index].QueryValidator)
	}
	plugin.Middlewares = slices.Clone(plugin.Middlewares)
	plugin.Before = slices.Clone(plugin.Before)
	plugin.After = slices.Clone(plugin.After)
	plugin.TrustedOrigins = slices.Clone(plugin.TrustedOrigins)
	plugin.RateLimits = slices.Clone(plugin.RateLimits)
	plugin.DatabaseHooks = slices.Clone(plugin.DatabaseHooks)
	for index := range plugin.DatabaseHooks {
		plugin.DatabaseHooks[index].Operations = slices.Clone(plugin.DatabaseHooks[index].Operations)
	}
	return plugin
}

func newPluginRuntime(plugins []Plugin, application ServerHooks) (pluginRuntime, error) {
	runtime := pluginRuntime{
		plugins:   slices.Clone(plugins),
		endpoints: make(map[string]map[string]compiledEndpoint),
	}
	if application.OnRequest != nil {
		runtime.onRequest = append(runtime.onRequest, compiledRequestHook{
			pluginID: "application", handler: application.OnRequest,
		})
	}
	if application.OnResponse != nil {
		runtime.onResponse = append(runtime.onResponse, compiledResponseHook{
			pluginID: "application", handler: application.OnResponse,
		})
	}
	for _, hook := range application.Before {
		if hook.Handler == nil {
			return pluginRuntime{}, errors.New("betterauth: application has nil before hook")
		}
		runtime.before = append(runtime.before, compiledRequestHook{
			pluginID: "application", matcher: hook.Matcher, handler: hook.Handler,
		})
	}
	for _, plugin := range plugins {
		if plugin.OnRequest != nil {
			runtime.onRequest = append(runtime.onRequest, compiledRequestHook{
				pluginID: plugin.ID, handler: plugin.OnRequest,
			})
		}
		if plugin.OnResponse != nil {
			runtime.onResponse = append(runtime.onResponse, compiledResponseHook{
				pluginID: plugin.ID, handler: plugin.OnResponse,
			})
		}
		for _, endpoint := range plugin.Endpoints {
			endpoint.Path = cleanAbsolutePath(endpoint.Path)
			endpoint.Method = strings.ToUpper(strings.TrimSpace(endpoint.Method))
			if endpoint.Path == "/" || endpoint.Handler == nil ||
				!slices.Contains([]string{
					http.MethodGet, http.MethodPost, http.MethodPut,
					http.MethodPatch, http.MethodDelete,
				}, endpoint.Method) {
				return pluginRuntime{}, fmt.Errorf("betterauth: plugin %q has an invalid endpoint", plugin.ID)
			}
			if isCoreRoute(endpoint.Path) || strings.HasPrefix(endpoint.Path, "/callback/") {
				return pluginRuntime{}, fmt.Errorf("betterauth: plugin %q endpoint collides with core route %q", plugin.ID, endpoint.Path)
			}
			for _, middleware := range endpoint.Use {
				if middleware == nil {
					return pluginRuntime{}, fmt.Errorf("betterauth: plugin %q endpoint has nil middleware", plugin.ID)
				}
			}
			for _, validator := range []EndpointValidator{endpoint.BodyValidator, endpoint.QueryValidator} {
				if configurable, ok := validator.(interface{ ValidateConfiguration() error }); ok {
					if err := configurable.ValidateConfiguration(); err != nil {
						return pluginRuntime{}, fmt.Errorf(
							"betterauth: plugin %q endpoint validator: %w", plugin.ID, err,
						)
					}
				}
			}
			shape, dynamic, err := pluginPathShape(
				endpoint.Path, endpoint.AllowNonKebabPath,
			)
			if err != nil {
				return pluginRuntime{}, fmt.Errorf("betterauth: plugin %q endpoint: %w", plugin.ID, err)
			}
			if dynamic {
				for _, existing := range runtime.dynamic {
					if existing.endpoint.Method == endpoint.Method &&
						templatesOverlap(existing.template, endpoint.Path) {
						return pluginRuntime{}, fmt.Errorf(
							"betterauth: overlapping plugin endpoint templates %s %s and %s",
							endpoint.Method, existing.template, endpoint.Path,
						)
					}
				}
				for _, corePath := range coreRoutePaths() {
					if _, matches := matchPluginPath(endpoint.Path, corePath); matches {
						return pluginRuntime{}, fmt.Errorf(
							"betterauth: plugin %q endpoint can shadow core route %q", plugin.ID, corePath,
						)
					}
				}
				runtime.dynamic = append(runtime.dynamic, compiledEndpoint{
					pluginID: plugin.ID, endpoint: endpoint, template: endpoint.Path, shape: shape,
				})
				continue
			}
			methods := runtime.endpoints[endpoint.Path]
			if methods == nil {
				methods = make(map[string]compiledEndpoint)
				runtime.endpoints[endpoint.Path] = methods
			}
			if _, exists := methods[endpoint.Method]; exists {
				return pluginRuntime{}, fmt.Errorf("betterauth: duplicate plugin endpoint %s %s", endpoint.Method, endpoint.Path)
			}
			methods[endpoint.Method] = compiledEndpoint{
				pluginID: plugin.ID, endpoint: endpoint, template: endpoint.Path, shape: shape,
			}
		}
		for _, middleware := range plugin.Middlewares {
			if middleware.Handler == nil {
				return pluginRuntime{}, fmt.Errorf("betterauth: plugin %q has nil middleware", plugin.ID)
			}
			runtime.middlewares = append(runtime.middlewares, compiledRequestHook{
				pluginID: plugin.ID, matcher: middleware.Matcher, handler: middleware.Handler,
			})
		}
		for _, hook := range plugin.Before {
			if hook.Handler == nil {
				return pluginRuntime{}, fmt.Errorf("betterauth: plugin %q has nil before hook", plugin.ID)
			}
			runtime.before = append(runtime.before, compiledRequestHook{
				pluginID: plugin.ID, matcher: hook.Matcher, handler: hook.Handler,
			})
		}
		for _, hook := range plugin.After {
			if hook.Handler == nil {
				return pluginRuntime{}, fmt.Errorf("betterauth: plugin %q has nil after hook", plugin.ID)
			}
			runtime.after = append(runtime.after, compiledResponseHook{
				pluginID: plugin.ID, matcher: hook.Matcher, handler: hook.Handler,
			})
		}
		for _, rule := range plugin.RateLimits {
			if rule.Action == "" || rule.Max <= 0 || rule.Window <= 0 {
				return pluginRuntime{}, fmt.Errorf("betterauth: plugin %q has invalid rate-limit rule", plugin.ID)
			}
			runtime.rateLimits = append(runtime.rateLimits, compiledRateLimit{pluginID: plugin.ID, rule: rule})
		}
	}
	for _, hook := range application.After {
		if hook.Handler == nil {
			return pluginRuntime{}, errors.New("betterauth: application has nil after hook")
		}
		runtime.after = append(runtime.after, compiledResponseHook{
			pluginID: "application", matcher: hook.Matcher, handler: hook.Handler,
		})
	}
	slices.Reverse(runtime.onResponse)
	return runtime, nil
}

func validPluginID(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, char := range value {
		if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
			return false
		}
	}
	return true
}

func isCoreRoute(path string) bool {
	switch path {
	case "/sign-up/email", "/sign-in/email", "/sign-out", "/get-session",
		"/list-sessions", "/refresh-session", "/revoke-session",
		"/revoke-other-sessions", "/revoke-sessions", "/update-session",
		"/update-user", "/change-email", "/delete-user", "/delete-user/callback",
		"/change-password",
		"/list-accounts", "/link-social", "/unlink-account",
		"/get-access-token", "/refresh-token",
		"/sign-in/social",
		"/request-password-reset", "/forget-password", "/reset-password",
		"/send-verification-email",
		"/verify-email", "/admin/impersonate-user", "/admin/stop-impersonating":
		return true
	default:
		return false
	}
}

func coreRoutePaths() []string {
	return []string{
		"/sign-up/email", "/sign-in/email", "/sign-out", "/get-session",
		"/list-sessions", "/refresh-session", "/revoke-session",
		"/revoke-other-sessions", "/revoke-sessions", "/update-session",
		"/update-user", "/change-email", "/delete-user", "/delete-user/callback",
		"/change-password",
		"/list-accounts", "/link-social", "/unlink-account",
		"/get-access-token", "/refresh-token",
		"/sign-in/social",
		"/request-password-reset", "/forget-password", "/reset-password",
		"/reset-password/:token", "/send-verification-email",
		"/verify-email", "/admin/impersonate-user", "/admin/stop-impersonating",
	}
}

func pluginPathShape(path string, allowNonKebab bool) (string, bool, error) {
	segments := strings.Split(strings.TrimPrefix(path, "/"), "/")
	dynamic := false
	for index, segment := range segments {
		if strings.HasPrefix(segment, ":") {
			name := strings.TrimPrefix(segment, ":")
			if !validPathParameter(name) {
				return "", false, fmt.Errorf("invalid path parameter %q", segment)
			}
			segments[index] = ":"
			dynamic = true
			continue
		}
		if strings.HasPrefix(segment, "*") {
			name := strings.TrimPrefix(segment, "*")
			if index != len(segments)-1 || !validPathParameter(name) {
				return "", false, fmt.Errorf("invalid wildcard parameter %q", segment)
			}
			segments[index] = "*"
			dynamic = true
			continue
		}
		if !validLiteralPathSegment(segment, allowNonKebab) {
			return "", false, fmt.Errorf("invalid literal path segment %q", segment)
		}
	}
	return "/" + strings.Join(segments, "/"), dynamic, nil
}

func validLiteralPathSegment(value string, allowNonKebab bool) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, char := range value {
		upper := allowNonKebab && char >= 'A' && char <= 'Z'
		if !upper && (char < 'a' || char > 'z') &&
			(char < '0' || char > '9') && char != '-' {
			return false
		}
	}
	return true
}

func matchPluginPath(template, path string) (map[string]string, bool) {
	templateSegments := strings.Split(strings.TrimPrefix(template, "/"), "/")
	pathSegments := strings.Split(strings.TrimPrefix(path, "/"), "/")
	params := make(map[string]string)
	for index, templateSegment := range templateSegments {
		if strings.HasPrefix(templateSegment, "*") {
			params[strings.TrimPrefix(templateSegment, "*")] = strings.Join(pathSegments[index:], "/")
			return params, true
		}
		if index >= len(pathSegments) {
			return nil, false
		}
		if strings.HasPrefix(templateSegment, ":") {
			if pathSegments[index] == "" {
				return nil, false
			}
			params[strings.TrimPrefix(templateSegment, ":")] = pathSegments[index]
		} else if templateSegment != pathSegments[index] {
			return nil, false
		}
	}
	return params, len(templateSegments) == len(pathSegments)
}

func validPathParameter(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, char := range value {
		if (char < 'a' || char > 'z') && (char < 'A' || char > 'Z') &&
			(char < '0' || char > '9') && char != '_' {
			return false
		}
	}
	return true
}

func templatesOverlap(first, second string) bool {
	a := strings.Split(strings.TrimPrefix(first, "/"), "/")
	b := strings.Split(strings.TrimPrefix(second, "/"), "/")
	limit := min(len(a), len(b))
	for index := 0; index < limit; index++ {
		if strings.HasPrefix(a[index], "*") || strings.HasPrefix(b[index], "*") {
			return true
		}
		aDynamic := strings.HasPrefix(a[index], ":")
		bDynamic := strings.HasPrefix(b[index], ":")
		if !aDynamic && !bDynamic && a[index] != b[index] {
			return false
		}
	}
	return len(a) == len(b)
}

func initializePlugins(cfg Config, plugins []Plugin) (Schema, []string, error) {
	schema, err := MergeSchema(CoreSchema(), cfg.Schema)
	if err != nil {
		return nil, nil, err
	}
	origins := slices.Clone(cfg.TrustedOrigins)
	basePath := cfg.BasePath
	if basePath == "" {
		basePath = "/api/auth"
	}
	baseURL := strings.TrimSuffix(cfg.PublicURL, "/") + cleanAbsolutePath(basePath)
	for _, plugin := range plugins {
		if plugin.Schema != nil {
			schema, err = MergeSchema(schema, plugin.Schema)
			if err != nil {
				return nil, nil, fmt.Errorf("betterauth: plugin %q schema: %w", plugin.ID, err)
			}
		}
		origins = append(origins, plugin.TrustedOrigins...)
		if plugin.Init == nil {
			continue
		}
		result, err := callPluginInit(plugin, PluginInitContext{
			PluginID: plugin.ID, BaseURL: baseURL, Database: cfg.Database,
			Schema: cloneSchema(schema), TrustedOrigins: slices.Clone(origins),
		})
		if err != nil {
			return nil, nil, err
		}
		if result.Schema != nil {
			schema, err = MergeSchema(schema, result.Schema)
			if err != nil {
				return nil, nil, fmt.Errorf("betterauth: plugin %q init schema: %w", plugin.ID, err)
			}
		}
		origins = append(origins, result.TrustedOrigins...)
	}
	return schema, origins, nil
}

func callPluginInit(plugin Plugin, context PluginInitContext) (result PluginInitResult, err error) {
	defer func() {
		if recover() != nil {
			err = fmt.Errorf("betterauth: plugin %q init panicked", plugin.ID)
		}
	}()
	result, err = plugin.Init(context)
	if err != nil {
		return PluginInitResult{}, fmt.Errorf("betterauth: plugin %q init: %w", plugin.ID, err)
	}
	return result, nil
}

func cloneSchema(schema Schema) Schema {
	if schema == nil {
		return nil
	}
	result := make(Schema, len(schema))
	for name, model := range schema {
		model.Fields = maps.Clone(model.Fields)
		model.Indexes = cloneIndexes(model.Indexes)
		result[name] = model
	}
	return result
}
