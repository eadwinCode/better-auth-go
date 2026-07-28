package betterauth

import (
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)

type CookieConfig struct {
	Name     string
	CSRFName string
	Path     string
	SameSite http.SameSite
}

type Config struct {
	BasePath                string
	PublicURL               string
	TrustedOrigins          []string
	Database                DatabaseAdapter
	Schema                  Schema
	Mailer                  Mailer
	RateLimiter             RateLimiter
	ImpersonationAuthorizer ImpersonationAuthorizer
	Passwords               PasswordVerifier
	Clock                   Clock
	Tokens                  TokenSource
	ProviderTokenCipher     TokenCipher
	SocialProviders         map[string]OAuthProvider
	AllowedRedirectURLs     []string
	Cookie                  CookieConfig
	SessionDuration         time.Duration
	ImpersonationDuration   time.Duration
	PasswordResetTTL        time.Duration
	EmailVerificationTTL    time.Duration
	OAuthStateTTL           time.Duration
	ProviderTimeout         time.Duration
	MaxRequestBytes         int64
	MinPasswordBytes        int
	MaxPasswordBytes        int
	TrustProxyHeaders       bool
	Plugins                 []Plugin
	Hooks                   ServerHooks
	BackgroundTasks         BackgroundTaskRunner
	MaxResponseBytes        int64
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now().UTC() }

func (cfg Config) normalized() (Config, map[string]struct{}, map[string]struct{}, error) {
	plugins, err := compilePlugins(cfg.Plugins)
	if err != nil {
		return cfg, nil, nil, err
	}
	cfg.Plugins = plugins
	if cfg.Database == nil {
		return cfg, nil, nil, fmt.Errorf("betterauth: database adapter is required")
	}
	if !cfg.Database.Capabilities().Transactions {
		return cfg, nil, nil, fmt.Errorf("betterauth: enabled core flows require database transactions")
	}
	if cfg.BasePath == "" {
		cfg.BasePath = "/api/auth"
	}
	cfg.BasePath = cleanAbsolutePath(cfg.BasePath)
	if cfg.BasePath == "/" {
		return cfg, nil, nil, fmt.Errorf("betterauth: base path may not be root")
	}
	if cfg.PublicURL == "" {
		return cfg, nil, nil, fmt.Errorf("betterauth: public URL is required")
	}
	publicURL, err := validateHTTPSURL(cfg.PublicURL, false)
	if err != nil {
		return cfg, nil, nil, fmt.Errorf("betterauth: public URL: %w", err)
	}
	cfg.PublicURL = strings.TrimSuffix(publicURL.String(), "/")
	cfg.Schema, cfg.TrustedOrigins, err = initializePlugins(cfg, cfg.Plugins)
	if err != nil {
		return cfg, nil, nil, err
	}
	if err := validateSchema(cfg.Schema); err != nil {
		return cfg, nil, nil, err
	}
	cfg.Database, err = WrapDatabaseAdapter(cfg.Database, cfg.Schema)
	if err != nil {
		return cfg, nil, nil, err
	}
	cfg.Database, err = wrapDatabaseHooks(cfg.Database, cfg.Plugins)
	if err != nil {
		return cfg, nil, nil, err
	}
	if cfg.Mailer == nil {
		return cfg, nil, nil, fmt.Errorf("betterauth: mailer is required")
	}
	if cfg.ImpersonationAuthorizer == nil {
		return cfg, nil, nil, fmt.Errorf("betterauth: impersonation authorizer is required")
	}
	if cfg.RateLimiter == nil {
		cfg.RateLimiter = NopRateLimiter{}
	}
	if cfg.Clock == nil {
		cfg.Clock = systemClock{}
	}
	if cfg.Tokens == nil {
		cfg.Tokens = CryptoTokenSource{}
	}
	if cfg.BackgroundTasks == nil {
		cfg.BackgroundTasks = InlineBackgroundTasks{}
	}
	if len(cfg.TrustedOrigins) == 0 {
		return cfg, nil, nil, fmt.Errorf("betterauth: at least one trusted origin is required")
	}
	origins := make(map[string]struct{}, len(cfg.TrustedOrigins))
	normalizedOrigins := make([]string, 0, len(cfg.TrustedOrigins))
	for _, raw := range cfg.TrustedOrigins {
		origin, err := normalizeOrigin(raw)
		if err != nil {
			return cfg, nil, nil, fmt.Errorf("betterauth: trusted origin %q: %w", raw, err)
		}
		origins[origin] = struct{}{}
		normalizedOrigins = append(normalizedOrigins, origin)
	}
	cfg.TrustedOrigins = normalizedOrigins

	if cfg.Cookie.Name == "" {
		cfg.Cookie.Name = "__Host-better_auth_session"
	}
	if cfg.Cookie.CSRFName == "" {
		cfg.Cookie.CSRFName = "__Host-better_auth_csrf"
	}
	if !strings.HasPrefix(cfg.Cookie.Name, "__Host-") || !strings.HasPrefix(cfg.Cookie.CSRFName, "__Host-") {
		return cfg, nil, nil, fmt.Errorf("betterauth: cookie names must use the __Host- prefix")
	}
	if cfg.Cookie.Path == "" {
		cfg.Cookie.Path = "/"
	}
	if cfg.Cookie.Path != "/" {
		return cfg, nil, nil, fmt.Errorf("betterauth: __Host- cookies require path /")
	}
	if cfg.Cookie.SameSite == 0 {
		cfg.Cookie.SameSite = http.SameSiteLaxMode
	}
	if cfg.Cookie.SameSite != http.SameSiteLaxMode && cfg.Cookie.SameSite != http.SameSiteStrictMode {
		return cfg, nil, nil, fmt.Errorf("betterauth: SameSite must be Lax or Strict")
	}

	if cfg.SessionDuration == 0 {
		cfg.SessionDuration = 30 * 24 * time.Hour
	}
	if cfg.SessionDuration < 5*time.Minute || cfg.SessionDuration > 365*24*time.Hour {
		return cfg, nil, nil, fmt.Errorf("betterauth: session duration is out of bounds")
	}
	if cfg.ImpersonationDuration == 0 {
		cfg.ImpersonationDuration = time.Hour
	}
	if cfg.ImpersonationDuration <= 0 || cfg.ImpersonationDuration > time.Hour {
		return cfg, nil, nil, fmt.Errorf("betterauth: impersonation duration must not exceed one hour")
	}
	if cfg.PasswordResetTTL == 0 {
		cfg.PasswordResetTTL = 30 * time.Minute
	}
	if cfg.EmailVerificationTTL == 0 {
		cfg.EmailVerificationTTL = 24 * time.Hour
	}
	if cfg.OAuthStateTTL == 0 {
		cfg.OAuthStateTTL = 10 * time.Minute
	}
	if cfg.ProviderTimeout == 0 {
		cfg.ProviderTimeout = 15 * time.Second
	}
	if cfg.ProviderTimeout < time.Second || cfg.ProviderTimeout > time.Minute {
		return cfg, nil, nil, fmt.Errorf("betterauth: provider timeout is out of bounds")
	}
	for name, value := range map[string]time.Duration{
		"password reset TTL":     cfg.PasswordResetTTL,
		"email verification TTL": cfg.EmailVerificationTTL,
		"OAuth state TTL":        cfg.OAuthStateTTL,
	} {
		if value < time.Minute || value > 7*24*time.Hour {
			return cfg, nil, nil, fmt.Errorf("betterauth: %s is out of bounds", name)
		}
	}
	if cfg.MaxRequestBytes == 0 {
		cfg.MaxRequestBytes = 64 << 10
	}
	if cfg.MaxRequestBytes < 1024 || cfg.MaxRequestBytes > 1<<20 {
		return cfg, nil, nil, fmt.Errorf("betterauth: max request bytes is out of bounds")
	}
	if cfg.MaxResponseBytes == 0 {
		cfg.MaxResponseBytes = 1 << 20
	}
	if cfg.MaxResponseBytes < 1024 || cfg.MaxResponseBytes > 16<<20 {
		return cfg, nil, nil, fmt.Errorf("betterauth: max response bytes is out of bounds")
	}
	if cfg.MinPasswordBytes == 0 {
		cfg.MinPasswordBytes = 12
	}
	if cfg.MaxPasswordBytes == 0 {
		cfg.MaxPasswordBytes = 1024
	}
	if cfg.MinPasswordBytes < 8 || cfg.MaxPasswordBytes < cfg.MinPasswordBytes || cfg.MaxPasswordBytes > 1<<20 {
		return cfg, nil, nil, fmt.Errorf("betterauth: password length policy is invalid")
	}
	if cfg.Passwords == nil {
		argon, err := NewArgon2idVerifier(DefaultArgon2Params(), cfg.MaxPasswordBytes)
		if err != nil {
			return cfg, nil, nil, err
		}
		cfg.Passwords = argon
	}

	returnTo := map[string]struct{}{}
	if len(cfg.SocialProviders) > 0 && len(cfg.AllowedRedirectURLs) == 0 {
		return cfg, nil, nil, fmt.Errorf("betterauth: allowed redirect URLs are required when social providers are configured")
	}
	if len(cfg.SocialProviders) > 0 && cfg.ProviderTokenCipher == nil {
		return cfg, nil, nil, fmt.Errorf("betterauth: provider token cipher is required when social providers are configured")
	}
	normalizedReturns := make([]string, 0, len(cfg.AllowedRedirectURLs))
	for _, raw := range cfg.AllowedRedirectURLs {
		value, err := validateHTTPSURL(raw, true)
		if err != nil {
			return cfg, nil, nil, fmt.Errorf("betterauth: allowed redirect URL %q: %w", raw, err)
		}
		canonical := value.String()
		returnTo[canonical] = struct{}{}
		normalizedReturns = append(normalizedReturns, canonical)
	}
	cfg.AllowedRedirectURLs = normalizedReturns
	for providerID, provider := range cfg.SocialProviders {
		if provider == nil || !validProviderID(providerID) {
			return cfg, nil, nil, fmt.Errorf("betterauth: invalid social provider %q", providerID)
		}
	}
	cfg.SocialProviders = maps.Clone(cfg.SocialProviders)
	return cfg, origins, returnTo, nil
}

func validProviderID(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, char := range value {
		if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' && char != '_' {
			return false
		}
	}
	return true
}

func cleanAbsolutePath(value string) string {
	if !strings.HasPrefix(value, "/") {
		value = "/" + value
	}
	return strings.TrimSuffix(path.Clean(value), "/")
}

func normalizeOrigin(raw string) (string, error) {
	u, err := validateHTTPSURL(raw, false)
	if err != nil {
		return "", err
	}
	if u.Path != "" && u.Path != "/" {
		return "", fmt.Errorf("origin must not contain a path")
	}
	return u.Scheme + "://" + u.Host, nil
}

func validateHTTPSURL(raw string, allowPath bool) (*url.URL, error) {
	if strings.Contains(raw, "*") {
		return nil, fmt.Errorf("wildcards are not allowed")
	}
	u, err := url.Parse(raw)
	if err != nil || u == nil || !u.IsAbs() || u.Host == "" {
		return nil, fmt.Errorf("must be an absolute URL")
	}
	if u.Scheme != "https" {
		isLoopback := u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1")
		if !isLoopback {
			return nil, fmt.Errorf("must use HTTPS outside loopback development")
		}
	}
	if u.User != nil || u.Fragment != "" || u.RawQuery != "" {
		return nil, fmt.Errorf("credentials, fragments, and query strings are not allowed")
	}
	if !allowPath && u.Path != "" && u.Path != "/" {
		return nil, fmt.Errorf("path is not allowed")
	}
	u.Host = strings.ToLower(u.Host)
	if u.Path == "/" && !allowPath {
		u.Path = ""
	}
	return u, nil
}
