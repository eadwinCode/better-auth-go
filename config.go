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

type AccountManagementConfig struct {
	// UpdateAccountOnSignIn controls whether returning-provider sign-in writes
	// the latest provider tokens. Nil defaults to true.
	UpdateAccountOnSignIn *bool
	// LinkingEnabled controls explicit and implicit provider linking. Nil
	// defaults to true, matching Better Auth v1.6.
	LinkingEnabled *bool
	// DisableImplicitLinking prevents a social sign-in from attaching a new
	// provider identity to an existing same-email user. Explicit link-social
	// remains available when linking itself is enabled.
	DisableImplicitLinking bool
	// TrustedProviders is an immutable allowlist whose configured provider is
	// accepted as verified identity evidence even when its profile omits an
	// emailVerified flag.
	TrustedProviders []string
	// TrustedProviderResolver is the request-dependent v1.6 alternative to the
	// static TrustedProviders list. Configuring both fails closed.
	TrustedProviderResolver TrustedProviderResolver
	// RequireLocalEmailVerified protects implicit same-email linking. Nil
	// defaults to true.
	RequireLocalEmailVerified *bool
	// UpdateUserInfoOnLink copies non-identity name/image fields from a newly
	// linked provider profile. Email and verification state are never changed.
	UpdateUserInfoOnLink bool
	// AllowUnlinkingAll permits removal of the final sign-in method. The secure
	// default is false so a user cannot accidentally make their account
	// unreachable.
	AllowUnlinkingAll bool
	// AllowLinkingDifferentEmails permits an authenticated user to link a
	// provider identity whose verified email differs from the current user.
	AllowLinkingDifferentEmails bool
}

type UserManagementConfig struct {
	ChangeEmailEnabled             bool
	SendChangeEmailConfirmation    bool
	UpdateEmailWithoutVerification bool
	DeleteUserEnabled              bool
	SendDeleteAccountVerification  bool
	BeforeDelete                   UserDeletionHook
	AfterDelete                    UserDeletionHook
}

// AdminConfig provides the Better Auth v1.6 administrator-selection options
// that govern core impersonation. Full admin CRUD/ban endpoints remain a
// separate plugin surface.
type AdminConfig struct {
	DefaultRole              string
	AdminRoles               []string
	AdminUserIDs             []string
	RoleResolver             AdminRoleResolver
	AllowImpersonatingAdmins bool
}

// EmailVerificationConfig controls the Better Auth v1.6 verification
// lifecycle. SendOnSignUp is optional because its default follows
// EmailPassword.RequireEmailVerification.
type EmailVerificationConfig struct {
	SendOnSignUp                *bool
	SendOnSignIn                bool
	AutoSignInAfterVerification bool
	BeforeVerification          UserLifecycleHook
	AfterVerification           UserLifecycleHook
}

// EmailPasswordConfig controls the Better Auth v1.6 email/password lifecycle.
// AutoSignIn is optional because the upstream default is true.
type EmailPasswordConfig struct {
	// DisableSignUp rejects new email/password registrations.
	DisableSignUp bool
	// AutoSignIn controls session creation after signup. Nil defaults to true.
	// New copies the pointed-to value so later caller mutation cannot change a
	// running server.
	AutoSignIn *bool
	// RequireEmailVerification suppresses signup sessions and blocks credential
	// sign-in until the single-use verification token is consumed.
	RequireEmailVerification bool
	// RevokeSessionsOnPasswordReset atomically revokes every active user
	// session when a reset token is consumed. Better Auth defaults to false.
	RevokeSessionsOnPasswordReset bool
	// OnPasswordReset runs after the password is durably replaced and before
	// optional session revocation.
	OnPasswordReset UserLifecycleHook
	// OnExistingUserSignUp receives an existing user only through the
	// application-owned background runner. Its result never changes the
	// enumeration-resistant synthetic response.
	OnExistingUserSignUp UserLifecycleHook
	// CustomSyntheticUser adds application-defined public fields to protected
	// duplicate-signup responses.
	CustomSyntheticUser SyntheticUserFactory
}

type Config struct {
	BasePath                string
	PublicURL               string
	TrustedOrigins          []string
	TrustedOriginResolver   TrustedOriginResolver
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
	Account                 AccountManagementConfig
	Admin                   AdminConfig
	User                    UserManagementConfig
	EmailPassword           EmailPasswordConfig
	EmailVerification       EmailVerificationConfig
	SessionDuration         time.Duration
	SessionFreshAge         time.Duration
	ImpersonationDuration   time.Duration
	PasswordResetTTL        time.Duration
	EmailVerificationTTL    time.Duration
	DeleteUserTTL           time.Duration
	OAuthStateTTL           time.Duration
	ProviderTimeout         time.Duration
	MaxRequestBytes         int64
	MinPasswordBytes        int
	MaxPasswordBytes        int
	// TrustProxyHeaders permits X-Forwarded-For only for rate-limit/audit IP
	// attribution. PublicURL, callback URLs, cookies, and origin authority are
	// always derived from explicit configuration, never forwarded host/proto.
	TrustProxyHeaders bool
	Plugins           []Plugin
	Hooks             ServerHooks
	BackgroundTasks   BackgroundTaskRunner
	MaxResponseBytes  int64
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now().UTC() }

func (cfg Config) normalized() (Config, trustedOriginPolicy, map[string]struct{}, error) {
	plugins, err := compilePlugins(cfg.Plugins)
	if err != nil {
		return cfg, trustedOriginPolicy{}, nil, err
	}
	cfg.Plugins = plugins
	if cfg.Database == nil {
		return cfg, trustedOriginPolicy{}, nil, fmt.Errorf("betterauth: database adapter is required")
	}
	if !cfg.Database.Capabilities().Transactions {
		return cfg, trustedOriginPolicy{}, nil, fmt.Errorf("betterauth: enabled core flows require database transactions")
	}
	if cfg.BasePath == "" {
		cfg.BasePath = "/api/auth"
	}
	cfg.BasePath = cleanAbsolutePath(cfg.BasePath)
	if cfg.BasePath == "/" {
		return cfg, trustedOriginPolicy{}, nil, fmt.Errorf("betterauth: base path may not be root")
	}
	if cfg.PublicURL == "" {
		return cfg, trustedOriginPolicy{}, nil, fmt.Errorf("betterauth: public URL is required")
	}
	publicURL, err := validateHTTPSURL(cfg.PublicURL, false)
	if err != nil {
		return cfg, trustedOriginPolicy{}, nil, fmt.Errorf("betterauth: public URL: %w", err)
	}
	cfg.PublicURL = strings.TrimSuffix(publicURL.String(), "/")
	cfg.Schema, cfg.TrustedOrigins, err = initializePlugins(cfg, cfg.Plugins)
	if err != nil {
		return cfg, trustedOriginPolicy{}, nil, err
	}
	if err := validateSchema(cfg.Schema); err != nil {
		return cfg, trustedOriginPolicy{}, nil, err
	}
	if configurable, ok := cfg.Database.(SchemaConfigurableAdapter); ok {
		cfg.Database, err = configurable.WithSchema(cfg.Schema)
		if err != nil {
			return cfg, trustedOriginPolicy{}, nil, fmt.Errorf("betterauth: configure database schema: %w", err)
		}
	}
	cfg.Database, err = WrapDatabaseAdapter(cfg.Database, cfg.Schema)
	if err != nil {
		return cfg, trustedOriginPolicy{}, nil, err
	}
	cfg.Database, err = wrapDatabaseHooks(cfg.Database, cfg.Plugins)
	if err != nil {
		return cfg, trustedOriginPolicy{}, nil, err
	}
	if cfg.Mailer == nil {
		return cfg, trustedOriginPolicy{}, nil, fmt.Errorf("betterauth: mailer is required")
	}
	if cfg.ImpersonationAuthorizer == nil {
		return cfg, trustedOriginPolicy{}, nil, fmt.Errorf("betterauth: impersonation authorizer is required")
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
	if cfg.EmailPassword.AutoSignIn != nil {
		autoSignIn := *cfg.EmailPassword.AutoSignIn
		cfg.EmailPassword.AutoSignIn = &autoSignIn
	}
	if cfg.EmailVerification.SendOnSignUp != nil {
		sendOnSignUp := *cfg.EmailVerification.SendOnSignUp
		cfg.EmailVerification.SendOnSignUp = &sendOnSignUp
	}
	if cfg.Account.LinkingEnabled != nil {
		enabled := *cfg.Account.LinkingEnabled
		cfg.Account.LinkingEnabled = &enabled
	}
	if cfg.Account.UpdateAccountOnSignIn != nil {
		update := *cfg.Account.UpdateAccountOnSignIn
		cfg.Account.UpdateAccountOnSignIn = &update
	}
	if cfg.Account.RequireLocalEmailVerified != nil {
		required := *cfg.Account.RequireLocalEmailVerified
		cfg.Account.RequireLocalEmailVerified = &required
	}
	if err := normalizeAdminConfig(&cfg.Admin); err != nil {
		return cfg, trustedOriginPolicy{}, nil, err
	}
	if len(cfg.TrustedOrigins) == 0 && cfg.TrustedOriginResolver == nil {
		return cfg, trustedOriginPolicy{}, nil, fmt.Errorf(
			"betterauth: at least one trusted origin or a trusted-origin resolver is required",
		)
	}
	origins, err := compileTrustedOriginPolicy(cfg.TrustedOrigins)
	if err != nil {
		return cfg, trustedOriginPolicy{}, nil, fmt.Errorf(
			"betterauth: trusted origins: %w",
			err,
		)
	}
	cfg.TrustedOrigins = append([]string(nil), origins.values...)

	if cfg.Cookie.Name == "" {
		cfg.Cookie.Name = "__Host-better_auth_session"
	}
	if cfg.Cookie.CSRFName == "" {
		cfg.Cookie.CSRFName = "__Host-better_auth_csrf"
	}
	if !strings.HasPrefix(cfg.Cookie.Name, "__Host-") || !strings.HasPrefix(cfg.Cookie.CSRFName, "__Host-") {
		return cfg, trustedOriginPolicy{}, nil, fmt.Errorf("betterauth: cookie names must use the __Host- prefix")
	}
	if cfg.Cookie.Path == "" {
		cfg.Cookie.Path = "/"
	}
	if cfg.Cookie.Path != "/" {
		return cfg, trustedOriginPolicy{}, nil, fmt.Errorf("betterauth: __Host- cookies require path /")
	}
	if cfg.Cookie.SameSite == 0 {
		cfg.Cookie.SameSite = http.SameSiteLaxMode
	}
	if cfg.Cookie.SameSite != http.SameSiteLaxMode && cfg.Cookie.SameSite != http.SameSiteStrictMode {
		return cfg, trustedOriginPolicy{}, nil, fmt.Errorf("betterauth: SameSite must be Lax or Strict")
	}

	if cfg.SessionDuration == 0 {
		cfg.SessionDuration = 30 * 24 * time.Hour
	}
	if cfg.SessionDuration < 5*time.Minute || cfg.SessionDuration > 365*24*time.Hour {
		return cfg, trustedOriginPolicy{}, nil, fmt.Errorf("betterauth: session duration is out of bounds")
	}
	if cfg.SessionFreshAge == 0 {
		cfg.SessionFreshAge = 24 * time.Hour
	}
	if cfg.SessionFreshAge < time.Minute || cfg.SessionFreshAge > 30*24*time.Hour {
		return cfg, trustedOriginPolicy{}, nil, fmt.Errorf("betterauth: session fresh age is out of bounds")
	}
	if cfg.ImpersonationDuration == 0 {
		cfg.ImpersonationDuration = time.Hour
	}
	if cfg.ImpersonationDuration <= 0 || cfg.ImpersonationDuration > time.Hour {
		return cfg, trustedOriginPolicy{}, nil, fmt.Errorf("betterauth: impersonation duration must not exceed one hour")
	}
	if cfg.PasswordResetTTL == 0 {
		cfg.PasswordResetTTL = time.Hour
	}
	if cfg.EmailVerificationTTL == 0 {
		cfg.EmailVerificationTTL = time.Hour
	}
	if cfg.DeleteUserTTL == 0 {
		cfg.DeleteUserTTL = 24 * time.Hour
	}
	if cfg.OAuthStateTTL == 0 {
		cfg.OAuthStateTTL = 10 * time.Minute
	}
	if cfg.ProviderTimeout == 0 {
		cfg.ProviderTimeout = 15 * time.Second
	}
	if cfg.ProviderTimeout < time.Second || cfg.ProviderTimeout > time.Minute {
		return cfg, trustedOriginPolicy{}, nil, fmt.Errorf("betterauth: provider timeout is out of bounds")
	}
	for name, value := range map[string]time.Duration{
		"password reset TTL":     cfg.PasswordResetTTL,
		"email verification TTL": cfg.EmailVerificationTTL,
		"delete user TTL":        cfg.DeleteUserTTL,
		"OAuth state TTL":        cfg.OAuthStateTTL,
	} {
		if value < time.Minute || value > 7*24*time.Hour {
			return cfg, trustedOriginPolicy{}, nil, fmt.Errorf("betterauth: %s is out of bounds", name)
		}
	}
	if cfg.User.SendDeleteAccountVerification && !cfg.User.DeleteUserEnabled {
		return cfg, trustedOriginPolicy{}, nil, fmt.Errorf(
			"betterauth: delete verification requires user deletion to be enabled",
		)
	}
	if cfg.MaxRequestBytes == 0 {
		cfg.MaxRequestBytes = 64 << 10
	}
	if cfg.MaxRequestBytes < 1024 || cfg.MaxRequestBytes > 1<<20 {
		return cfg, trustedOriginPolicy{}, nil, fmt.Errorf("betterauth: max request bytes is out of bounds")
	}
	if cfg.MaxResponseBytes == 0 {
		cfg.MaxResponseBytes = 1 << 20
	}
	if cfg.MaxResponseBytes < 1024 || cfg.MaxResponseBytes > 16<<20 {
		return cfg, trustedOriginPolicy{}, nil, fmt.Errorf("betterauth: max response bytes is out of bounds")
	}
	if cfg.MinPasswordBytes == 0 {
		cfg.MinPasswordBytes = 8
	}
	if cfg.MaxPasswordBytes == 0 {
		cfg.MaxPasswordBytes = 128
	}
	if cfg.MinPasswordBytes < 8 || cfg.MaxPasswordBytes < cfg.MinPasswordBytes || cfg.MaxPasswordBytes > 1<<20 {
		return cfg, trustedOriginPolicy{}, nil, fmt.Errorf("betterauth: password length policy is invalid")
	}
	if cfg.Passwords == nil {
		argon, err := NewArgon2idVerifier(DefaultArgon2Params(), cfg.MaxPasswordBytes)
		if err != nil {
			return cfg, trustedOriginPolicy{}, nil, err
		}
		cfg.Passwords = argon
	}

	returnTo := map[string]struct{}{}
	if len(cfg.SocialProviders) > 0 && len(cfg.AllowedRedirectURLs) == 0 {
		return cfg, trustedOriginPolicy{}, nil, fmt.Errorf("betterauth: allowed redirect URLs are required when social providers are configured")
	}
	if len(cfg.SocialProviders) > 0 && cfg.ProviderTokenCipher == nil {
		return cfg, trustedOriginPolicy{}, nil, fmt.Errorf("betterauth: provider token cipher is required when social providers are configured")
	}
	normalizedReturns := make([]string, 0, len(cfg.AllowedRedirectURLs))
	for _, raw := range cfg.AllowedRedirectURLs {
		value, err := validateHTTPSURL(raw, true)
		if err != nil {
			return cfg, trustedOriginPolicy{}, nil, fmt.Errorf("betterauth: allowed redirect URL %q: %w", raw, err)
		}
		canonical := value.String()
		returnTo[canonical] = struct{}{}
		normalizedReturns = append(normalizedReturns, canonical)
	}
	cfg.AllowedRedirectURLs = normalizedReturns
	for providerID, provider := range cfg.SocialProviders {
		if provider == nil || !validProviderID(providerID) {
			return cfg, trustedOriginPolicy{}, nil, fmt.Errorf("betterauth: invalid social provider %q", providerID)
		}
	}
	trustedProviders := make([]string, 0, len(cfg.Account.TrustedProviders))
	if cfg.Account.TrustedProviderResolver != nil && len(cfg.Account.TrustedProviders) > 0 {
		return cfg, trustedOriginPolicy{}, nil, fmt.Errorf("betterauth: static and request-resolved trusted providers are mutually exclusive")
	}
	trustedProviderSet := make(map[string]struct{}, len(cfg.Account.TrustedProviders))
	for _, raw := range cfg.Account.TrustedProviders {
		providerID := strings.ToLower(strings.TrimSpace(raw))
		if !validProviderID(providerID) {
			return cfg, trustedOriginPolicy{}, nil, fmt.Errorf("betterauth: invalid trusted provider %q", raw)
		}
		if _, configured := cfg.SocialProviders[providerID]; !configured && providerID != "email-password" {
			return cfg, trustedOriginPolicy{}, nil, fmt.Errorf("betterauth: trusted provider %q is not configured", providerID)
		}
		if _, duplicate := trustedProviderSet[providerID]; duplicate {
			continue
		}
		trustedProviderSet[providerID] = struct{}{}
		trustedProviders = append(trustedProviders, providerID)
	}
	cfg.Account.TrustedProviders = trustedProviders
	cfg.SocialProviders = maps.Clone(cfg.SocialProviders)
	return cfg, origins, returnTo, nil
}

func (cfg Config) autoSignInAfterSignUp() bool {
	return cfg.EmailPassword.AutoSignIn == nil || *cfg.EmailPassword.AutoSignIn
}

func (cfg Config) accountLinkingEnabled() bool {
	return cfg.Account.LinkingEnabled == nil || *cfg.Account.LinkingEnabled
}

func (cfg Config) updateAccountOnSignIn() bool {
	return cfg.Account.UpdateAccountOnSignIn == nil || *cfg.Account.UpdateAccountOnSignIn
}

func (cfg Config) requireLocalEmailVerifiedForLinking() bool {
	return cfg.Account.RequireLocalEmailVerified == nil || *cfg.Account.RequireLocalEmailVerified
}

func normalizeAdminConfig(config *AdminConfig) error {
	config.DefaultRole = strings.ToLower(strings.TrimSpace(config.DefaultRole))
	if config.DefaultRole == "" {
		config.DefaultRole = "user"
	}
	if !validRoleName(config.DefaultRole) {
		return fmt.Errorf("betterauth: invalid default admin role %q", config.DefaultRole)
	}
	roles := make([]string, 0, len(config.AdminRoles))
	seenRoles := make(map[string]struct{}, len(config.AdminRoles))
	for _, raw := range config.AdminRoles {
		role := strings.ToLower(strings.TrimSpace(raw))
		if !validRoleName(role) {
			return fmt.Errorf("betterauth: invalid admin role %q", raw)
		}
		if _, duplicate := seenRoles[role]; duplicate {
			continue
		}
		seenRoles[role] = struct{}{}
		roles = append(roles, role)
	}
	if config.RoleResolver != nil && len(roles) == 0 {
		roles = []string{"admin"}
	}
	if len(roles) > 0 && config.RoleResolver == nil {
		return fmt.Errorf("betterauth: admin role resolver is required when admin roles are configured")
	}
	config.AdminRoles = roles
	ids := make([]string, 0, len(config.AdminUserIDs))
	seenIDs := make(map[string]struct{}, len(config.AdminUserIDs))
	for _, raw := range config.AdminUserIDs {
		id := strings.TrimSpace(raw)
		if id == "" || len(id) > 512 {
			return fmt.Errorf("betterauth: invalid admin user ID")
		}
		if _, duplicate := seenIDs[id]; duplicate {
			continue
		}
		seenIDs[id] = struct{}{}
		ids = append(ids, id)
	}
	config.AdminUserIDs = ids
	return nil
}

func validRoleName(value string) bool {
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
