// Package passkey provides an opt-in Better Auth-shaped WebAuthn plugin.
package passkey

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"golang.org/x/net/publicsuffix"

	betterauth "github.com/eadwinCode/better-auth-go"
)

const (
	// ModelPasskey is the logical adapter model contributed by this plugin.
	ModelPasskey = "passkey"

	defaultChallengeCookie = "__Host-better_auth_passkey"
)

// UserVerification controls whether an authenticator must verify the user.
type UserVerification string

const (
	VerificationRequired  UserVerification = "required"
	VerificationPreferred UserVerification = "preferred"
)

// ResidentKey controls discoverable-credential creation.
type ResidentKey string

const (
	ResidentKeyRequired    ResidentKey = "required"
	ResidentKeyPreferred   ResidentKey = "preferred"
	ResidentKeyDiscouraged ResidentKey = "discouraged"
)

// AuthenticatorAttachment optionally limits registration to platform or
// cross-platform authenticators.
type AuthenticatorAttachment string

const (
	AuthenticatorPlatform      AuthenticatorAttachment = "platform"
	AuthenticatorCrossPlatform AuthenticatorAttachment = "cross-platform"
)

// Config is immutable after New. RPID and Origins are explicit so a proxy or
// request header can never expand the WebAuthn relying-party boundary.
type Config struct {
	RPID                    string
	RPDisplayName           string
	Origins                 []string
	ChallengeTTL            time.Duration
	ChallengeCookie         string
	UserVerification        UserVerification
	ResidentKey             ResidentKey
	AuthenticatorAttachment AuthenticatorAttachment
	RequireResidentKey      bool
	MaxCredentials          int
	Schema                  betterauth.ModelSchema
	Registration            RegistrationConfig
	Authentication          AuthenticationConfig
}

type runtime struct {
	config   Config
	webAuthn *webauthn.WebAuthn
	schema   betterauth.Schema
}

// New validates configuration and returns an immutable passkey plugin.
func New(config Config) (betterauth.Plugin, error) {
	normalized, webAuthn, err := normalizeConfig(config)
	if err != nil {
		return betterauth.Plugin{}, err
	}
	schema, err := betterauth.MergeSchema(
		basePasskeySchema(), betterauth.Schema{ModelPasskey: normalized.Schema},
	)
	if err != nil {
		return betterauth.Plugin{}, fmt.Errorf("passkey: schema: %w", err)
	}
	instance := &runtime{config: normalized, webAuthn: webAuthn, schema: schema}
	return instance.plugin(), nil
}

func normalizeConfig(config Config) (Config, *webauthn.WebAuthn, error) {
	config.RPID = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(config.RPID, ".")))
	if config.RPID == "" {
		return config, nil, fmt.Errorf("passkey: relying-party ID is required")
	}
	if err := protocol.ValidateRPID(config.RPID); err != nil {
		return config, nil, fmt.Errorf("passkey: invalid relying-party ID: %w", err)
	}
	if ip := net.ParseIP(config.RPID); ip != nil {
		return config, nil, fmt.Errorf("passkey: relying-party ID must be a domain, not an IP address")
	}
	if config.RPID != "localhost" {
		suffix, _ := publicsuffix.PublicSuffix(config.RPID)
		if suffix == config.RPID {
			return config, nil, fmt.Errorf("passkey: relying-party ID may not be a public suffix")
		}
	}
	config.RPDisplayName = strings.TrimSpace(config.RPDisplayName)
	if config.RPDisplayName == "" || len(config.RPDisplayName) > 128 {
		return config, nil, fmt.Errorf("passkey: relying-party display name is required and must not exceed 128 bytes")
	}
	if len(config.Origins) == 0 {
		return config, nil, fmt.Errorf("passkey: at least one exact origin is required")
	}
	origins := make([]string, 0, len(config.Origins))
	seen := make(map[string]struct{}, len(config.Origins))
	for _, raw := range config.Origins {
		origin, host, err := normalizeOrigin(raw)
		if err != nil {
			return config, nil, fmt.Errorf("passkey: origin %q: %w", raw, err)
		}
		if host != config.RPID && !strings.HasSuffix(host, "."+config.RPID) {
			return config, nil, fmt.Errorf(
				"passkey: origin host %q is outside relying-party ID %q", host, config.RPID,
			)
		}
		if _, exists := seen[origin]; !exists {
			seen[origin] = struct{}{}
			origins = append(origins, origin)
		}
	}
	slices.Sort(origins)
	config.Origins = origins

	if config.ChallengeTTL == 0 {
		config.ChallengeTTL = 5 * time.Minute
	}
	if config.ChallengeTTL < time.Minute || config.ChallengeTTL > 15*time.Minute {
		return config, nil, fmt.Errorf("passkey: challenge TTL must be between one and fifteen minutes")
	}
	if config.ChallengeCookie == "" {
		config.ChallengeCookie = defaultChallengeCookie
	}
	if !strings.HasPrefix(config.ChallengeCookie, "__Host-") {
		return config, nil, fmt.Errorf("passkey: challenge cookie must use the __Host- prefix")
	}
	if err := (&http.Cookie{Name: config.ChallengeCookie, Value: "value"}).Valid(); err != nil {
		return config, nil, fmt.Errorf("passkey: invalid challenge cookie: %w", err)
	}
	if config.UserVerification == "" {
		config.UserVerification = VerificationRequired
	}
	if config.UserVerification != VerificationRequired &&
		config.UserVerification != VerificationPreferred {
		return config, nil, fmt.Errorf("passkey: user verification must be required or preferred")
	}
	if config.ResidentKey == "" {
		config.ResidentKey = ResidentKeyPreferred
	}
	switch config.ResidentKey {
	case ResidentKeyRequired, ResidentKeyPreferred, ResidentKeyDiscouraged:
	default:
		return config, nil, fmt.Errorf("passkey: invalid resident-key policy")
	}
	switch config.AuthenticatorAttachment {
	case "", AuthenticatorPlatform, AuthenticatorCrossPlatform:
	default:
		return config, nil, fmt.Errorf("passkey: invalid authenticator attachment")
	}
	if config.RequireResidentKey && config.ResidentKey == ResidentKeyDiscouraged {
		return config, nil, fmt.Errorf(
			"passkey: require-resident-key conflicts with discouraged resident keys",
		)
	}
	if config.MaxCredentials == 0 {
		config.MaxCredentials = 20
	}
	if config.MaxCredentials < 1 || config.MaxCredentials > 100 {
		return config, nil, fmt.Errorf("passkey: max credentials must be between 1 and 100")
	}
	if config.Registration.AllowWithoutSession &&
		config.Registration.ResolveUser == nil {
		return config, nil, fmt.Errorf(
			"passkey: registration user resolver is required without a session",
		)
	}
	config.Schema = cloneModelSchema(config.Schema)

	selection := protocol.AuthenticatorSelection{
		AuthenticatorAttachment: protocol.AuthenticatorAttachment(config.AuthenticatorAttachment),
		ResidentKey:             protocol.ResidentKeyRequirement(config.ResidentKey),
		UserVerification:        protocol.UserVerificationRequirement(config.UserVerification),
	}
	if config.ResidentKey == ResidentKeyRequired || config.RequireResidentKey {
		required := true
		selection.RequireResidentKey = &required
	}
	webAuthn, err := webauthn.New(&webauthn.Config{
		RPID:                   config.RPID,
		RPDisplayName:          config.RPDisplayName,
		RPOrigins:              slices.Clone(config.Origins),
		RPAllowCrossOrigin:     false,
		AttestationPreference:  protocol.PreferNoAttestation,
		AuthenticatorSelection: selection,
		Timeouts: webauthn.TimeoutsConfig{
			Registration: webauthn.TimeoutConfig{Timeout: config.ChallengeTTL},
			Login:        webauthn.TimeoutConfig{Timeout: config.ChallengeTTL},
		},
	})
	if err != nil {
		return config, nil, fmt.Errorf("passkey: WebAuthn configuration: %w", err)
	}
	return config, webAuthn, nil
}

func cloneModelSchema(model betterauth.ModelSchema) betterauth.ModelSchema {
	if model.Fields == nil {
		return model
	}
	fields := make(map[string]betterauth.FieldSchema, len(model.Fields))
	for name, definition := range model.Fields {
		fields[name] = definition
	}
	model.Fields = fields
	return model
}

func normalizeOrigin(raw string) (string, string, error) {
	if strings.Contains(raw, "*") {
		return "", "", fmt.Errorf("wildcards are not allowed")
	}
	value, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || value == nil || !value.IsAbs() || value.Host == "" {
		return "", "", fmt.Errorf("must be an absolute origin")
	}
	host := strings.ToLower(strings.TrimSuffix(value.Hostname(), "."))
	loopback := host == "localhost"
	if value.Scheme != "https" && !(value.Scheme == "http" && loopback) {
		return "", "", fmt.Errorf("must use HTTPS outside localhost development")
	}
	if value.User != nil || value.RawQuery != "" || value.Fragment != "" ||
		(value.Path != "" && value.Path != "/") {
		return "", "", fmt.Errorf("must not include credentials, path, query, or fragment")
	}
	authority := host
	if port := value.Port(); port != "" {
		authority = net.JoinHostPort(host, port)
	}
	return strings.ToLower(value.Scheme) + "://" + authority, host, nil
}
