// Package twofactor provides an opt-in Better Auth-shaped two-factor plugin.
package twofactor

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	betterauth "github.com/eadwinCode/better-auth-go"
)

const (
	// ModelTwoFactor is the logical adapter model contributed by this plugin.
	ModelTwoFactor = "twoFactor"

	defaultPendingCookie = "__Host-better_auth_two_factor"
	defaultTrustedCookie = "__Host-better_auth_trusted_device"
)

// OTPDelivery delivers a library-generated second-factor code. Implementations
// must be concurrency-safe and must not retain HookContext.
type OTPDelivery func(*betterauth.HookContext, betterauth.User, string) error

// Config is immutable after construction.
type Config struct {
	Issuer                   string
	Cipher                   betterauth.TokenCipher
	DeliverOTP               OTPDelivery
	PendingCookie            string
	TrustedDeviceCookie      string
	PendingTTL               time.Duration
	OTPTTL                   time.Duration
	TrustedDeviceTTL         time.Duration
	TOTPDigits               int
	TOTPPeriod               time.Duration
	BackupCodeCount          int
	BackupCodeLength         int
	ChallengeMaxAttempts     int
	AccountMaxFailedAttempts int
	AccountLockoutDuration   time.Duration
	AllowPasswordless        bool
	SkipVerificationOnEnable bool
	DisableTOTP              bool
	Schema                   betterauth.ModelSchema
}

type runtime struct {
	config Config
	schema betterauth.Schema
}

// Manager exposes the plugin descriptor and the server-only backup-code API.
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

// NewManager returns an integration with server-only management operations.
func NewManager(config Config) (*Manager, error) {
	normalized, err := normalizeConfig(config)
	if err != nil {
		return nil, err
	}
	schema, err := betterauth.MergeSchema(
		baseSchema(), betterauth.Schema{ModelTwoFactor: cloneModelSchema(normalized.Schema)},
	)
	if err != nil {
		return nil, fmt.Errorf("twofactor: schema: %w", err)
	}
	return &Manager{runtime: &runtime{config: normalized, schema: schema}}, nil
}

// Plugin returns the immutable server plugin descriptor.
func (manager *Manager) Plugin() betterauth.Plugin {
	if manager == nil || manager.runtime == nil {
		return betterauth.Plugin{}
	}
	return manager.runtime.plugin()
}

// ViewBackupCodes decrypts a user's current recovery codes for trusted
// server-side use. It is deliberately not an HTTP endpoint.
func (manager *Manager) ViewBackupCodes(
	ctx context.Context,
	database betterauth.DatabaseAdapter,
	userID string,
) ([]string, error) {
	if manager == nil || manager.runtime == nil || database == nil {
		return nil, errors.New("twofactor: manager and database are required")
	}
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return nil, betterauth.ErrNotFound
	}
	row, err := database.FindOne(ctx, betterauth.FindOneQuery{
		Model:  ModelTwoFactor,
		Where:  []betterauth.Where{betterauth.Eq("userId", userID)},
		Select: []string{"backupCodes"},
	})
	if err != nil || row == nil {
		if err == nil {
			err = betterauth.ErrNotFound
		}
		return nil, err
	}
	encoded, _ := row["backupCodes"].(string)
	return manager.runtime.openBackupCodes(ctx, encoded)
}

func normalizeConfig(config Config) (Config, error) {
	config.Issuer = strings.TrimSpace(config.Issuer)
	if config.Issuer == "" || len(config.Issuer) > 128 {
		return config, errors.New("twofactor: issuer is required and must not exceed 128 bytes")
	}
	if config.Cipher == nil {
		return config, errors.New("twofactor: secret cipher is required")
	}
	if config.DisableTOTP && config.DeliverOTP == nil {
		return config, errors.New("twofactor: at least TOTP or delivered OTP must be enabled")
	}
	if config.DisableTOTP && !config.SkipVerificationOnEnable {
		return config, errors.New(
			"twofactor: OTP-only mode requires skip-verification-on-enable",
		)
	}
	if config.PendingCookie == "" {
		config.PendingCookie = defaultPendingCookie
	}
	if config.TrustedDeviceCookie == "" {
		config.TrustedDeviceCookie = defaultTrustedCookie
	}
	for label, name := range map[string]string{
		"pending": config.PendingCookie, "trusted-device": config.TrustedDeviceCookie,
	} {
		if !strings.HasPrefix(name, "__Host-") {
			return config, fmt.Errorf("twofactor: %s cookie must use the __Host- prefix", label)
		}
		if err := (&http.Cookie{Name: name, Value: "value"}).Valid(); err != nil {
			return config, fmt.Errorf("twofactor: invalid %s cookie: %w", label, err)
		}
	}
	if config.PendingCookie == config.TrustedDeviceCookie {
		return config, errors.New("twofactor: pending and trusted-device cookies must differ")
	}
	if config.PendingTTL == 0 {
		config.PendingTTL = 10 * time.Minute
	}
	if config.OTPTTL == 0 {
		config.OTPTTL = 5 * time.Minute
	}
	if config.TrustedDeviceTTL == 0 {
		config.TrustedDeviceTTL = 30 * 24 * time.Hour
	}
	if config.PendingTTL < time.Minute || config.PendingTTL > 30*time.Minute {
		return config, errors.New("twofactor: pending TTL must be between one and thirty minutes")
	}
	if config.OTPTTL < time.Minute || config.OTPTTL > config.PendingTTL {
		return config, errors.New("twofactor: OTP TTL must be between one minute and the pending TTL")
	}
	if config.TrustedDeviceTTL < time.Hour || config.TrustedDeviceTTL > 90*24*time.Hour {
		return config, errors.New("twofactor: trusted-device TTL must be between one hour and ninety days")
	}
	if config.TOTPDigits == 0 {
		config.TOTPDigits = 6
	}
	if config.TOTPDigits != 6 && config.TOTPDigits != 8 {
		return config, errors.New("twofactor: TOTP digits must be six or eight")
	}
	if config.TOTPPeriod == 0 {
		config.TOTPPeriod = 30 * time.Second
	}
	if config.TOTPPeriod < 15*time.Second || config.TOTPPeriod > 2*time.Minute {
		return config, errors.New("twofactor: TOTP period must be between fifteen seconds and two minutes")
	}
	if config.BackupCodeCount == 0 {
		config.BackupCodeCount = 10
	}
	if config.BackupCodeLength == 0 {
		config.BackupCodeLength = 10
	}
	if config.BackupCodeCount < 1 || config.BackupCodeCount > 50 ||
		config.BackupCodeLength < 8 || config.BackupCodeLength > 32 {
		return config, errors.New("twofactor: backup-code configuration is out of bounds")
	}
	if config.ChallengeMaxAttempts == 0 {
		config.ChallengeMaxAttempts = 5
	}
	if config.AccountMaxFailedAttempts == 0 {
		config.AccountMaxFailedAttempts = 10
	}
	if config.AccountLockoutDuration == 0 {
		config.AccountLockoutDuration = 15 * time.Minute
	}
	if config.ChallengeMaxAttempts < 1 || config.ChallengeMaxAttempts > 20 ||
		config.AccountMaxFailedAttempts < config.ChallengeMaxAttempts ||
		config.AccountMaxFailedAttempts > 100 ||
		config.AccountLockoutDuration < time.Minute ||
		config.AccountLockoutDuration > 24*time.Hour {
		return config, errors.New("twofactor: attempt or lockout configuration is out of bounds")
	}
	config.Schema = cloneModelSchema(config.Schema)
	return config, nil
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

func baseSchema() betterauth.Schema {
	return betterauth.Schema{
		betterauth.ModelUser: {
			Fields: map[string]betterauth.FieldSchema{
				"twoFactorEnabled": {
					Type: betterauth.FieldBoolean, Input: false, Returned: true,
				},
			},
		},
		ModelTwoFactor: {
			Fields: map[string]betterauth.FieldSchema{
				"id": {
					Type: betterauth.FieldString, Required: true, Unique: true,
				},
				"userId": {
					Type: betterauth.FieldString, Required: true, Unique: true,
					References: betterauth.ModelUser,
				},
				"secret": {
					Type: betterauth.FieldString, Required: true,
				},
				"backupCodes": {
					Type: betterauth.FieldString, Required: true,
				},
				"verified": {
					Type: betterauth.FieldBoolean, Required: true,
				},
				"failedVerificationCount": {
					Type: betterauth.FieldNumber, Required: true,
				},
				"lockedUntil": {Type: betterauth.FieldDate},
				"createdAt": {
					Type: betterauth.FieldDate, Required: true,
				},
				"updatedAt": {
					Type: betterauth.FieldDate, Required: true,
				},
			},
		},
	}
}
