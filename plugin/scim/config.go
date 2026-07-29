// Package scim provides an inbound Better Auth-shaped SCIM 2.0 provisioning
// service.
//
// Stability: Experimental. This package is tested but is outside the
// better-auth-go v1 compatibility guarantee pending pinned differential and
// live enterprise-directory interoperability certification.
package scim

import (
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	betterauth "github.com/eadwinCode/better-auth-go"
	"github.com/eadwinCode/better-auth-go/social"
	"golang.org/x/net/publicsuffix"
)

type Config struct {
	OrganizationAuthorizer OrganizationAuthorizer
	DefaultConnections     []DefaultConnection
	RequiredRoles          []string
	ReservedProviderIDs    []string
	ProviderOwnership      bool
	ProviderLimit          int
	TokenTTL               time.Duration
	MaxBearerBytes         int
	MaxFilterBytes         int
	MaxFilterClauses       int
	MaxPatchOperations     int
	MaxPageSize            int
	LinkExistingUsers      ExistingUserLinkPolicy
	CanGenerateToken       func(*betterauth.HookContext, string, string) (bool, error)
	Hooks                  Hooks
	Schema                 betterauth.ModelSchema
}

type runtime struct {
	config Config
	schema betterauth.Schema
}

func New(config Config) (betterauth.Plugin, error) {
	normalized, err := normalizeConfig(config)
	if err != nil {
		return betterauth.Plugin{}, err
	}
	schema, err := betterauth.MergeSchema(
		baseSchema(), betterauth.Schema{ModelSCIMProvider: cloneModelSchema(normalized.Schema)},
	)
	if err != nil {
		return betterauth.Plugin{}, fmt.Errorf("scim: schema: %w", err)
	}
	return (&runtime{config: normalized, schema: schema}).plugin(), nil
}

func normalizeConfig(config Config) (Config, error) {
	if config.ProviderLimit == 0 {
		config.ProviderLimit = 100
	}
	if config.MaxBearerBytes == 0 {
		config.MaxBearerBytes = 2048
	}
	if config.MaxFilterBytes == 0 {
		config.MaxFilterBytes = 2048
	}
	if config.MaxFilterClauses == 0 {
		config.MaxFilterClauses = 10
	}
	if config.MaxPatchOperations == 0 {
		config.MaxPatchOperations = 50
	}
	if config.MaxPageSize == 0 {
		config.MaxPageSize = 200
	}
	if config.TokenTTL < 0 || config.TokenTTL > 365*24*time.Hour {
		return config, errors.New("scim: token TTL is out of bounds")
	}
	if config.ProviderLimit < 1 || config.ProviderLimit > 1000 ||
		config.MaxBearerBytes < 128 || config.MaxBearerBytes > 16<<10 ||
		config.MaxFilterBytes < 128 || config.MaxFilterBytes > 16<<10 ||
		config.MaxFilterClauses < 1 || config.MaxFilterClauses > 100 ||
		config.MaxPatchOperations < 1 || config.MaxPatchOperations > 1000 ||
		config.MaxPageSize < 1 || config.MaxPageSize > 1000 {
		return config, errors.New("scim: configured limit is out of bounds")
	}
	roles := make([]string, 0, len(config.RequiredRoles)+2)
	if len(config.RequiredRoles) == 0 {
		roles = append(roles, "admin", "owner")
	} else {
		for _, role := range config.RequiredRoles {
			role = strings.ToLower(strings.TrimSpace(role))
			if !validIdentifier(role, 64) {
				return config, errors.New("scim: invalid required role")
			}
			roles = append(roles, role)
		}
	}
	slices.Sort(roles)
	config.RequiredRoles = slices.Compact(roles)

	reserved := []string{
		"credential", "email-otp", "magic-link", "phone-number", "anonymous", "siwe",
	}
	reserved = append(reserved, social.SupportedProviders...)
	for _, providerID := range config.ReservedProviderIDs {
		providerID = strings.ToLower(strings.TrimSpace(providerID))
		if !validIdentifier(providerID, 128) {
			return config, errors.New("scim: invalid reserved provider id")
		}
		reserved = append(reserved, providerID)
	}
	slices.Sort(reserved)
	config.ReservedProviderIDs = slices.Compact(reserved)

	connections := make([]DefaultConnection, len(config.DefaultConnections))
	seen := make(map[string]struct{}, len(connections))
	for index, connection := range config.DefaultConnections {
		connection.ProviderID = strings.ToLower(strings.TrimSpace(connection.ProviderID))
		connection.OrganizationID = strings.TrimSpace(connection.OrganizationID)
		connection.UserID = strings.TrimSpace(connection.UserID)
		if !validIdentifier(connection.ProviderID, 128) ||
			slices.Contains(config.ReservedProviderIDs, connection.ProviderID) ||
			!validTokenHash(connection.TokenHash) {
			return config, fmt.Errorf("scim: invalid default connection %d", index)
		}
		if connection.OrganizationID != "" && config.OrganizationAuthorizer == nil {
			return config, errors.New(
				"scim: organization authorizer is required for organization connections",
			)
		}
		if connection.OrganizationID == "" && config.ProviderOwnership &&
			connection.UserID == "" {
			return config, errors.New("scim: owned default connection requires a user")
		}
		if _, exists := seen[connection.ProviderID]; exists {
			return config, errors.New("scim: duplicate default provider id")
		}
		seen[connection.ProviderID] = struct{}{}
		connections[index] = connection
	}
	config.DefaultConnections = connections

	domains := make([]string, 0, len(config.LinkExistingUsers.TrustedDomains))
	for _, domain := range config.LinkExistingUsers.TrustedDomains {
		normalized, err := normalizeDomain(domain)
		if err != nil {
			return config, fmt.Errorf("scim: trusted domain: %w", err)
		}
		domains = append(domains, normalized)
	}
	slices.Sort(domains)
	config.LinkExistingUsers.TrustedDomains = slices.Compact(domains)
	if config.LinkExistingUsers.Enabled &&
		len(config.LinkExistingUsers.TrustedDomains) == 0 &&
		!config.LinkExistingUsers.RequireExistingOrgMembership &&
		config.LinkExistingUsers.Allow == nil {
		return config, errors.New(
			"scim: existing-user linking requires at least one explicit constraint",
		)
	}
	if config.LinkExistingUsers.RequireExistingOrgMembership &&
		config.OrganizationAuthorizer == nil {
		return config, errors.New(
			"scim: organization authorizer is required for membership-constrained linking",
		)
	}
	config.Schema = cloneModelSchema(config.Schema)
	return config, nil
}

func validTokenHash(value string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == 32
}

func validIdentifier(value string, limit int) bool {
	if value == "" || len(value) > limit || strings.Contains(value, ":") {
		return false
	}
	for _, character := range value {
		if character != '-' && character != '_' && character != '.' &&
			(character < 'a' || character > 'z') &&
			(character < '0' || character > '9') {
			return false
		}
	}
	return true
}

func normalizeDomain(value string) (string, error) {
	value = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
	if value == "" || len(value) > 253 || strings.ContainsAny(value, "/:@*") {
		return "", errors.New("invalid domain")
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' ||
			label[len(label)-1] == '-' {
			return "", errors.New("invalid domain")
		}
		for _, character := range label {
			if character != '-' && (character < 'a' || character > 'z') &&
				(character < '0' || character > '9') {
				return "", errors.New("invalid domain")
			}
		}
	}
	suffix, _ := publicsuffix.PublicSuffix(value)
	if suffix == value {
		return "", errors.New("domain cannot be a public suffix")
	}
	return value, nil
}

func cloneModelSchema(model betterauth.ModelSchema) betterauth.ModelSchema {
	fields := make(map[string]betterauth.FieldSchema, len(model.Fields))
	for name, field := range model.Fields {
		fields[name] = field
	}
	model.Fields = fields
	indexes := make([]betterauth.IndexSchema, len(model.Indexes))
	for index, definition := range model.Indexes {
		definition.Fields = slices.Clone(definition.Fields)
		indexes[index] = definition
	}
	model.Indexes = indexes
	return model
}
