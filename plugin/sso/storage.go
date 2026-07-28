package sso

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	betterauth "github.com/eadwinCode/better-auth-go"
)

type storedProvider struct {
	Provider
	OIDC *OIDCConfig
	SAML *SAMLConfig
}

func (instance *runtime) createProvider(
	ctx *betterauth.HookContext,
	registration ProviderRegistration,
	ownerID string,
) (storedProvider, error) {
	normalized, err := normalizeProvider(registration)
	if err != nil {
		return storedProvider{}, badRequest(err)
	}
	if err = instance.validateProvider(ctx.Context, normalized); err != nil {
		return storedProvider{}, providerFailure(err)
	}
	if normalized.OrganizationID != "" {
		if instance.config.OrganizationAuthorizer == nil {
			return storedProvider{}, forbidden(errors.New("organization SSO is not configured"))
		}
		if err = instance.config.OrganizationAuthorizer.AuthorizeSSOProvider(
			ctx, normalized.OrganizationID,
		); err != nil {
			return storedProvider{}, forbidden(err)
		}
	}
	countWhere := []betterauth.Where{betterauth.Eq("userId", ownerID)}
	if normalized.OrganizationID != "" {
		countWhere = []betterauth.Where{
			betterauth.Eq("organizationId", normalized.OrganizationID),
		}
	}
	count, err := ctx.Database.Count(ctx.Context, betterauth.CountQuery{
		Model: ModelSSOProvider, Where: countWhere,
	})
	if err != nil {
		return storedProvider{}, internal(err)
	}
	if count >= int64(instance.config.ProvidersLimit) {
		return storedProvider{}, conflict(errors.New("SSO provider limit reached"))
	}
	id, err := ctx.GenerateID()
	if err != nil {
		return storedProvider{}, internal(err)
	}
	now := ctx.Clock.Now().UTC()
	oidcSecret, samlSecret, err := instance.sealProvider(ctx.Context, normalized)
	if err != nil {
		return storedProvider{}, internal(err)
	}
	record, err := ctx.Database.Create(ctx.Context, betterauth.CreateQuery{
		Model: ModelSSOProvider, ForceAllowID: true,
		Data: betterauth.Record{
			"id": id, "issuer": normalized.Issuer,
			"oidcConfig": oidcSecret, "samlConfig": samlSecret,
			"userId": ownerID, "providerId": normalized.ProviderID,
			"organizationId": nullableString(normalized.OrganizationID),
			"domain":         normalized.Domain, "domainVerified": !instance.config.DomainVerification,
			"createdAt": now, "updatedAt": now,
		},
	})
	if err != nil {
		if errors.Is(err, betterauth.ErrConflict) {
			return storedProvider{}, conflict(err)
		}
		return storedProvider{}, internal(err)
	}
	return instance.decodeProvider(ctx.Context, record)
}

func (instance *runtime) sealProvider(
	ctx context.Context,
	registration ProviderRegistration,
) (string, string, error) {
	var oidcSecret, samlSecret string
	if registration.OIDC != nil {
		raw, err := json.Marshal(registration.OIDC)
		if err != nil {
			return "", "", err
		}
		oidcSecret, err = instance.config.Cipher.Seal(ctx, string(raw))
		if err != nil {
			return "", "", err
		}
	}
	if registration.SAML != nil {
		raw, err := json.Marshal(registration.SAML)
		if err != nil {
			return "", "", err
		}
		samlSecret, err = instance.config.Cipher.Seal(ctx, string(raw))
		if err != nil {
			return "", "", err
		}
	}
	return oidcSecret, samlSecret, nil
}

func (instance *runtime) decodeProvider(
	ctx context.Context,
	record betterauth.Record,
) (storedProvider, error) {
	if record == nil {
		return storedProvider{}, betterauth.ErrNotFound
	}
	provider := storedProvider{Provider: Provider{
		ID:             stringRecord(record, "id"),
		Issuer:         stringRecord(record, "issuer"),
		Domain:         stringRecord(record, "domain"),
		ProviderID:     stringRecord(record, "providerId"),
		UserID:         stringRecord(record, "userId"),
		OrganizationID: stringRecord(record, "organizationId"),
		DomainVerified: boolRecord(record, "domainVerified"),
		CreatedAt:      timeRecord(record, "createdAt"),
		UpdatedAt:      timeRecord(record, "updatedAt"),
	}}
	for field, destination := range map[string]any{
		"oidcConfig": &provider.OIDC,
		"samlConfig": &provider.SAML,
	} {
		sealed := stringRecord(record, field)
		if sealed == "" {
			continue
		}
		raw, err := instance.config.Cipher.Open(ctx, sealed)
		if err != nil {
			return storedProvider{}, fmt.Errorf("sso: open %s: %w", field, err)
		}
		if err = json.Unmarshal([]byte(raw), destination); err != nil {
			return storedProvider{}, fmt.Errorf("sso: decode %s: %w", field, err)
		}
	}
	switch {
	case provider.OIDC != nil && provider.SAML == nil:
		provider.Type = "oidc"
	case provider.SAML != nil && provider.OIDC == nil:
		provider.Type = "saml"
	default:
		return storedProvider{}, errors.New("sso: corrupt provider protocol configuration")
	}
	return provider, nil
}

func (instance *runtime) findProvider(
	ctx *betterauth.HookContext,
	providerID string,
) (storedProvider, error) {
	providerID = strings.ToLower(strings.TrimSpace(providerID))
	if registration, exists := instance.defaults[providerID]; exists {
		return instance.defaultProvider(registration), nil
	}
	record, err := ctx.Database.FindOne(ctx.Context, betterauth.FindOneQuery{
		Model: ModelSSOProvider,
		Where: []betterauth.Where{betterauth.Eq("providerId", providerID)},
	})
	if err != nil || record == nil {
		return storedProvider{}, betterauth.ErrNotFound
	}
	return instance.decodeProvider(ctx.Context, record)
}

func (instance *runtime) findProviderForSignIn(
	ctx *betterauth.HookContext,
	providerID, issuer, email string,
) (storedProvider, error) {
	if providerID != "" {
		return instance.findProvider(ctx, providerID)
	}
	if issuer != "" {
		for _, registration := range instance.defaults {
			if registration.Issuer == strings.TrimRight(strings.TrimSpace(issuer), "/") {
				return instance.defaultProvider(registration), nil
			}
		}
		record, err := ctx.Database.FindOne(ctx.Context, betterauth.FindOneQuery{
			Model: ModelSSOProvider,
			Where: []betterauth.Where{betterauth.Eq("issuer", strings.TrimRight(strings.TrimSpace(issuer), "/"))},
		})
		if err == nil && record != nil {
			return instance.decodeProvider(ctx.Context, record)
		}
	}
	domain := emailDomain(email)
	if domain != "" {
		for _, registration := range instance.defaults {
			if domainAllowed(registration.Domain, domain) {
				return instance.defaultProvider(registration), nil
			}
		}
		records, err := ctx.Database.FindMany(ctx.Context, betterauth.FindManyQuery{
			Model: ModelSSOProvider, Limit: instance.config.ProvidersLimit + 1,
		})
		if err == nil {
			for _, record := range records {
				if domainAllowed(stringRecord(record, "domain"), domain) {
					return instance.decodeProvider(ctx.Context, record)
				}
			}
		}
	}
	return storedProvider{}, betterauth.ErrNotFound
}

func (instance *runtime) defaultProvider(registration ProviderRegistration) storedProvider {
	providerType := "oidc"
	if registration.SAML != nil {
		providerType = "saml"
	}
	return storedProvider{
		Provider: Provider{
			ID: "default:" + registration.ProviderID, Issuer: registration.Issuer,
			Domain: registration.Domain, ProviderID: registration.ProviderID,
			OrganizationID: registration.OrganizationID, Type: providerType,
			DomainVerified: true,
		},
		OIDC: registration.OIDC, SAML: registration.SAML,
	}
}

func (instance *runtime) authorizeProvider(
	ctx *betterauth.HookContext,
	provider storedProvider,
) error {
	if ctx.User == nil {
		return forbidden(errors.New("authentication required"))
	}
	if provider.OrganizationID == "" {
		if provider.UserID != ctx.User.ID {
			return forbidden(errors.New("provider access denied"))
		}
		return nil
	}
	if instance.config.OrganizationAuthorizer == nil {
		return forbidden(errors.New("organization SSO is not configured"))
	}
	if err := instance.config.OrganizationAuthorizer.AuthorizeSSOProvider(
		ctx, provider.OrganizationID,
	); err != nil {
		return forbidden(err)
	}
	return nil
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func stringRecord(record betterauth.Record, field string) string {
	value, _ := record[field].(string)
	return value
}

func boolRecord(record betterauth.Record, field string) bool {
	value, _ := record[field].(bool)
	return value
}

func timeRecord(record betterauth.Record, field string) time.Time {
	switch value := record[field].(type) {
	case time.Time:
		return value.UTC()
	case string:
		parsed, _ := time.Parse(time.RFC3339Nano, value)
		return parsed.UTC()
	default:
		return time.Time{}
	}
}
