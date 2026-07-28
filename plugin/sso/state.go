package sso

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"

	betterauth "github.com/eadwinCode/better-auth-go"
)

const (
	stateIdentifierOIDC = "sso_oidc_state"
	stateIdentifierSAML = "sso_saml_state"
	stateIdentifierSLO  = "sso_saml_logout"
)

type protocolState struct {
	ProviderID    string
	Verifier      string
	Nonce         string
	RedirectURI   string
	ReturnTo      string
	NewUserTo     string
	ErrorTo       string
	RequestID     string
	RequestSignUp bool
}

func (instance *runtime) createState(
	ctx *betterauth.HookContext,
	identifier string,
	state protocolState,
) (string, error) {
	raw, err := ctx.GenerateToken(32)
	if err != nil {
		return "", err
	}
	id, err := ctx.GenerateID()
	if err != nil {
		return "", err
	}
	now := ctx.Clock.Now().UTC()
	_, err = ctx.Database.Create(ctx.Context, betterauth.CreateQuery{
		Model: betterauth.ModelVerification, ForceAllowID: true,
		Data: betterauth.Record{
			"id": id, "identifier": identifier, "value": betterauth.HashToken(raw),
			"expiresAt": now.Add(instance.config.StateTTL), "createdAt": now,
			"metadata": map[string]string{
				"providerId": state.ProviderID, "verifier": state.Verifier,
				"nonce": state.Nonce, "redirectURI": state.RedirectURI,
				"returnTo": state.ReturnTo, "newUserTo": state.NewUserTo,
				"errorTo": state.ErrorTo, "requestId": state.RequestID,
				"requestSignUp": strconv.FormatBool(state.RequestSignUp),
			},
		},
	})
	return raw, err
}

func (instance *runtime) consumeState(
	ctx *betterauth.HookContext,
	identifier, raw string,
) (protocolState, error) {
	if len(raw) < 20 || len(raw) > 2048 {
		return protocolState{}, betterauth.ErrReplay
	}
	record, err := ctx.Database.ConsumeOne(ctx.Context, betterauth.DeleteQuery{
		Model: betterauth.ModelVerification,
		Where: []betterauth.Where{
			betterauth.Eq("identifier", identifier),
			betterauth.Eq("value", betterauth.HashToken(raw)),
			{Field: "expiresAt", Operator: betterauth.WhereGT, Value: ctx.Clock.Now().UTC()},
		},
	})
	if err != nil || record == nil {
		return protocolState{}, betterauth.ErrReplay
	}
	metadata := stringMapRecord(record["metadata"])
	return protocolState{
		ProviderID: metadata["providerId"], Verifier: metadata["verifier"],
		Nonce: metadata["nonce"], RedirectURI: metadata["redirectURI"],
		ReturnTo: metadata["returnTo"], NewUserTo: metadata["newUserTo"],
		ErrorTo: metadata["errorTo"], RequestID: metadata["requestId"],
		RequestSignUp: metadata["requestSignUp"] == "true",
	}, nil
}

func stringMapRecord(value any) map[string]string {
	if values, ok := value.(map[string]string); ok {
		return values
	}
	result := map[string]string{}
	if values, ok := value.(map[string]any); ok {
		for key, value := range values {
			if text, ok := value.(string); ok {
				result[key] = text
			}
		}
	}
	return result
}

func pkceChallenge(verifier string) string {
	digest := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func safeReturnTo(ctx *betterauth.HookContext, value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}
	if err := validateRedirectURI(value, ctx.BaseURL, ctx.TrustedOrigins); err != nil {
		return "", err
	}
	if strings.HasPrefix(value, "/") {
		return strings.TrimSuffix(ctx.BaseURL, "/") + value, nil
	}
	return value, nil
}

func emailDomain(email string) string {
	index := strings.LastIndex(strings.TrimSpace(strings.ToLower(email)), "@")
	if index < 1 || index == len(email)-1 {
		return ""
	}
	return strings.TrimSuffix(email[index+1:], ".")
}

func domainAllowed(configured, actual string) bool {
	actual = strings.ToLower(strings.TrimSpace(actual))
	for _, domain := range strings.Split(configured, ",") {
		domain = strings.ToLower(strings.TrimSpace(domain))
		if actual == domain {
			return true
		}
	}
	return false
}

func normalizeDomains(value string) (string, error) {
	parts := strings.Split(value, ",")
	if len(parts) == 0 || len(parts) > 32 {
		return "", errors.New("invalid provider domain")
	}
	seen := map[string]struct{}{}
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		domain, err := normalizeDomain(part)
		if err != nil {
			return "", err
		}
		if _, exists := seen[domain]; exists {
			continue
		}
		seen[domain] = struct{}{}
		result = append(result, domain)
	}
	return strings.Join(result, ","), nil
}
