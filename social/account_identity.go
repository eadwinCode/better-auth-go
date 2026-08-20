package social

import (
	"errors"
	"fmt"
	"strings"
)

func isBuiltInProvider(providerID string) bool {
	for _, candidate := range SupportedProviders {
		if candidate == providerID {
			return true
		}
	}
	return false
}

func providerAccountSubject(providerID string, raw map[string]any) (string, error) {
	profile := unwrapProfile(raw)
	var subject string
	switch providerID {
	case "apple", "cognito", "google", "huggingface", "line", "linkedin",
		"paybin", "railway", "roblox", "twitch", "vercel":
		subject = firstString(profile, "sub")
	case "atlassian", "dropbox":
		subject = firstString(profile, "account_id")
	case "kick", "salesforce":
		subject = firstString(profile, "user_id")
	case "paypal":
		subject = firstString(profile, "user_id")
	case "slack":
		subject = firstString(profile, "https://slack.com/user_id")
	case "tiktok":
		if user := nestedMap(profile, "user"); user != nil {
			subject = firstString(user, "open_id")
		}
		if subject == "" {
			subject = firstString(profile, "open_id")
		}
	case "twitter":
		subject = firstString(profile, "id")
	case "vk":
		if user := nestedMap(profile, "user"); user != nil {
			subject = firstString(user, "user_id")
		}
		if subject == "" {
			subject = firstString(profile, "user_id")
		}
	case "wechat":
		subject = firstString(profile, "unionid", "openid")
	default:
		// The remaining built-ins publish an immutable numeric/string id. A
		// custom provider should configure Options.AccountSubject explicitly.
		subject = firstString(profile, "id")
	}
	if strings.TrimSpace(subject) == "" {
		return "", errors.New("social: profile has no immutable account subject")
	}
	return subject, nil
}

func microsoftClaimsValidator(authority, configuredTenant string) func(map[string]any) error {
	authority = strings.TrimRight(authority, "/")
	configuredTenant = strings.TrimSpace(configuredTenant)
	return func(claims map[string]any) error {
		tenantID := strings.TrimSpace(stringValue(claims["tid"]))
		issuer := strings.TrimSpace(stringValue(claims["iss"]))
		oid := strings.TrimSpace(stringValue(claims["oid"]))
		if tenantID == "" || oid == "" || issuer != authority+"/"+tenantID+"/v2.0" {
			return errors.New("social: invalid Microsoft Entra identity claims")
		}
		switch strings.ToLower(configuredTenant) {
		case "common", "organizations", "consumers":
			if !looksLikeGUID(tenantID) {
				return errors.New("social: invalid Microsoft Entra tenant ID")
			}
		default:
			if !strings.EqualFold(configuredTenant, tenantID) {
				return fmt.Errorf("social: Microsoft Entra tenant mismatch")
			}
		}
		return nil
	}
}

func looksLikeGUID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for index, character := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			if character != '-' {
				return false
			}
			continue
		}
		if !((character >= '0' && character <= '9') ||
			(character >= 'a' && character <= 'f') ||
			(character >= 'A' && character <= 'F')) {
			return false
		}
	}
	return true
}
