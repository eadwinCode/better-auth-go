package scim

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strings"

	betterauth "github.com/eadwinCode/better-auth-go"
)

type bearerClaims struct {
	Secret         string
	ProviderID     string
	OrganizationID string
	TokenHash      string
}

func encodeBearerToken(secret, providerID, organizationID string) (string, error) {
	secret = strings.TrimSpace(secret)
	providerID = strings.ToLower(strings.TrimSpace(providerID))
	organizationID = strings.TrimSpace(organizationID)
	if len(secret) < 22 || len(secret) > 1024 || strings.Contains(secret, ":") ||
		!validIdentifier(providerID, 128) || strings.Contains(organizationID, ":") ||
		len(organizationID) > 512 {
		return "", errors.New("scim: invalid bearer token fields")
	}
	value := secret + ":" + providerID
	if organizationID != "" {
		value += ":" + organizationID
	}
	return base64.RawURLEncoding.EncodeToString([]byte(value)), nil
}

func parseBearerToken(raw string, maxBytes int) (bearerClaims, error) {
	var result bearerClaims
	raw = strings.TrimSpace(raw)
	if maxBytes <= 0 {
		maxBytes = 2048
	}
	if raw == "" || len(raw) > maxBytes {
		return result, errors.New("scim: invalid bearer token")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil || len(decoded) == 0 || len(decoded) > maxBytes {
		return result, errors.New("scim: invalid bearer token")
	}
	parts := strings.Split(string(decoded), ":")
	if len(parts) != 2 && len(parts) != 3 {
		return result, errors.New("scim: invalid bearer token")
	}
	result.Secret = parts[0]
	result.ProviderID = strings.ToLower(parts[1])
	if len(parts) == 3 {
		result.OrganizationID = parts[2]
	}
	if len(result.Secret) < 22 || len(result.Secret) > 1024 ||
		!validIdentifier(result.ProviderID, 128) ||
		len(result.OrganizationID) > 512 || strings.TrimSpace(result.OrganizationID) != result.OrganizationID {
		return bearerClaims{}, errors.New("scim: invalid bearer token")
	}
	result.TokenHash = betterauth.HashToken(result.Secret)
	return result, nil
}

func tokenHashMatches(left, right string) bool {
	return len(left) == len(right) &&
		subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}
