package betterauth

import (
	"errors"
	"strings"
)

const CredentialAccountIssuer = "local:credential"

// OAuthAccountIssuer returns the synthetic namespace used by an OAuth
// provider that has no protocol issuer of its own. Provider IDs are escaped so
// an application-defined ID cannot cross namespace boundaries.
func OAuthAccountIssuer(providerID string) (string, error) {
	providerID = strings.TrimSpace(providerID)
	if providerID == "" {
		return "", errors.New("betterauth: OAuth provider ID is required")
	}
	return "local:oauth:" + percentEncodeIdentityComponent(providerID), nil
}

func percentEncodeIdentityComponent(value string) string {
	const hexadecimal = "0123456789ABCDEF"
	var encoded strings.Builder
	for index := 0; index < len(value); index++ {
		character := value[index]
		if character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' ||
			character == '-' || character == '.' || character == '_' || character == '~' {
			encoded.WriteByte(character)
			continue
		}
		encoded.WriteByte('%')
		encoded.WriteByte(hexadecimal[character>>4])
		encoded.WriteByte(hexadecimal[character&15])
	}
	return encoded.String()
}

func accountIdentityWhere(issuer, accountID string) []Where {
	return []Where{Eq("issuer", issuer), Eq("accountId", accountID)}
}

func credentialIdentityWhere(userID string) []Where {
	return []Where{
		Eq("issuer", CredentialAccountIssuer),
		Eq("accountId", userID),
		Eq("providerId", credentialProvider),
	}
}
