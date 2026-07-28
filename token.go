package betterauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

type CryptoTokenSource struct{}

func (CryptoTokenSource) Token(byteLength int) (string, error) {
	if byteLength < 16 || byteLength > 1024 {
		return "", fmt.Errorf("betterauth: token byte length out of bounds")
	}
	value := make([]byte, byteLength)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("betterauth: random token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

// HashToken returns a fixed-size, URL-safe representation suitable for storage.
func HashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
