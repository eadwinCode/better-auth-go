package social

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

type idTokenVerifier struct {
	client           *http.Client
	jwksURL          string
	issuers          []string
	audience         string
	maxResponseBytes int64

	mu        sync.RWMutex
	keys      map[string]*rsa.PublicKey
	expiresAt time.Time
}

func (v *idTokenVerifier) Verify(ctx context.Context, raw, expectedNonce string) (map[string]any, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 || len(raw) > 64<<10 {
		return nil, errors.New("social: malformed ID token")
	}
	headerBytes, err := base64.RawURLEncoding.Strict().DecodeString(parts[0])
	if err != nil {
		return nil, errors.New("social: malformed ID token header")
	}
	var header struct {
		Algorithm string `json:"alg"`
		KeyID     string `json:"kid"`
		Type      string `json:"typ"`
	}
	if err := strictJSON(headerBytes, &header); err != nil || header.Algorithm != "RS256" || header.KeyID == "" {
		return nil, errors.New("social: unsupported ID token header")
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if err != nil || len(signature) > 1024 {
		return nil, errors.New("social: malformed ID token signature")
	}
	key, err := v.key(ctx, header.KeyID, false)
	if errors.Is(err, errUnknownKey) {
		key, err = v.key(ctx, header.KeyID, true)
	}
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature); err != nil {
		return nil, errors.New("social: invalid ID token signature")
	}
	claimsBytes, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if err != nil || len(claimsBytes) > 1<<20 {
		return nil, errors.New("social: malformed ID token claims")
	}
	var claims map[string]any
	if err := strictJSON(claimsBytes, &claims); err != nil {
		return nil, errors.New("social: malformed ID token claims")
	}
	now := time.Now().UTC()
	expiry, ok := numericDate(claims["exp"])
	if !ok || !expiry.After(now.Add(-30*time.Second)) || expiry.After(now.Add(24*time.Hour)) {
		return nil, errors.New("social: expired or invalid ID token")
	}
	if notBefore, exists := claims["nbf"]; exists {
		value, valid := numericDate(notBefore)
		if !valid || value.After(now.Add(30*time.Second)) {
			return nil, errors.New("social: ID token is not active")
		}
	}
	issuer := stringValue(claims["iss"])
	if !contains(v.issuers, issuer) {
		return nil, errors.New("social: invalid ID token issuer")
	}
	if !audienceContains(claims["aud"], v.audience) {
		return nil, errors.New("social: invalid ID token audience")
	}
	if expectedNonce != "" && stringValue(claims["nonce"]) != expectedNonce {
		return nil, errors.New("social: invalid ID token nonce")
	}
	if stringValue(claims["sub"]) == "" {
		return nil, errors.New("social: ID token has no subject")
	}
	return claims, nil
}

var errUnknownKey = errors.New("social: unknown signing key")

func (v *idTokenVerifier) key(ctx context.Context, keyID string, force bool) (*rsa.PublicKey, error) {
	v.mu.RLock()
	key := v.keys[keyID]
	fresh := time.Now().Before(v.expiresAt)
	v.mu.RUnlock()
	if key != nil && fresh && !force {
		return key, nil
	}
	if err := v.refresh(ctx); err != nil {
		return nil, err
	}
	v.mu.RLock()
	key = v.keys[keyID]
	v.mu.RUnlock()
	if key == nil {
		return nil, errUnknownKey
	}
	return key, nil
}

func (v *idTokenVerifier) refresh(ctx context.Context) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, v.jwksURL, nil)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/json")
	response, err := v.client.Do(request)
	if err != nil {
		return fmt.Errorf("social: fetch JWKS: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return fmt.Errorf("social: JWKS returned HTTP %d", response.StatusCode)
	}
	var document struct {
		Keys []struct {
			KeyType   string `json:"kty"`
			KeyID     string `json:"kid"`
			Use       string `json:"use"`
			Algorithm string `json:"alg"`
			Modulus   string `json:"n"`
			Exponent  string `json:"e"`
		} `json:"keys"`
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, v.maxResponseBytes+1))
	if err := decoder.Decode(&document); err != nil {
		return fmt.Errorf("social: invalid JWKS: %w", err)
	}
	if len(document.Keys) == 0 || len(document.Keys) > 100 {
		return errors.New("social: invalid JWKS key count")
	}
	keys := make(map[string]*rsa.PublicKey, len(document.Keys))
	for _, jwk := range document.Keys {
		if jwk.KeyType != "RSA" || jwk.KeyID == "" || (jwk.Algorithm != "" && jwk.Algorithm != "RS256") {
			continue
		}
		modulus, err := base64.RawURLEncoding.Strict().DecodeString(jwk.Modulus)
		if err != nil || len(modulus) < 256 || len(modulus) > 1024 {
			continue
		}
		exponentBytes, err := base64.RawURLEncoding.Strict().DecodeString(jwk.Exponent)
		if err != nil || len(exponentBytes) == 0 || len(exponentBytes) > 4 {
			continue
		}
		exponent := 0
		for _, value := range exponentBytes {
			exponent = exponent<<8 | int(value)
		}
		if exponent < 3 || exponent%2 == 0 {
			continue
		}
		keys[jwk.KeyID] = &rsa.PublicKey{N: new(big.Int).SetBytes(modulus), E: exponent}
	}
	if len(keys) == 0 {
		return errors.New("social: JWKS contains no supported keys")
	}
	v.keys = keys
	v.expiresAt = time.Now().Add(15 * time.Minute)
	return nil
}

func strictJSON(raw []byte, destination any) error {
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON")
	}
	return nil
}

func numericDate(value any) (time.Time, bool) {
	switch typed := value.(type) {
	case json.Number:
		seconds, err := typed.Int64()
		if err != nil {
			float, floatErr := strconv.ParseFloat(typed.String(), 64)
			if floatErr != nil {
				return time.Time{}, false
			}
			return time.Unix(int64(float), 0).UTC(), true
		}
		return time.Unix(seconds, 0).UTC(), true
	case float64:
		return time.Unix(int64(typed), 0).UTC(), true
	default:
		return time.Time{}, false
	}
}

func audienceContains(value any, expected string) bool {
	switch typed := value.(type) {
	case string:
		return typed == expected
	case []any:
		for _, item := range typed {
			if stringValue(item) == expected {
				return true
			}
		}
	}
	return false
}

func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
