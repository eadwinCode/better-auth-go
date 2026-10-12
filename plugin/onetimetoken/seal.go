package onetimetoken

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
)

const (
	sealPrefix  = "v1."
	sealKeyInfo = "better-auth-go/one-time-token/session-key/v1"
	sealAAD     = "better-auth-go/one-time-token/session/v1"
)

// Better Auth stores the raw session token next to the one-time token. Go
// never stores raw session tokens, so it seals the session token with
// AES-256-GCM under a key derived from the one-time token. Only the holder of
// the one-time token can open it. The key derivation is separate from the
// stored hash, and the stored value is bound in as extra authenticated data
// so a sealed value cannot be moved to another record.

func sessionAEAD(token string) (cipher.AEAD, error) {
	mac := hmac.New(sha256.New, []byte(token))
	mac.Write([]byte(sealKeyInfo))
	block, err := aes.NewCipher(mac.Sum(nil))
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func sealSession(token, stored, rawSession string) (string, error) {
	if token == "" || rawSession == "" {
		return "", errors.New("onetimetoken: cannot seal an empty value")
	}
	aead, err := sessionAEAD(token)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := aead.Seal(nonce, nonce, []byte(rawSession), []byte(sealAAD+"\x00"+stored))
	return sealPrefix + base64.RawURLEncoding.EncodeToString(sealed), nil
}

func openSession(token, stored, sealed string) (string, error) {
	invalid := errors.New("onetimetoken: invalid sealed session")
	encoded, ok := strings.CutPrefix(sealed, sealPrefix)
	if !ok || len(encoded) > 8192 {
		return "", invalid
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil {
		return "", invalid
	}
	aead, err := sessionAEAD(token)
	if err != nil {
		return "", err
	}
	if len(payload) <= aead.NonceSize()+aead.Overhead() {
		return "", invalid
	}
	plain, err := aead.Open(nil, payload[:aead.NonceSize()], payload[aead.NonceSize():],
		[]byte(sealAAD+"\x00"+stored))
	if err != nil || len(plain) == 0 {
		return "", invalid
	}
	return string(plain), nil
}
