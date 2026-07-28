package betterauth

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
)

const providerTokenAAD = "better-auth-go/provider-token/v1"

type AESGCMTokenCipher struct {
	aead cipher.AEAD
}

func NewAESGCMTokenCipher(key []byte) (*AESGCMTokenCipher, error) {
	if len(key) != 32 {
		return nil, errors.New("betterauth: provider token encryption key must be 32 bytes")
	}
	keyCopy := append([]byte(nil), key...)
	block, err := aes.NewCipher(keyCopy)
	for index := range keyCopy {
		keyCopy[index] = 0
	}
	if err != nil {
		return nil, fmt.Errorf("betterauth: provider token cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("betterauth: provider token cipher: %w", err)
	}
	return &AESGCMTokenCipher{aead: aead}, nil
}

func (c *AESGCMTokenCipher) Seal(_ context.Context, plaintext string) (string, error) {
	if plaintext == "" || len(plaintext) > 1<<20 {
		return "", errors.New("betterauth: provider token plaintext is empty or too large")
	}
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("betterauth: provider token nonce: %w", err)
	}
	sealed := c.aead.Seal(nil, nonce, []byte(plaintext), []byte(providerTokenAAD))
	payload := append(nonce, sealed...)
	return "v1." + base64.RawURLEncoding.EncodeToString(payload), nil
}

func (c *AESGCMTokenCipher) Open(_ context.Context, encoded string) (string, error) {
	if !strings.HasPrefix(encoded, "v1.") || len(encoded) > 2<<20 {
		return "", errors.New("betterauth: invalid encrypted provider token")
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(strings.TrimPrefix(encoded, "v1."))
	if err != nil || len(payload) <= c.aead.NonceSize()+c.aead.Overhead() {
		return "", errors.New("betterauth: invalid encrypted provider token")
	}
	nonce := payload[:c.aead.NonceSize()]
	ciphertext := payload[c.aead.NonceSize():]
	plaintext, err := c.aead.Open(nil, nonce, ciphertext, []byte(providerTokenAAD))
	if err != nil {
		return "", errors.New("betterauth: invalid encrypted provider token")
	}
	return string(plaintext), nil
}

var _ TokenCipher = (*AESGCMTokenCipher)(nil)
