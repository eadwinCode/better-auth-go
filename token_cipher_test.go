package betterauth

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
)

func TestAESGCMTokenCipher(t *testing.T) {
	t.Parallel()
	cipher, err := NewAESGCMTokenCipher([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	first, err := cipher.Seal(context.Background(), "provider-secret")
	if err != nil {
		t.Fatal(err)
	}
	second, err := cipher.Seal(context.Background(), "provider-secret")
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("ciphertext nonce was reused")
	}
	plaintext, err := cipher.Open(context.Background(), first)
	if err != nil {
		t.Fatal(err)
	}
	if plaintext != "provider-secret" {
		t.Fatalf("unexpected plaintext %q", plaintext)
	}
}

func TestAESGCMTokenCipherRejectsTampering(t *testing.T) {
	t.Parallel()
	cipher, err := NewAESGCMTokenCipher([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := cipher.Seal(context.Background(), "provider-secret")
	if err != nil {
		t.Fatal(err)
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(strings.TrimPrefix(encoded, "v1."))
	if err != nil {
		t.Fatal(err)
	}
	payload[len(payload)-1] ^= 0x01
	tampered := "v1." + base64.RawURLEncoding.EncodeToString(payload)
	if _, err := cipher.Open(context.Background(), tampered); err == nil {
		t.Fatal("tampered ciphertext opened")
	}
}

func FuzzAESGCMTokenCipherOpen(f *testing.F) {
	cipher, err := NewAESGCMTokenCipher([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add("v1.invalid")
	f.Add("")
	f.Fuzz(func(t *testing.T, encoded string) {
		if len(encoded) > 4096 {
			t.Skip()
		}
		_, _ = cipher.Open(context.Background(), encoded)
	})
}
