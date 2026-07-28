package betterauth

import (
	"context"
	"strings"
	"testing"
)

func TestArgon2idHashAndVerify(t *testing.T) {
	t.Parallel()
	verifier, err := NewArgon2idVerifier(Argon2Params{
		Memory: 19 * 1024, Iterations: 2, Parallelism: 1, SaltLength: 16, KeyLength: 32,
	}, 1024)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := verifier.Hash(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash, "$argon2id$v=19$") {
		t.Fatalf("unexpected PHC hash: %q", hash)
	}
	result, err := verifier.Verify(context.Background(), hash, "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !result.Valid {
		t.Fatal("expected valid password")
	}
	wrong, err := verifier.Verify(context.Background(), hash, "wrong password")
	if err != nil {
		t.Fatal(err)
	}
	if wrong.Valid {
		t.Fatal("wrong password verified")
	}
}

func TestArgon2idRejectsHostileParameters(t *testing.T) {
	t.Parallel()
	verifier, err := NewArgon2idVerifier(DefaultArgon2Params(), 1024)
	if err != nil {
		t.Fatal(err)
	}
	hostile := "$argon2id$v=19$m=4294967295,t=3,p=2$c2FsdHNhbHRzYWx0c2FsdA$YWJjZA"
	result, err := verifier.Verify(context.Background(), hostile, "password")
	if err != nil {
		t.Fatal(err)
	}
	if result.Valid {
		t.Fatal("hostile hash verified")
	}
}

func TestArgon2idRehashesWeakerParameters(t *testing.T) {
	t.Parallel()
	weak, err := NewArgon2idVerifier(Argon2Params{
		Memory: 19 * 1024, Iterations: 2, Parallelism: 1, SaltLength: 16, KeyLength: 32,
	}, 1024)
	if err != nil {
		t.Fatal(err)
	}
	strong, err := NewArgon2idVerifier(Argon2Params{
		Memory: 20 * 1024, Iterations: 3, Parallelism: 1, SaltLength: 16, KeyLength: 32,
	}, 1024)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := weak.Hash(context.Background(), "migration password")
	if err != nil {
		t.Fatal(err)
	}
	result, err := strong.Verify(context.Background(), hash, "migration password")
	if err != nil {
		t.Fatal(err)
	}
	if !result.Valid || result.ReplacementHash == "" {
		t.Fatal("expected valid verification with replacement hash")
	}
}

func FuzzArgon2idParser(f *testing.F) {
	f.Add("$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0c2FsdA$YWJjZA", "password")
	f.Add("", "")
	verifier, err := NewArgon2idVerifier(DefaultArgon2Params(), 1024)
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, encoded, password string) {
		if len(encoded) > 4096 || len(password) > 2048 {
			t.Skip()
		}
		_, _ = verifier.Verify(context.Background(), encoded, password)
	})
}
