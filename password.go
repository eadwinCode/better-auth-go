package betterauth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	maxArgonMemory      = 1024 * 1024
	maxArgonIterations  = 20
	maxArgonParallelism = 32
)

type Argon2Params struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

func DefaultArgon2Params() Argon2Params {
	return Argon2Params{
		Memory:      64 * 1024,
		Iterations:  3,
		Parallelism: 2,
		SaltLength:  16,
		KeyLength:   32,
	}
}

func (p Argon2Params) validate() error {
	if p.Memory < 19*1024 || p.Memory > maxArgonMemory {
		return fmt.Errorf("argon2 memory must be between 19 MiB and 1 GiB")
	}
	if p.Iterations < 2 || p.Iterations > maxArgonIterations {
		return fmt.Errorf("argon2 iterations must be between 2 and %d", maxArgonIterations)
	}
	if p.Parallelism < 1 || p.Parallelism > maxArgonParallelism {
		return fmt.Errorf("argon2 parallelism must be between 1 and %d", maxArgonParallelism)
	}
	if p.SaltLength < 16 || p.SaltLength > 64 {
		return fmt.Errorf("argon2 salt length must be between 16 and 64 bytes")
	}
	if p.KeyLength < 16 || p.KeyLength > 64 {
		return fmt.Errorf("argon2 key length must be between 16 and 64 bytes")
	}
	return nil
}

// Argon2idVerifier is the native password format.
type Argon2idVerifier struct {
	Params      Argon2Params
	MaxPassword int
}

func NewArgon2idVerifier(params Argon2Params, maxPassword int) (*Argon2idVerifier, error) {
	if err := params.validate(); err != nil {
		return nil, err
	}
	if maxPassword < 64 || maxPassword > 1024*1024 {
		return nil, fmt.Errorf("maximum password length must be between 64 bytes and 1 MiB")
	}
	return &Argon2idVerifier{Params: params, MaxPassword: maxPassword}, nil
}

func (v *Argon2idVerifier) Hash(_ context.Context, password string) (string, error) {
	if len(password) == 0 || len(password) > v.MaxPassword {
		return "", errors.New("betterauth: password length out of bounds")
	}
	salt := make([]byte, v.Params.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("betterauth: password salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, v.Params.Iterations, v.Params.Memory, v.Params.Parallelism, v.Params.KeyLength)
	return fmt.Sprintf(
		"$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		v.Params.Memory,
		v.Params.Iterations,
		v.Params.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), nil
}

func (v *Argon2idVerifier) Verify(ctx context.Context, encoded, password string) (PasswordVerification, error) {
	if len(password) == 0 || len(password) > v.MaxPassword || len(encoded) > 1024 {
		return PasswordVerification{}, nil
	}
	params, salt, expected, err := parseArgon2id(encoded)
	if err != nil {
		return PasswordVerification{}, nil
	}
	actual := argon2.IDKey([]byte(password), salt, params.Iterations, params.Memory, params.Parallelism, uint32(len(expected)))
	if subtle.ConstantTimeCompare(actual, expected) != 1 {
		return PasswordVerification{}, nil
	}
	result := PasswordVerification{Valid: true}
	if params != v.Params {
		result.ReplacementHash, err = v.Hash(ctx, password)
		if err != nil {
			return PasswordVerification{}, err
		}
	}
	return result, nil
}

func parseArgon2id(encoded string) (Argon2Params, []byte, []byte, error) {
	var empty Argon2Params
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v=19" {
		return empty, nil, nil, errors.New("invalid argon2id PHC string")
	}
	fields := strings.Split(parts[3], ",")
	if len(fields) != 3 {
		return empty, nil, nil, errors.New("invalid argon2id parameters")
	}
	memory, err := parsePHCUint(fields[0], "m=", 32)
	if err != nil {
		return empty, nil, nil, err
	}
	iterations, err := parsePHCUint(fields[1], "t=", 32)
	if err != nil {
		return empty, nil, nil, err
	}
	parallelism, err := parsePHCUint(fields[2], "p=", 8)
	if err != nil {
		return empty, nil, nil, err
	}
	salt, err := base64.RawStdEncoding.Strict().DecodeString(parts[4])
	if err != nil {
		return empty, nil, nil, err
	}
	key, err := base64.RawStdEncoding.Strict().DecodeString(parts[5])
	if err != nil {
		return empty, nil, nil, err
	}
	params := Argon2Params{
		Memory:      uint32(memory),
		Iterations:  uint32(iterations),
		Parallelism: uint8(parallelism),
		SaltLength:  uint32(len(salt)),
		KeyLength:   uint32(len(key)),
	}
	if err := params.validate(); err != nil {
		return empty, nil, nil, err
	}
	return params, salt, key, nil
}

func parsePHCUint(value, prefix string, bits int) (uint64, error) {
	if !strings.HasPrefix(value, prefix) {
		return 0, errors.New("invalid argon2id parameter")
	}
	return strconv.ParseUint(strings.TrimPrefix(value, prefix), 10, bits)
}
