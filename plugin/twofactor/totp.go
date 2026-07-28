package twofactor

import (
	"crypto/hmac"
	"crypto/sha1" // TOTP interoperability requires HMAC-SHA-1 by default.
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func generateTOTPSecret(raw string) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).
		EncodeToString([]byte(raw))
}

func totpCode(secret string, at time.Time, period time.Duration, digits int) (string, error) {
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).
		DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil || len(decoded) < 16 {
		return "", errors.New("twofactor: invalid TOTP secret")
	}
	step := uint64(at.UTC().Unix() / int64(period/time.Second))
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], step)
	mac := hmac.New(sha1.New, decoded)
	_, _ = mac.Write(counter[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	modulus := uint32(1_000_000)
	if digits == 8 {
		modulus = 100_000_000
	}
	return fmt.Sprintf("%0*d", digits, value%modulus), nil
}

func verifyTOTP(
	secret string,
	candidate string,
	at time.Time,
	period time.Duration,
	digits int,
) bool {
	if len(candidate) != digits {
		return false
	}
	if _, err := strconv.ParseUint(candidate, 10, 32); err != nil {
		return false
	}
	var valid int
	for offset := -1; offset <= 1; offset++ {
		expected, err := totpCode(
			secret, at.Add(time.Duration(offset)*period), period, digits,
		)
		if err != nil {
			return false
		}
		valid |= subtle.ConstantTimeCompare([]byte(expected), []byte(candidate))
	}
	return valid == 1
}

func totpURI(issuer, account, secret string, period time.Duration, digits int) string {
	label := url.PathEscape(issuer + ":" + account)
	query := url.Values{
		"secret":    []string{secret},
		"issuer":    []string{issuer},
		"algorithm": []string{"SHA1"},
		"digits":    []string{strconv.Itoa(digits)},
		"period":    []string{strconv.FormatInt(int64(period/time.Second), 10)},
	}
	return "otpauth://totp/" + label + "?" + query.Encode()
}
