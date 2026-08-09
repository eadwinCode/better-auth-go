package betterauth

import (
	"errors"
	"fmt"
	"strings"
)

const placeholderEmailDomain = "placeholder.invalid"

// ErrInvalidPlaceholderEmail reports an invalid placeholder email component.
var ErrInvalidPlaceholderEmail = errors.New("betterauth: invalid placeholder email")

// PlaceholderEmailOptions identifies an account that has no deliverable email
// address. Namespace must distinguish independently managed identity sources.
type PlaceholderEmailOptions struct {
	Identifier string
	Namespace  string
}

// CreatePlaceholderEmail returns a deterministic, non-routable email address
// on the RFC 6761 reserved placeholder.invalid domain.
//
// Identifier must be an ASCII dot-atom local part. Namespace must be one or
// more ASCII DNS labels. Inputs are preserved exactly so repeated calls with
// the same options produce the same address and equal identifiers in different
// namespaces cannot collide.
func CreatePlaceholderEmail(options PlaceholderEmailOptions) (string, error) {
	if !validPlaceholderLocalPart(options.Identifier) {
		return "", fmt.Errorf("%w: invalid identifier", ErrInvalidPlaceholderEmail)
	}
	if !validPlaceholderNamespace(options.Namespace) {
		return "", fmt.Errorf("%w: invalid namespace", ErrInvalidPlaceholderEmail)
	}
	email := options.Identifier + "@" + options.Namespace + "." + placeholderEmailDomain
	if len(email) > 254 {
		return "", fmt.Errorf("%w: address is too long", ErrInvalidPlaceholderEmail)
	}
	return email, nil
}

func validPlaceholderLocalPart(value string) bool {
	if value == "" || len(value) > 64 || value[0] == '.' || value[len(value)-1] == '.' || strings.Contains(value, "..") {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' ||
			strings.ContainsRune("!#$%&'*+-/=?^_`{|}~.", rune(character)) {
			continue
		}
		return false
	}
	return true
}

func validPlaceholderNamespace(value string) bool {
	if value == "" || len(value) > 215 {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for index := 0; index < len(label); index++ {
			character := label[index]
			if character >= 'a' && character <= 'z' ||
				character >= 'A' && character <= 'Z' ||
				character >= '0' && character <= '9' || character == '-' {
				continue
			}
			return false
		}
	}
	return true
}
