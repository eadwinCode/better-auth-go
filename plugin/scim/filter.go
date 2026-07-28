package scim

import (
	"errors"
	"fmt"
	"strings"
)

var filterFields = map[string]string{
	"id":           "id",
	"username":     "email",
	"emails.value": "email",
	"externalid":   "accountId",
}

func parseFilter(value string, maxBytes, maxClauses int) ([]Filter, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	if maxBytes <= 0 {
		maxBytes = 2048
	}
	if maxClauses <= 0 {
		maxClauses = 10
	}
	if len(value) > maxBytes {
		return nil, errors.New("scim: filter is too large")
	}
	segments, err := splitFilterAND(value)
	if err != nil || len(segments) > maxClauses {
		return nil, errors.New("scim: invalidFilter")
	}
	result := make([]Filter, 0, len(segments))
	for _, segment := range segments {
		path, filterValue, parseErr := parseEquality(segment)
		if parseErr != nil {
			return nil, errors.New("scim: invalidFilter")
		}
		field, exists := filterFields[strings.ToLower(path)]
		if !exists {
			return nil, fmt.Errorf("scim: invalidFilter: unsupported path %q", path)
		}
		result = append(result, Filter{Path: path, Field: field, Value: filterValue})
	}
	return result, nil
}

func splitFilterAND(value string) ([]string, error) {
	var result []string
	start := 0
	quoted := false
	escaped := false
	for index := 0; index < len(value); index++ {
		switch {
		case escaped:
			escaped = false
		case value[index] == '\\' && quoted:
			escaped = true
		case value[index] == '"':
			quoted = !quoted
		case !quoted && index+5 <= len(value) &&
			strings.EqualFold(value[index:index+5], " and "):
			result = append(result, strings.TrimSpace(value[start:index]))
			start = index + 5
			index += 4
		}
	}
	if quoted || escaped {
		return nil, errors.New("unterminated filter string")
	}
	result = append(result, strings.TrimSpace(value[start:]))
	for _, item := range result {
		if item == "" {
			return nil, errors.New("empty filter clause")
		}
	}
	return result, nil
}

func parseEquality(value string) (string, string, error) {
	parts := strings.Fields(value)
	if len(parts) < 3 || !strings.EqualFold(parts[1], "eq") {
		return "", "", errors.New("expected equality")
	}
	path := parts[0]
	remainder := strings.TrimSpace(value[len(parts[0]):])
	if len(remainder) < 2 || !strings.EqualFold(remainder[:2], "eq") {
		return "", "", errors.New("expected equality")
	}
	remainder = strings.TrimSpace(remainder[2:])
	if len(remainder) < 2 || remainder[0] != '"' || remainder[len(remainder)-1] != '"' {
		return "", "", errors.New("expected quoted value")
	}
	quoted := remainder[1 : len(remainder)-1]
	var builder strings.Builder
	escaped := false
	for index := 0; index < len(quoted); index++ {
		character := quoted[index]
		if escaped {
			if character != '"' && character != '\\' {
				return "", "", errors.New("invalid escape")
			}
			builder.WriteByte(character)
			escaped = false
			continue
		}
		if character == '\\' {
			escaped = true
			continue
		}
		if character == '"' {
			return "", "", errors.New("unescaped quote")
		}
		if character < 0x20 {
			return "", "", errors.New("invalid control character")
		}
		builder.WriteByte(character)
	}
	if escaped || builder.Len() == 0 || builder.Len() > 512 {
		return "", "", errors.New("invalid filter value")
	}
	return path, builder.String(), nil
}
