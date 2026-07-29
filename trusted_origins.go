package betterauth

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

const (
	maxTrustedOriginCount  = 128
	maxTrustedOriginLength = 2048
)

type trustedOriginPattern struct {
	value    string
	scheme   string
	port     string
	hostname *regexp.Regexp
}

type trustedOriginPolicy struct {
	values   []string
	exact    map[string]struct{}
	patterns []trustedOriginPattern
}

type trustedOriginResolution struct {
	policy trustedOriginPolicy
	err    error
}

type trustedOriginContextKey struct{}

func compileTrustedOriginPolicy(values []string) (trustedOriginPolicy, error) {
	if len(values) > maxTrustedOriginCount {
		return trustedOriginPolicy{}, errors.New("too many trusted origins")
	}
	policy := trustedOriginPolicy{exact: make(map[string]struct{}, len(values))}
	seen := make(map[string]struct{}, len(values))
	for _, raw := range values {
		raw = strings.TrimSpace(raw)
		if raw == "" || len(raw) > maxTrustedOriginLength {
			return trustedOriginPolicy{}, errors.New("trusted origin is empty or too long")
		}
		if strings.ContainsAny(raw, "\x00\r\n\t ") {
			return trustedOriginPolicy{}, errors.New("trusted origin contains whitespace")
		}
		if strings.ContainsAny(raw, "*?") {
			pattern, err := compileTrustedOriginPattern(raw)
			if err != nil {
				return trustedOriginPolicy{}, err
			}
			if _, duplicate := seen[pattern.value]; duplicate {
				continue
			}
			seen[pattern.value] = struct{}{}
			policy.values = append(policy.values, pattern.value)
			policy.patterns = append(policy.patterns, pattern)
			continue
		}
		origin, err := canonicalTrustedOrigin(raw)
		if err != nil {
			return trustedOriginPolicy{}, err
		}
		if _, duplicate := seen[origin]; duplicate {
			continue
		}
		seen[origin] = struct{}{}
		policy.values = append(policy.values, origin)
		policy.exact[origin] = struct{}{}
	}
	return policy, nil
}

func compileTrustedOriginPattern(raw string) (trustedOriginPattern, error) {
	scheme, authority, found := strings.Cut(raw, "://")
	if !found || scheme == "" || authority == "" {
		return trustedOriginPattern{}, fmt.Errorf("trusted origin pattern %q must be an absolute URL", raw)
	}
	if scheme != "https" {
		return trustedOriginPattern{}, fmt.Errorf("trusted origin pattern %q must use HTTPS", raw)
	}
	authority = strings.TrimSuffix(authority, "/")
	if authority == "" || strings.Contains(authority, "/") ||
		strings.ContainsAny(authority, "@#") {
		return trustedOriginPattern{}, fmt.Errorf(
			"trusted origin pattern %q cannot contain credentials, a path, query, or fragment",
			raw,
		)
	}
	hostname := authority
	port := ""
	if separator := strings.LastIndexByte(authority, ':'); separator >= 0 {
		if strings.Count(authority, ":") != 1 {
			return trustedOriginPattern{}, fmt.Errorf(
				"trusted origin pattern %q has an invalid host or port",
				raw,
			)
		}
		hostname, port = authority[:separator], authority[separator+1:]
		if port == "" {
			return trustedOriginPattern{}, fmt.Errorf(
				"trusted origin pattern %q has an empty port",
				raw,
			)
		}
	}
	hostname = strings.ToLower(strings.TrimSuffix(hostname, "."))
	if hostname == "" || !strings.ContainsAny(hostname, "*?") ||
		net.ParseIP(strings.ReplaceAll(strings.ReplaceAll(hostname, "*", "1"), "?", "1")) != nil {
		return trustedOriginPattern{}, fmt.Errorf("trusted origin pattern %q has an invalid hostname", raw)
	}
	if strings.ContainsAny(port, "*?") {
		return trustedOriginPattern{}, fmt.Errorf("trusted origin pattern %q has a wildcard port", raw)
	}
	if port != "" {
		number, parseErr := strconv.Atoi(port)
		if parseErr != nil || number < 1 || number > 65535 {
			return trustedOriginPattern{}, fmt.Errorf("trusted origin pattern %q has an invalid port", raw)
		}
	}

	labels := strings.Split(hostname, ".")
	asciiLabels := make([]string, len(labels))
	sampleLabels := make([]string, len(labels))
	firstWildcardLabel := -1
	for index, label := range labels {
		if label == "" {
			return trustedOriginPattern{}, fmt.Errorf("trusted origin pattern %q has an empty hostname label", raw)
		}
		if strings.ContainsAny(label, "*?") {
			if firstWildcardLabel < 0 {
				firstWildcardLabel = index
			}
			for _, character := range label {
				if (character < 'a' || character > 'z') &&
					(character < '0' || character > '9') &&
					character != '-' && character != '*' && character != '?' {
					return trustedOriginPattern{}, fmt.Errorf(
						"trusted origin pattern %q has an invalid wildcard label",
						raw,
					)
				}
			}
			asciiLabels[index] = label
			sampleLabels[index] = "wildcardtoken"
			continue
		}
		ascii, convertErr := idna.Lookup.ToASCII(label)
		if convertErr != nil || ascii == "" || len(ascii) > 63 {
			return trustedOriginPattern{}, fmt.Errorf(
				"trusted origin pattern %q has an invalid hostname label",
				raw,
			)
		}
		asciiLabels[index] = strings.ToLower(ascii)
		sampleLabels[index] = strings.ToLower(ascii)
	}
	if firstWildcardLabel >= 0 && firstWildcardLabel+1 < len(asciiLabels) &&
		net.ParseIP(strings.Join(asciiLabels[firstWildcardLabel+1:], ".")) != nil {
		return trustedOriginPattern{}, fmt.Errorf(
			"trusted origin pattern %q cannot match an IP address",
			raw,
		)
	}
	sampleHost := strings.Join(sampleLabels, ".")
	registrable, err := publicsuffix.EffectiveTLDPlusOne(sampleHost)
	if err != nil || strings.Contains(registrable, "wildcardtoken") {
		return trustedOriginPattern{}, fmt.Errorf(
			"trusted origin pattern %q can match a public suffix",
			raw,
		)
	}
	asciiHostname := strings.Join(asciiLabels, ".")
	var expression strings.Builder
	expression.WriteString("^(?:")
	for _, character := range asciiHostname {
		switch character {
		case '*':
			expression.WriteString("[a-z0-9.-]*")
		case '?':
			expression.WriteString("[a-z0-9.-]")
		default:
			expression.WriteString(regexp.QuoteMeta(string(character)))
		}
	}
	expression.WriteString(")$")
	compiled, err := regexp.Compile(expression.String())
	if err != nil {
		return trustedOriginPattern{}, fmt.Errorf("compile trusted origin pattern %q: %w", raw, err)
	}
	host := asciiHostname
	if port != "" {
		host = net.JoinHostPort(host, port)
	}
	return trustedOriginPattern{
		value: "https://" + host, scheme: "https", port: port, hostname: compiled,
	}, nil
}

func canonicalTrustedOrigin(raw string) (string, error) {
	parsed, err := validateHTTPSURL(raw, false)
	if err != nil {
		return "", err
	}
	rawHostname := strings.TrimSuffix(parsed.Hostname(), ".")
	hostname := ""
	if ip := net.ParseIP(rawHostname); ip != nil {
		hostname = ip.String()
	} else {
		hostname, err = idna.Lookup.ToASCII(rawHostname)
		if err != nil || hostname == "" {
			return "", errors.New("origin hostname is invalid")
		}
	}
	hostname = strings.ToLower(hostname)
	host := hostname
	if strings.Contains(hostname, ":") {
		host = "[" + hostname + "]"
	}
	if port := parsed.Port(); port != "" {
		host = net.JoinHostPort(hostname, port)
	}
	return parsed.Scheme + "://" + host, nil
}

func (policy trustedOriginPolicy) matches(raw string) bool {
	origin, err := canonicalTrustedOrigin(raw)
	if err != nil {
		return false
	}
	if _, found := policy.exact[origin]; found {
		return true
	}
	parsed, err := url.Parse(origin)
	if err != nil {
		return false
	}
	hostname := strings.ToLower(parsed.Hostname())
	for _, pattern := range policy.patterns {
		if parsed.Scheme == pattern.scheme && parsed.Port() == pattern.port &&
			pattern.hostname.MatchString(hostname) {
			return true
		}
	}
	return false
}

func (policy trustedOriginPolicy) merged(other trustedOriginPolicy) trustedOriginPolicy {
	if len(other.values) == 0 {
		return policy
	}
	result := trustedOriginPolicy{
		values:   append([]string(nil), policy.values...),
		exact:    make(map[string]struct{}, len(policy.exact)+len(other.exact)),
		patterns: append(append([]trustedOriginPattern(nil), policy.patterns...), other.patterns...),
	}
	seen := make(map[string]struct{}, len(policy.values)+len(other.values))
	for _, value := range policy.values {
		seen[value] = struct{}{}
	}
	for _, value := range other.values {
		if _, duplicate := seen[value]; duplicate {
			continue
		}
		seen[value] = struct{}{}
		result.values = append(result.values, value)
	}
	for origin := range policy.exact {
		result.exact[origin] = struct{}{}
	}
	for origin := range other.exact {
		result.exact[origin] = struct{}{}
	}
	return result
}

func (s *Server) resolveTrustedOrigins(r *http.Request) (trustedOriginPolicy, error) {
	if cached, ok := r.Context().Value(trustedOriginContextKey{}).(trustedOriginResolution); ok {
		return cached.policy, cached.err
	}
	resolved := trustedOriginResolution{policy: s.trustedOrigins}
	if s.cfg.TrustedOriginResolver != nil {
		values, err := callTrustedOriginResolver(s.cfg.TrustedOriginResolver, r)
		if err != nil {
			resolved.err = publicError(
				CodeInvalidOrigin, "Invalid origin", http.StatusForbidden, err,
			)
		} else {
			dynamic, compileErr := compileTrustedOriginPolicy(values)
			if compileErr != nil {
				resolved.err = publicError(
					CodeInvalidOrigin, "Invalid origin", http.StatusForbidden, compileErr,
				)
			} else {
				resolved.policy = resolved.policy.merged(dynamic)
				if len(resolved.policy.values) > maxTrustedOriginCount {
					resolved.err = publicError(
						CodeInvalidOrigin,
						"Invalid origin",
						http.StatusForbidden,
						errors.New("too many resolved trusted origins"),
					)
				}
			}
		}
	}
	*r = *r.WithContext(context.WithValue(r.Context(), trustedOriginContextKey{}, resolved))
	return resolved.policy, resolved.err
}

func callTrustedOriginResolver(
	resolver TrustedOriginResolver,
	request *http.Request,
) (values []string, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			values = nil
			err = fmt.Errorf("betterauth: trusted origin resolver panicked")
		}
	}()
	values, err = resolver.TrustedOrigins(request.Context(), request)
	if err != nil {
		return nil, fmt.Errorf("betterauth: trusted origin resolver: %w", err)
	}
	return append([]string(nil), values...), nil
}
