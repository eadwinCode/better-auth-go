package betterauth

import "strings"

func mergeOAuthScopes(existing, incoming string) string {
	ordered := make([]string, 0)
	seen := make(map[string]struct{})
	for _, raw := range []string{existing, incoming} {
		for _, scope := range strings.Fields(raw) {
			if _, duplicate := seen[scope]; duplicate {
				continue
			}
			seen[scope] = struct{}{}
			ordered = append(ordered, scope)
		}
	}
	return strings.Join(ordered, " ")
}
