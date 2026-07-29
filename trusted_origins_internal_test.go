package betterauth

import "testing"

func FuzzTrustedOriginPolicy(f *testing.F) {
	for _, seed := range [][2]string{
		{"https://app.example.com", "https://app.example.com"},
		{"https://*.example.com", "https://tenant.example.com"},
		{"https://preview-??.example.com:8443", "https://preview-ab.example.com:8443"},
		{"https://*.co.uk", "https://tenant.co.uk"},
		{"https://*.example.com.evil.test", "https://tenant.example.com"},
		{"http://localhost:3000", "http://localhost:3000"},
	} {
		f.Add(seed[0], seed[1])
	}
	f.Fuzz(func(t *testing.T, policyValue string, candidate string) {
		policy, err := compileTrustedOriginPolicy([]string{policyValue})
		if err != nil {
			return
		}
		_ = policy.matches(candidate)
	})
}
