package onetimetoken

import "testing"

// FuzzOpenSession checks that stored metadata never panics the opener and
// that a sealed session opens only with its own token and record.
func FuzzOpenSession(f *testing.F) {
	sealed, err := sealSession("token", "stored", "raw-session")
	if err != nil {
		f.Fatal(err)
	}
	f.Add("token", "stored", sealed)
	f.Add("token", "stored", "v1.")
	f.Add("", "", "")
	f.Fuzz(func(t *testing.T, token, stored, value string) {
		raw, err := openSession(token, stored, value)
		if err == nil && raw == "" {
			t.Fatal("opened an empty session")
		}
		if value == sealed && err == nil && (token != "token" || stored != "stored") {
			t.Fatal("sealed session opened with another token or record")
		}
	})
}
