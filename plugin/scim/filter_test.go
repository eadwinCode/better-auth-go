package scim

import "testing"

func TestParseFilterAcceptsBoundedEqualitySubset(t *testing.T) {
	t.Parallel()
	filters, err := parseFilter(
		`userName eq "ada@example.com" and externalId eq "employee-1"`,
		2048, 10,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(filters) != 2 || filters[0].Field != "email" ||
		filters[1].Field != "accountId" {
		t.Fatalf("unexpected filters: %#v", filters)
	}
}

func TestParseFilterRejectsUnsupportedGrammarAndPaths(t *testing.T) {
	t.Parallel()
	for _, value := range []string{
		`userName co "ada"`,
		`password eq "secret"`,
		`userName eq "ada" or id eq "user"`,
		`userName eq "unterminated`,
		`userName eq ""`,
	} {
		if _, err := parseFilter(value, 2048, 10); err == nil {
			t.Fatalf("accepted invalid filter %q", value)
		}
	}
}

func FuzzParseFilter(f *testing.F) {
	f.Add(`userName eq "ada@example.com"`)
	f.Add(`externalId eq "employee-1" and id eq "user-1"`)
	f.Add(`") or password pr`)
	f.Fuzz(func(t *testing.T, value string) {
		filters, err := parseFilter(value, 512, 4)
		if err == nil {
			if len(filters) > 4 {
				t.Fatalf("filter clause cap exceeded: %d", len(filters))
			}
			for _, filter := range filters {
				if filter.Field != "id" && filter.Field != "email" &&
					filter.Field != "accountId" {
					t.Fatalf("unsafe adapter field: %#v", filter)
				}
			}
		}
	})
}
