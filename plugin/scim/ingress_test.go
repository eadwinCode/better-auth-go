package scim

import (
	"net/http"
	"net/http/httptest"
	"testing"

	betterauth "github.com/eadwinCode/better-auth-go"
)

func TestNormalizeSCIMUserStringBooleans(t *testing.T) {
	t.Parallel()
	body := map[string]any{"active": "TrUe"}
	for index, attribute := range scimPrimaryAttributes {
		value := "FALSE"
		if index%2 == 0 {
			value = "tRuE"
		}
		body[attribute] = []any{map[string]any{"value": "example", "primary": value}}
	}
	hook := &betterauth.HookContext{
		Path: "/scim/v2/Users", Body: body,
		Request: httptest.NewRequest(http.MethodPost, "/scim/v2/Users", nil),
	}
	if response, err := (&runtime{}).normalizeSCIMIngress(hook); response != nil || err != nil {
		t.Fatalf("normalizeSCIMIngress() = %#v, %v", response, err)
	}
	if active, ok := body["active"].(bool); !ok || !active {
		t.Fatalf("active = %#v", body["active"])
	}
	for index, attribute := range scimPrimaryAttributes {
		item := body[attribute].([]any)[0].(map[string]any)
		primary, ok := item["primary"].(bool)
		if !ok || primary != (index%2 == 0) {
			t.Fatalf("%s primary = %#v", attribute, item["primary"])
		}
	}
}

func TestNormalizeSCIMPatchStringBooleans(t *testing.T) {
	t.Parallel()
	body := map[string]any{"Operations": []any{
		map[string]any{"op": "replace", "path": "active", "value": "FALSE"},
		map[string]any{
			"op": "replace", "path": "emails[type eq \"work\"].primary", "value": "TRUE",
		},
		map[string]any{
			"op": "replace", "path": SchemaUser + ":roles.primary", "value": "false",
		},
		map[string]any{"op": "replace", "value": map[string]any{
			"active": "true", "addresses": []any{map[string]any{"primary": "FaLsE"}},
		}},
	}}
	hook := &betterauth.HookContext{
		Path: "/scim/v2/Users/user-1", Body: body,
		Request: httptest.NewRequest(http.MethodPatch, "/scim/v2/Users/user-1", nil),
	}
	_, _ = (&runtime{}).normalizeSCIMIngress(hook)
	operations := body["Operations"].([]any)
	if operations[0].(map[string]any)["value"] != false ||
		operations[1].(map[string]any)["value"] != true ||
		operations[2].(map[string]any)["value"] != false {
		t.Fatalf("patch values were not normalized: %#v", operations)
	}
	pathless := operations[3].(map[string]any)["value"].(map[string]any)
	address := pathless["addresses"].([]any)[0].(map[string]any)
	if pathless["active"] != true || address["primary"] != false {
		t.Fatalf("pathless patch was not normalized: %#v", pathless)
	}
}

func TestSCIMStringBooleanNormalizationIsExact(t *testing.T) {
	t.Parallel()
	for _, value := range []any{" true", "false ", "1", 1, nil} {
		if got := scimBoolean(value); got != value {
			t.Fatalf("scimBoolean(%#v) = %#v", value, got)
		}
	}
}

func TestSCIMAccountProviderNamespaceUsesConnectionID(t *testing.T) {
	t.Parallel()
	first := ProviderConnection{ID: "connection-a", ProviderID: "shared"}
	second := ProviderConnection{ID: "connection-b", ProviderID: "shared"}
	if scimAccountProviderID(first) != "scim:connection-a" ||
		scimAccountProviderID(first) == scimAccountProviderID(second) ||
		scimAccountProviderID(first) == first.ProviderID {
		t.Fatal("SCIM account provider namespace is not connection-scoped")
	}
}
