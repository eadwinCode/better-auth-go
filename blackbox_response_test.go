package betterauth_test

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
)

type blackboxResponse struct {
	status int
	body   []byte
}

func goResponse(recorder *httptest.ResponseRecorder) blackboxResponse {
	return blackboxResponse{
		status: recorder.Code,
		body:   append([]byte(nil), recorder.Body.Bytes()...),
	}
}

func decodeObject(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("decode response %q: %v", body, err)
	}
	return result
}

func responseUser(t *testing.T, response blackboxResponse) map[string]any {
	t.Helper()
	object := decodeObject(t, response.body)
	user, ok := object["user"].(map[string]any)
	if !ok {
		t.Fatalf("response has no user object: %s", response.body)
	}
	return user
}
