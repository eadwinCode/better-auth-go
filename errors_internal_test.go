package betterauth

import "testing"

func TestHTTPErrorCodesUseBetterAuthWireVocabulary(t *testing.T) {
	expected := map[ErrorCode]string{
		CodeBadRequest:         "BAD_REQUEST",
		CodeValidation:         "VALIDATION_ERROR",
		CodeInvalidEmail:       "INVALID_EMAIL",
		CodePasswordTooShort:   "PASSWORD_TOO_SHORT",
		CodePasswordTooLong:    "PASSWORD_TOO_LONG",
		CodeInvalidCredentials: "INVALID_EMAIL_OR_PASSWORD",
		CodeEmailNotVerified:   "EMAIL_NOT_VERIFIED",
		CodeSignUpDisabled:     "EMAIL_PASSWORD_SIGN_UP_DISABLED",
		CodeUserAlreadyExists:  "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL",
		CodeUnauthorized:       "UNAUTHORIZED",
		CodeForbidden:          "FORBIDDEN",
		CodeNotFound:           "NOT_FOUND",
		CodeConflict:           "CONFLICT",
		CodeRateLimited:        "TOO_MANY_REQUESTS",
		CodeInvalidOrigin:      "INVALID_ORIGIN",
		CodeInvalidCSRF:        "FORBIDDEN",
		CodeInvalidToken:       "INVALID_TOKEN",
		CodeProviderFailure:    "PROVIDER_ERROR",
		CodeMethodNotAllowed:   "METHOD_NOT_ALLOWED",
		CodeInternal:           "INTERNAL_SERVER_ERROR",
	}
	for code, want := range expected {
		if got := httpErrorCode(code); got != want {
			t.Errorf("httpErrorCode(%q) = %q, want %q", code, got, want)
		}
	}
	if got := httpErrorCode(ErrorCode("unknown")); got != "INTERNAL_SERVER_ERROR" {
		t.Fatalf("unknown code did not fail closed: %q", got)
	}
}
