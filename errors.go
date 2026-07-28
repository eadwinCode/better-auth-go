package betterauth

import (
	"errors"
	"net/http"
	"strconv"
	"time"
)

type ErrorCode string

const (
	CodeBadRequest         ErrorCode = "bad_request"
	CodeInvalidCredentials ErrorCode = "invalid_credentials"
	CodeUnauthorized       ErrorCode = "unauthorized"
	CodeForbidden          ErrorCode = "forbidden"
	CodeNotFound           ErrorCode = "not_found"
	CodeConflict           ErrorCode = "conflict"
	CodeRateLimited        ErrorCode = "rate_limited"
	CodeInvalidOrigin      ErrorCode = "invalid_origin"
	CodeInvalidCSRF        ErrorCode = "invalid_csrf"
	CodeInvalidToken       ErrorCode = "invalid_or_expired_token"
	CodeProviderFailure    ErrorCode = "provider_failure"
	CodeMethodNotAllowed   ErrorCode = "method_not_allowed"
	CodeInternal           ErrorCode = "internal_error"
)

// Error is a structured public-safe authentication error.
type Error struct {
	Code       ErrorCode     `json:"code"`
	Message    string        `json:"message"`
	Status     int           `json:"-"`
	RetryAfter time.Duration `json:"-"`
	RequestID  string        `json:"request_id,omitempty"`
	cause      error
}

func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}
	return string(e.Code) + ": " + e.Message
}

func (e *Error) Unwrap() error { return e.cause }

func publicError(code ErrorCode, message string, status int, cause error) *Error {
	return &Error{Code: code, Message: message, Status: status, cause: cause}
}

func writeError(w http.ResponseWriter, requestID string, err error) {
	var authErr *Error
	if !errors.As(err, &authErr) {
		authErr = publicError(CodeInternal, "The request could not be completed.", http.StatusInternalServerError, err)
	}
	authErr.RequestID = requestID
	if authErr.RetryAfter > 0 {
		seconds := int(authErr.RetryAfter.Round(time.Second) / time.Second)
		if seconds < 1 {
			seconds = 1
		}
		w.Header().Set("Retry-After", strconv.Itoa(seconds))
	}
	writeJSON(w, authErr.Status, map[string]any{"error": authErr})
}
