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
	RequestID  string        `json:"requestId,omitempty"`
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

// NewError creates a structured public-safe error for application hooks and
// feature plugins. Message is returned to the caller and therefore must not
// contain secrets, database details, or cryptographic verification errors.
func NewError(code ErrorCode, message string, status int, cause error) *Error {
	return publicError(code, message, status, cause)
}

func writeError(w http.ResponseWriter, requestID string, err error) {
	var authErr *Error
	if !errors.As(err, &authErr) {
		authErr = publicError(CodeInternal, "The request could not be completed.", http.StatusInternalServerError, err)
	} else {
		copyError := *authErr
		authErr = &copyError
	}
	if authErr.Status < 400 || authErr.Status > 599 || authErr.Code == "" || authErr.Message == "" {
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
	response := map[string]any{
		"code":    httpErrorCode(authErr.Code),
		"message": authErr.Message,
	}
	if authErr.RequestID != "" {
		response["requestId"] = authErr.RequestID
	}
	writeJSON(w, authErr.Status, response)
}

func httpErrorCode(code ErrorCode) string {
	switch code {
	case CodeBadRequest:
		return "BAD_REQUEST"
	case CodeInvalidCredentials:
		return "INVALID_EMAIL_OR_PASSWORD"
	case CodeUnauthorized:
		return "UNAUTHORIZED"
	case CodeForbidden, CodeInvalidCSRF:
		return "FORBIDDEN"
	case CodeNotFound:
		return "NOT_FOUND"
	case CodeConflict:
		return "CONFLICT"
	case CodeRateLimited:
		return "TOO_MANY_REQUESTS"
	case CodeInvalidOrigin:
		return "INVALID_ORIGIN"
	case CodeInvalidToken:
		return "INVALID_TOKEN"
	case CodeProviderFailure:
		return "PROVIDER_ERROR"
	case CodeMethodNotAllowed:
		return "METHOD_NOT_ALLOWED"
	default:
		return "INTERNAL_SERVER_ERROR"
	}
}
