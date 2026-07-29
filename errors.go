package betterauth

import (
	"errors"
	"net/http"
	"strconv"
	"time"
)

type ErrorCode string

const (
	CodeBadRequest              ErrorCode = "bad_request"
	CodeValidation              ErrorCode = "validation_error"
	CodeInvalidEmail            ErrorCode = "invalid_email"
	CodePasswordTooShort        ErrorCode = "password_too_short"
	CodePasswordTooLong         ErrorCode = "password_too_long"
	CodeInvalidCredentials      ErrorCode = "invalid_credentials"
	CodeEmailNotVerified        ErrorCode = "email_not_verified"
	CodeEmailMismatch           ErrorCode = "email_mismatch"
	CodeEmailAlreadyVerified    ErrorCode = "email_already_verified"
	CodeInvalidPassword         ErrorCode = "invalid_password"
	CodeCredentialNotFound      ErrorCode = "credential_account_not_found"
	CodeAccountNotFound         ErrorCode = "account_not_found"
	CodeUnlinkLastAccount       ErrorCode = "failed_to_unlink_last_account"
	CodeLinkingNotAllowed       ErrorCode = "linking_not_allowed"
	CodeLinkingDifferentEmails  ErrorCode = "linking_different_emails_not_allowed"
	CodeAccountLinkedElsewhere  ErrorCode = "account_already_linked_to_different_user"
	CodeAccountNotLinked        ErrorCode = "account_not_linked"
	CodeOAuthSignUpDisabled     ErrorCode = "oauth_sign_up_disabled"
	CodeProviderNotSupported    ErrorCode = "provider_not_supported"
	CodeTokenRefreshUnsupported ErrorCode = "token_refresh_not_supported"
	CodeRefreshTokenNotFound    ErrorCode = "refresh_token_not_found"
	CodeFailedRefreshToken      ErrorCode = "failed_to_refresh_access_token"
	CodeSignUpDisabled          ErrorCode = "email_password_sign_up_disabled"
	CodeUserAlreadyExists       ErrorCode = "user_already_exists_use_another_email"
	CodeUnauthorized            ErrorCode = "unauthorized"
	CodeForbidden               ErrorCode = "forbidden"
	CodeCannotImpersonateAdmins ErrorCode = "cannot_impersonate_admins"
	CodeCannotImpersonateUsers  ErrorCode = "cannot_impersonate_users"
	CodeSessionNotFresh         ErrorCode = "session_not_fresh"
	CodeNotFound                ErrorCode = "not_found"
	CodeConflict                ErrorCode = "conflict"
	CodeRateLimited             ErrorCode = "rate_limited"
	CodeInvalidOrigin           ErrorCode = "invalid_origin"
	CodeInvalidCSRF             ErrorCode = "invalid_csrf"
	CodeInvalidToken            ErrorCode = "invalid_or_expired_token"
	CodeProviderFailure         ErrorCode = "provider_failure"
	CodeMethodNotAllowed        ErrorCode = "method_not_allowed"
	CodeInternal                ErrorCode = "internal_error"
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
	case CodeValidation:
		return "VALIDATION_ERROR"
	case CodeInvalidEmail:
		return "INVALID_EMAIL"
	case CodePasswordTooShort:
		return "PASSWORD_TOO_SHORT"
	case CodePasswordTooLong:
		return "PASSWORD_TOO_LONG"
	case CodeInvalidCredentials:
		return "INVALID_EMAIL_OR_PASSWORD"
	case CodeEmailNotVerified:
		return "EMAIL_NOT_VERIFIED"
	case CodeEmailMismatch:
		return "EMAIL_MISMATCH"
	case CodeEmailAlreadyVerified:
		return "EMAIL_ALREADY_VERIFIED"
	case CodeInvalidPassword:
		return "INVALID_PASSWORD"
	case CodeCredentialNotFound:
		return "CREDENTIAL_ACCOUNT_NOT_FOUND"
	case CodeAccountNotFound:
		return "ACCOUNT_NOT_FOUND"
	case CodeUnlinkLastAccount:
		return "FAILED_TO_UNLINK_LAST_ACCOUNT"
	case CodeLinkingNotAllowed:
		return "LINKING_NOT_ALLOWED"
	case CodeLinkingDifferentEmails:
		return "LINKING_DIFFERENT_EMAILS_NOT_ALLOWED"
	case CodeAccountLinkedElsewhere:
		return "ACCOUNT_ALREADY_LINKED_TO_DIFFERENT_USER"
	case CodeAccountNotLinked:
		return "ACCOUNT_NOT_LINKED"
	case CodeOAuthSignUpDisabled:
		return "SIGNUP_DISABLED"
	case CodeProviderNotSupported:
		return "PROVIDER_NOT_SUPPORTED"
	case CodeTokenRefreshUnsupported:
		return "TOKEN_REFRESH_NOT_SUPPORTED"
	case CodeRefreshTokenNotFound:
		return "REFRESH_TOKEN_NOT_FOUND"
	case CodeFailedRefreshToken:
		return "FAILED_TO_REFRESH_ACCESS_TOKEN"
	case CodeSignUpDisabled:
		return "EMAIL_PASSWORD_SIGN_UP_DISABLED"
	case CodeUserAlreadyExists:
		return "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL"
	case CodeUnauthorized:
		return "UNAUTHORIZED"
	case CodeForbidden, CodeInvalidCSRF:
		return "FORBIDDEN"
	case CodeCannotImpersonateAdmins:
		return "YOU_CANNOT_IMPERSONATE_ADMINS"
	case CodeCannotImpersonateUsers:
		return "YOU_ARE_NOT_ALLOWED_TO_IMPERSONATE_USERS"
	case CodeSessionNotFresh:
		return "SESSION_NOT_FRESH"
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
