package sso

import (
	"net/http"

	betterauth "github.com/eadwinCode/better-auth-go"
)

func badRequest(err error) error {
	return betterauth.NewError(
		betterauth.CodeBadRequest, "Invalid SSO request.", http.StatusBadRequest, err,
	)
}

func forbidden(err error) error {
	return betterauth.NewError(
		betterauth.CodeForbidden, "SSO provider access denied.", http.StatusForbidden, err,
	)
}

func notFound(err error) error {
	return betterauth.NewError(
		betterauth.CodeNotFound, "SSO provider not found.", http.StatusNotFound, err,
	)
}

func conflict(err error) error {
	return betterauth.NewError(
		betterauth.CodeConflict, "SSO provider already exists or conflicts.", http.StatusConflict, err,
	)
}

func providerFailure(err error) error {
	return betterauth.NewError(
		betterauth.CodeProviderFailure, "SSO sign in could not be completed.",
		http.StatusBadGateway, err,
	)
}

func invalidState(err error) error {
	return betterauth.NewError(
		betterauth.CodeInvalidToken, "The SSO response is invalid or expired.",
		http.StatusBadRequest, err,
	)
}

func internal(err error) error {
	return betterauth.NewError(
		betterauth.CodeInternal, "The SSO request could not be completed.",
		http.StatusInternalServerError, err,
	)
}
