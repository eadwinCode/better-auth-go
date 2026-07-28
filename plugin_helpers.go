package betterauth

import (
	"errors"
	"net/http"
	"strings"
)

// SessionMiddleware rejects requests without an active session. It can be used
// in PluginEndpoint.Use or as a plugin middleware handler.
func SessionMiddleware(context *HookContext) (*PluginResponse, error) {
	if context.Session == nil || context.User == nil {
		return nil, publicError(
			CodeUnauthorized, "Authentication required.", http.StatusUnauthorized, nil,
		)
	}
	return nil, nil
}

// CSRFMiddleware enforces the configured double-submit CSRF token. Use it on
// state-changing plugin endpoints that authenticate with a session cookie.
// Trusted-origin enforcement still runs independently before plugin code.
func CSRFMiddleware(context *HookContext) (*PluginResponse, error) {
	if context.ValidateCSRF == nil {
		return nil, publicError(
			CodeInternal, "The request could not be completed.", http.StatusInternalServerError, nil,
		)
	}
	return nil, context.ValidateCSRF()
}

// ResourceIDSource identifies where ownership middleware reads a resource ID.
type ResourceIDSource string

// Supported resource ID locations.
const (
	ResourceIDParams ResourceIDSource = "params"
	ResourceIDQuery  ResourceIDSource = "query"
	ResourceIDBody   ResourceIDSource = "body"
)

// ResourceOwnershipConfig configures RequireResourceOwnership.
type ResourceOwnershipConfig struct {
	Model      string
	IDField    string
	IDParam    string
	IDSource   ResourceIDSource
	OwnerField string
}

// RequireResourceOwnership returns middleware that requires a session and
// verifies a logical adapter record belongs to that user without disclosing
// whether a record with another owner exists.
func RequireResourceOwnership(config ResourceOwnershipConfig) (RequestHook, error) {
	config.Model = strings.TrimSpace(config.Model)
	if config.Model == "" {
		return nil, errors.New("betterauth: resource model is required")
	}
	if config.IDField == "" {
		config.IDField = "id"
	}
	if config.IDParam == "" {
		config.IDParam = "id"
	}
	if config.IDSource == "" {
		config.IDSource = ResourceIDParams
	}
	if config.OwnerField == "" {
		config.OwnerField = "userId"
	}
	switch config.IDSource {
	case ResourceIDParams, ResourceIDQuery, ResourceIDBody:
	default:
		return nil, errors.New("betterauth: invalid resource id source")
	}
	return func(context *HookContext) (*PluginResponse, error) {
		if _, err := SessionMiddleware(context); err != nil {
			return nil, err
		}
		resourceID := resourceIDFromContext(context, config)
		if resourceID == "" || len(resourceID) > 512 {
			return nil, publicError(CodeBadRequest, "Invalid resource identifier.", http.StatusBadRequest, nil)
		}
		record, err := context.Database.FindOne(context.Context, FindOneQuery{
			Model: config.Model,
			Where: []Where{
				Eq(config.IDField, resourceID),
				Eq(config.OwnerField, context.User.ID),
			},
		})
		if err != nil || record == nil {
			return nil, publicError(CodeNotFound, "Resource not found.", http.StatusNotFound, err)
		}
		return nil, nil
	}, nil
}

func resourceIDFromContext(context *HookContext, config ResourceOwnershipConfig) string {
	switch config.IDSource {
	case ResourceIDParams:
		return strings.TrimSpace(context.Params[config.IDParam])
	case ResourceIDQuery:
		return strings.TrimSpace(context.Query.Get(config.IDParam))
	case ResourceIDBody:
		body, ok := context.Body.(map[string]any)
		if !ok {
			return ""
		}
		value, _ := body[config.IDParam].(string)
		return strings.TrimSpace(value)
	default:
		return ""
	}
}
