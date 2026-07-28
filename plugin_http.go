package betterauth

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"golang.org/x/net/http/httpguts"
)

type responseCapture struct {
	header   http.Header
	body     bytes.Buffer
	status   int
	maxBytes int64
	overflow bool
}

func newResponseCapture(maxBytes int64) *responseCapture {
	return &responseCapture{header: make(http.Header), maxBytes: maxBytes}
}

func (capture *responseCapture) Header() http.Header { return capture.header }

func (capture *responseCapture) WriteHeader(status int) {
	if capture.status == 0 {
		capture.status = status
	}
}

func (capture *responseCapture) Write(value []byte) (int, error) {
	if capture.status == 0 {
		capture.status = http.StatusOK
	}
	if int64(capture.body.Len()+len(value)) > capture.maxBytes {
		capture.overflow = true
		return 0, errors.New("betterauth: response exceeds configured limit")
	}
	return capture.body.Write(value)
}

func (capture *responseCapture) reset() {
	capture.header = make(http.Header)
	capture.body.Reset()
	capture.status = 0
	capture.overflow = false
}

func (capture *responseCapture) response() *PluginResponse {
	status := capture.status
	if status == 0 {
		status = http.StatusOK
	}
	return &PluginResponse{
		Status: status, Headers: capture.header.Clone(), Body: slices.Clone(capture.body.Bytes()),
	}
}

func (s *Server) serveHTTP(w http.ResponseWriter, r *http.Request) {
	capture := newResponseCapture(s.cfg.MaxResponseBytes)
	setSecurityHeaders(capture.Header(), r)
	requestID := sanitizeRequestID(r.Header.Get("X-Request-ID"))

	hookContext, response, reachedEndpoint, err := s.executePluginPipeline(capture, r)
	if err != nil {
		capture.reset()
		setSecurityHeaders(capture.Header(), r)
		writeError(capture, requestID, err)
		response = capture.response()
		if hookContext != nil {
			hookContext.Failure = err
		}
	}
	if capture.overflow {
		capture.reset()
		setSecurityHeaders(capture.Header(), r)
		writeError(capture, requestID, publicError(
			CodeInternal, "The response could not be completed.", http.StatusInternalServerError, nil,
		))
		response = capture.response()
	}
	if response == nil {
		response = capture.response()
	}
	mergePluginHeaders(response, capture.Header())

	if hookContext != nil && reachedEndpoint {
		hookContext.Response = response
		if err := s.runResponseHooks(s.plugins.after, hookContext, response); err != nil {
			response = s.errorPluginResponse(requestID, err)
			hookContext.Response = response
			hookContext.Failure = err
		}
	}
	if hookContext != nil {
		hookContext.Response = response
		if err := s.runResponseHooks(s.plugins.onResponse, hookContext, response); err != nil {
			response = s.errorPluginResponse(requestID, err)
			hookContext.Response = response
			hookContext.Failure = err
		}
	}
	s.commitPluginResponse(w, response)
}

func setSecurityHeaders(header http.Header, r *http.Request) {
	header.Set("Content-Type", "application/json; charset=utf-8")
	header.Set("Cache-Control", "no-store")
	header.Set("Pragma", "no-cache")
	header.Set("X-Content-Type-Options", "nosniff")
	if requestID := sanitizeRequestID(r.Header.Get("X-Request-ID")); requestID != "" {
		header.Set("X-Request-ID", requestID)
	}
}

func (s *Server) executePluginPipeline(
	capture *responseCapture,
	r *http.Request,
) (*HookContext, *PluginResponse, bool, error) {
	relative, ok := strings.CutPrefix(r.URL.Path, s.cfg.BasePath)
	if !ok || relative == "" {
		return nil, nil, false, publicError(CodeNotFound, "Endpoint not found.", http.StatusNotFound, nil)
	}
	pluginEndpoint, params, core, allowed, found, skipOrigin := s.resolvePluginRoute(relative, r.Method)
	if unsafeRequestMethod(r.Method) && !skipOrigin {
		if err := s.checkOrigin(r); err != nil {
			return nil, nil, false, err
		}
	}
	hookContext, bodyWasJSON, err := s.newHookContext(r, relative, params)
	if err != nil {
		return hookContext, nil, false, err
	}
	if !found {
		return hookContext, nil, false, publicError(CodeNotFound, "Endpoint not found.", http.StatusNotFound, nil)
	}
	if !slices.Contains(allowed, r.Method) {
		capture.Header().Set("Allow", strings.Join(allowed, ", "))
		return hookContext, nil, false, publicError(
			CodeMethodNotAllowed, "Method not allowed.", http.StatusMethodNotAllowed, nil,
		)
	}
	if response, err := s.runRequestHooks(s.plugins.onRequest, hookContext); response != nil || err != nil {
		return hookContext, response, false, err
	}
	if err := s.runPluginRateLimits(hookContext); err != nil {
		return hookContext, nil, false, err
	}
	if !core {
		if err := validatePluginEndpointInput(pluginEndpoint.endpoint, hookContext); err != nil {
			return hookContext, nil, false, err
		}
	}
	if response, err := s.runRequestHooks(s.plugins.middlewares, hookContext); response != nil || err != nil {
		return hookContext, response, false, err
	}
	if !core {
		hookContext.PluginID = pluginEndpoint.pluginID
		for _, middleware := range pluginEndpoint.endpoint.Use {
			response, err := callRequestHook(compiledRequestHook{
				pluginID: pluginEndpoint.pluginID, handler: middleware,
			}, hookContext)
			if response != nil || err != nil {
				return hookContext, response, false, err
			}
		}
	}
	if response, err := s.runRequestHooks(s.plugins.before, hookContext); response != nil || err != nil {
		return hookContext, response, false, err
	}
	if err := syncHookRequest(hookContext, bodyWasJSON); err != nil {
		return hookContext, nil, false, err
	}
	if core {
		s.serveCoreHTTP(capture, r)
		return hookContext, capture.response(), true, nil
	}
	hookContext.PluginID = pluginEndpoint.pluginID
	response, err := callPluginEndpoint(pluginEndpoint, hookContext)
	return hookContext, response, true, err
}

func (s *Server) resolvePluginRoute(
	path string,
	method string,
) (compiledEndpoint, map[string]string, bool, []string, bool, bool) {
	if methods, exists := s.plugins.endpoints[path]; exists {
		allowed := make([]string, 0, len(methods))
		for candidate := range methods {
			allowed = append(allowed, candidate)
		}
		slices.Sort(allowed)
		selected := methods[method]
		return selected, nil, false, allowed, true, selected.endpoint.SkipOriginCheck
	}
	var allowed []string
	var selected compiledEndpoint
	var selectedParams map[string]string
	for _, endpoint := range s.plugins.dynamic {
		params, matches := matchPluginPath(endpoint.template, path)
		if !matches {
			continue
		}
		allowed = append(allowed, endpoint.endpoint.Method)
		if endpoint.endpoint.Method == method {
			selected, selectedParams = endpoint, params
		}
	}
	if len(allowed) > 0 {
		slices.Sort(allowed)
		return selected, selectedParams, false, slices.Compact(allowed), true,
			selected.endpoint.SkipOriginCheck
	}
	if isCoreRoute(path) {
		expected := http.MethodPost
		if path == "/get-session" || path == "/list-sessions" ||
			path == "/list-accounts" || path == "/verify-email" {
			expected = http.MethodGet
		}
		return compiledEndpoint{}, nil, true, []string{expected}, true, false
	}
	if providerID, callback := strings.CutPrefix(path, "/callback/"); callback && validProviderID(providerID) {
		return compiledEndpoint{}, nil, true, []string{http.MethodGet, http.MethodPost}, true, true
	}
	return compiledEndpoint{}, nil, false, nil, false, false
}

func unsafeRequestMethod(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

func (s *Server) newHookContext(
	r *http.Request,
	path string,
	params map[string]string,
) (*HookContext, bool, error) {
	context := &HookContext{
		Context: r.Context(), Request: r, Path: path, Params: maps.Clone(params),
		Headers: r.Header.Clone(), Query: cloneValues(r.URL.Query()),
		Database: s.cfg.Database, Clock: s.cfg.Clock, GenerateID: s.newID,
		GenerateToken: s.cfg.Tokens.Token,
		BaseURL:       s.cfg.PublicURL + s.cfg.BasePath, Schema: cloneSchema(s.cfg.Schema),
		Cookies: s.cfg.Cookie, Passwords: s.cfg.Passwords,
		TrustedOrigins:  slices.Clone(s.cfg.TrustedOrigins),
		SessionFreshAge: s.cfg.SessionFreshAge,
		BackgroundTasks: s.cfg.BackgroundTasks,
		IsTrustedOrigin: func(raw string) bool {
			origin, err := normalizeOrigin(raw)
			if err != nil {
				return false
			}
			_, ok := s.trustedOrigins[origin]
			return ok
		},
		ValidateCSRF: func() error {
			return s.requireCSRF(r)
		},
		IssueSession: func(userID string) (*IssuedSession, error) {
			return s.issuePluginSession(r, userID)
		},
	}
	if session, user, _, err := s.sessionFromRequest(r.Context(), r); err == nil {
		context.Session, context.User = &session, &user
	}
	contentType := strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0]))
	if r.Body == nil || contentType != "application/json" {
		return context, false, nil
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, s.cfg.MaxRequestBytes+1))
	if err != nil {
		return context, false, publicError(CodeBadRequest, "Invalid request body.", http.StatusBadRequest, err)
	}
	if int64(len(raw)) > s.cfg.MaxRequestBytes {
		return context, false, publicError(CodeBadRequest, "Request body is too large.", http.StatusRequestEntityTooLarge, nil)
	}
	context.RawBody = slices.Clone(raw)
	r.Body = io.NopCloser(bytes.NewReader(raw))
	if len(bytes.TrimSpace(raw)) == 0 {
		return context, false, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&context.Body); err != nil {
		// Core endpoints retain ownership of their exact JSON error contract.
		context.bodyDecodeError = err
		return context, false, nil
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		context.bodyDecodeError = errors.New("betterauth: request body must contain one JSON value")
		return context, false, nil
	}
	return context, true, nil
}

func syncHookRequest(context *HookContext, bodyWasJSON bool) error {
	context.Request.Header = context.Headers.Clone()
	query := cloneValues(context.Query)
	context.Request.URL.RawQuery = query.Encode()
	if bodyWasJSON || context.Body != nil {
		raw, err := json.Marshal(context.Body)
		if err != nil {
			return publicError(CodeBadRequest, "Invalid request body.", http.StatusBadRequest, err)
		}
		context.RawBody = raw
	}
	if context.RawBody != nil {
		context.Request.Body = io.NopCloser(bytes.NewReader(context.RawBody))
		context.Request.ContentLength = int64(len(context.RawBody))
	}
	return nil
}

func (s *Server) runRequestHooks(
	hooks []compiledRequestHook,
	context *HookContext,
) (*PluginResponse, error) {
	for _, hook := range hooks {
		matched, err := callHookMatcher(hook.pluginID, hook.matcher, context)
		if err != nil {
			return nil, err
		}
		if !matched {
			continue
		}
		context.PluginID = hook.pluginID
		response, err := callRequestHook(hook, context)
		if err != nil || response != nil {
			return response, err
		}
	}
	return nil, nil
}

func (s *Server) runResponseHooks(
	hooks []compiledResponseHook,
	context *HookContext,
	response *PluginResponse,
) error {
	for _, hook := range hooks {
		matched, err := callHookMatcher(hook.pluginID, hook.matcher, context)
		if err != nil {
			return err
		}
		if !matched {
			continue
		}
		context.PluginID = hook.pluginID
		context.Response = response
		if err := callResponseHook(hook, context, response); err != nil {
			return err
		}
		if err := s.validatePluginResponse(response); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) runPluginRateLimits(context *HookContext) error {
	for _, compiled := range s.plugins.rateLimits {
		matched, err := callHookMatcher(compiled.pluginID, compiled.rule.Matcher, context)
		if err != nil {
			return err
		}
		if !matched {
			continue
		}
		accountKey := ""
		if compiled.rule.AccountKey != nil {
			accountKey, err = callAccountKey(compiled, context)
			if err != nil {
				return err
			}
		}
		decision, err := s.cfg.RateLimiter.Allow(context.Context, RateLimitRequest{
			Action: compiled.rule.Action, IP: s.remoteIP(context.Request), AccountKey: accountKey,
			Window: compiled.rule.Window, Max: compiled.rule.Max,
		})
		if err != nil {
			return publicError(CodeInternal, "The request could not be completed.", http.StatusInternalServerError, err)
		}
		if !decision.Allowed {
			result := publicError(CodeRateLimited, "Too many requests.", http.StatusTooManyRequests, nil)
			result.RetryAfter = decision.RetryAfter
			return result
		}
	}
	return nil
}

func callHookMatcher(pluginID string, matcher HookMatcher, context *HookContext) (matched bool, err error) {
	if matcher == nil {
		return true, nil
	}
	defer func() {
		if recover() != nil {
			err = fmt.Errorf("betterauth: plugin %q matcher panicked", pluginID)
		}
	}()
	return matcher(context), nil
}

func callRequestHook(
	hook compiledRequestHook,
	context *HookContext,
) (response *PluginResponse, err error) {
	defer func() {
		if recover() != nil {
			response = nil
			err = fmt.Errorf("betterauth: plugin %q request hook panicked", hook.pluginID)
		}
	}()
	response, err = hook.handler(context)
	if err != nil {
		return nil, fmt.Errorf("betterauth: plugin %q request hook: %w", hook.pluginID, err)
	}
	return response, nil
}

func callResponseHook(
	hook compiledResponseHook,
	context *HookContext,
	response *PluginResponse,
) (err error) {
	defer func() {
		if recover() != nil {
			err = fmt.Errorf("betterauth: plugin %q response hook panicked", hook.pluginID)
		}
	}()
	if err := hook.handler(context, response); err != nil {
		return fmt.Errorf("betterauth: plugin %q response hook: %w", hook.pluginID, err)
	}
	return nil
}

func callPluginEndpoint(
	endpoint compiledEndpoint,
	context *HookContext,
) (response *PluginResponse, err error) {
	defer func() {
		if recover() != nil {
			response = nil
			err = fmt.Errorf("betterauth: plugin %q endpoint panicked", endpoint.pluginID)
		}
	}()
	response, err = endpoint.endpoint.Handler(context)
	if err != nil {
		return nil, fmt.Errorf("betterauth: plugin %q endpoint: %w", endpoint.pluginID, err)
	}
	if response == nil {
		return nil, fmt.Errorf("betterauth: plugin %q endpoint returned a nil response", endpoint.pluginID)
	}
	return response, nil
}

func callAccountKey(
	rule compiledRateLimit,
	context *HookContext,
) (key string, err error) {
	defer func() {
		if recover() != nil {
			err = fmt.Errorf("betterauth: plugin %q rate-limit key panicked", rule.pluginID)
		}
	}()
	return rule.rule.AccountKey(context), nil
}

func (s *Server) validatePluginResponse(response *PluginResponse) error {
	if response == nil || response.Status < 200 || response.Status > 599 {
		return errors.New("betterauth: plugin returned an invalid response")
	}
	if int64(len(response.Body)) > s.cfg.MaxResponseBytes {
		return errors.New("betterauth: plugin response exceeds configured limit")
	}
	for name, values := range response.Headers {
		if !httpguts.ValidHeaderFieldName(name) {
			return errors.New("betterauth: plugin response contains an invalid header")
		}
		for _, value := range values {
			if !httpguts.ValidHeaderFieldValue(value) {
				return errors.New("betterauth: plugin response contains an invalid header")
			}
		}
	}
	return nil
}

func (s *Server) errorPluginResponse(requestID string, err error) *PluginResponse {
	capture := newResponseCapture(s.cfg.MaxResponseBytes)
	capture.Header().Set("Content-Type", "application/json; charset=utf-8")
	writeError(capture, requestID, err)
	return capture.response()
}

func (s *Server) commitPluginResponse(w http.ResponseWriter, response *PluginResponse) {
	if err := s.validatePluginResponse(response); err != nil {
		response = s.errorPluginResponse("", err)
	}
	for name, values := range response.Headers {
		w.Header()[name] = slices.Clone(values)
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(response.Status)
	_, _ = w.Write(response.Body)
}

func cloneValues(values url.Values) url.Values {
	if values == nil {
		return nil
	}
	result := make(url.Values, len(values))
	for key, items := range values {
		result[key] = slices.Clone(items)
	}
	return result
}

func mergePluginHeaders(response *PluginResponse, defaults http.Header) {
	if response.Headers == nil {
		response.Headers = make(http.Header)
	}
	for name, values := range defaults {
		if _, exists := response.Headers[name]; !exists {
			response.Headers[name] = slices.Clone(values)
		}
	}
}
