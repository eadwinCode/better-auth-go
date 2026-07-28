package sso

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	betterauth "github.com/eadwinCode/better-auth-go"
)

type signInRequest struct {
	Email              string   `json:"email,omitempty"`
	Issuer             string   `json:"issuer,omitempty"`
	ProviderID         string   `json:"providerId,omitempty"`
	Domain             string   `json:"domain,omitempty"`
	CallbackURL        string   `json:"callbackURL"`
	ErrorCallbackURL   string   `json:"errorCallbackURL,omitempty"`
	NewUserCallbackURL string   `json:"newUserCallbackURL,omitempty"`
	Scopes             []string `json:"scopes,omitempty"`
	LoginHint          string   `json:"loginHint,omitempty"`
	RequestSignUp      bool     `json:"requestSignUp,omitempty"`
	ProviderType       string   `json:"providerType,omitempty"`
}

type updateProviderRequest struct {
	ProviderID string      `json:"providerId"`
	Issuer     string      `json:"issuer,omitempty"`
	Domain     string      `json:"domain,omitempty"`
	OIDC       *OIDCConfig `json:"oidcConfig,omitempty"`
	SAML       *SAMLConfig `json:"samlConfig,omitempty"`
}

func (instance *runtime) register(
	ctx *betterauth.HookContext,
) (*betterauth.PluginResponse, error) {
	if instance.config.DisableProviderRegistration {
		return nil, forbidden(errors.New("SSO provider registration is disabled"))
	}
	var registration ProviderRegistration
	if err := decodeContextBody(ctx, &registration); err != nil {
		return nil, badRequest(err)
	}
	provider, err := instance.createProvider(ctx, registration, ctx.User.ID)
	if err != nil {
		return nil, err
	}
	response := publicProvider(provider)
	response["redirectURI"] = instance.oidcRedirectURI(ctx, provider.ProviderID)
	if instance.config.DomainVerification {
		token, tokenErr := instance.putDomainVerification(ctx, provider)
		if tokenErr != nil {
			return nil, tokenErr
		}
		response["domainVerificationToken"] = token
	}
	return betterauth.JSONResponse(http.StatusOK, response)
}

func (instance *runtime) listProviders(
	ctx *betterauth.HookContext,
) (*betterauth.PluginResponse, error) {
	records, err := ctx.Database.FindMany(ctx.Context, betterauth.FindManyQuery{
		Model: ModelSSOProvider, Limit: instance.config.ProvidersLimit * 100,
		Sort: &betterauth.Sort{Field: "createdAt", Direction: "asc"},
	})
	if err != nil {
		return nil, internal(err)
	}
	providers := make([]map[string]any, 0, len(records))
	for _, record := range records {
		provider, decodeErr := instance.decodeProvider(ctx.Context, record)
		if decodeErr != nil || instance.authorizeProvider(ctx, provider) != nil {
			continue
		}
		providers = append(providers, publicProvider(provider))
	}
	return betterauth.JSONResponse(http.StatusOK, map[string]any{"providers": providers})
}

func (instance *runtime) getProvider(
	ctx *betterauth.HookContext,
) (*betterauth.PluginResponse, error) {
	provider, err := instance.findProvider(ctx, ctx.Query.Get("providerId"))
	if err != nil {
		return nil, notFound(err)
	}
	if err = instance.authorizeProvider(ctx, provider); err != nil {
		return nil, err
	}
	return betterauth.JSONResponse(http.StatusOK, publicProvider(provider))
}

func (instance *runtime) updateProvider(
	ctx *betterauth.HookContext,
) (*betterauth.PluginResponse, error) {
	var request updateProviderRequest
	if err := decodeContextBody(ctx, &request); err != nil {
		return nil, badRequest(err)
	}
	current, err := instance.findProvider(ctx, request.ProviderID)
	if err != nil || strings.HasPrefix(current.ID, "default:") {
		return nil, notFound(err)
	}
	if err = instance.authorizeProvider(ctx, current); err != nil {
		return nil, err
	}
	registration := ProviderRegistration{
		Issuer: current.Issuer, Domain: current.Domain, ProviderID: current.ProviderID,
		OrganizationID: current.OrganizationID, OIDC: current.OIDC, SAML: current.SAML,
	}
	identityChanged := false
	if request.Issuer != "" {
		registration.Issuer = request.Issuer
		identityChanged = registration.Issuer != current.Issuer
	}
	if request.Domain != "" {
		registration.Domain = request.Domain
		identityChanged = identityChanged || registration.Domain != current.Domain
	}
	if request.OIDC != nil {
		registration.OIDC, registration.SAML = request.OIDC, nil
		identityChanged = true
	}
	if request.SAML != nil {
		registration.SAML, registration.OIDC = request.SAML, nil
		identityChanged = true
	}
	registration, err = normalizeProvider(registration)
	if err != nil {
		return nil, badRequest(err)
	}
	if err = instance.validateProvider(ctx.Context, registration); err != nil {
		return nil, providerFailure(err)
	}
	oidcSecret, samlSecret, err := instance.sealProvider(ctx.Context, registration)
	if err != nil {
		return nil, internal(err)
	}
	update := betterauth.Record{
		"issuer": registration.Issuer, "domain": registration.Domain,
		"oidcConfig": oidcSecret, "samlConfig": samlSecret,
		"updatedAt": ctx.Clock.Now().UTC(),
	}
	if identityChanged && instance.config.DomainVerification {
		update["domainVerified"] = false
	}
	record, err := ctx.Database.Update(ctx.Context, betterauth.UpdateQuery{
		Model: ModelSSOProvider,
		Where: []betterauth.Where{
			betterauth.Eq("id", current.ID), betterauth.Eq("providerId", current.ProviderID),
		},
		Update: update,
	})
	if err != nil || record == nil {
		return nil, internal(err)
	}
	updated, err := instance.decodeProvider(ctx.Context, record)
	if err != nil {
		return nil, internal(err)
	}
	return betterauth.JSONResponse(http.StatusOK, publicProvider(updated))
}

func (instance *runtime) deleteProvider(
	ctx *betterauth.HookContext,
) (*betterauth.PluginResponse, error) {
	var request struct {
		ProviderID string `json:"providerId"`
	}
	if err := decodeContextBody(ctx, &request); err != nil {
		return nil, badRequest(err)
	}
	provider, err := instance.findProvider(ctx, request.ProviderID)
	if err != nil || strings.HasPrefix(provider.ID, "default:") {
		return nil, notFound(err)
	}
	if err = instance.authorizeProvider(ctx, provider); err != nil {
		return nil, err
	}
	if err = ctx.Database.Delete(ctx.Context, betterauth.DeleteQuery{
		Model: ModelSSOProvider,
		Where: []betterauth.Where{
			betterauth.Eq("id", provider.ID), betterauth.Eq("providerId", provider.ProviderID),
		},
	}); err != nil {
		return nil, internal(err)
	}
	return betterauth.JSONResponse(http.StatusOK, map[string]any{"success": true})
}

func (instance *runtime) signIn(
	ctx *betterauth.HookContext,
) (*betterauth.PluginResponse, error) {
	var request signInRequest
	if err := decodeContextBody(ctx, &request); err != nil {
		return nil, badRequest(err)
	}
	if request.ProviderID == "" && request.Issuer == "" &&
		request.Email == "" && request.Domain == "" {
		return nil, badRequest(errors.New("email, issuer, domain, or providerId is required"))
	}
	lookupEmail := request.Email
	if lookupEmail == "" && request.Domain != "" {
		lookupEmail = "sso@" + strings.TrimSpace(request.Domain)
	}
	provider, err := instance.findProviderForSignIn(
		ctx, request.ProviderID, request.Issuer, lookupEmail,
	)
	if err != nil {
		return nil, notFound(err)
	}
	if request.ProviderType != "" && request.ProviderType != provider.Type {
		return nil, notFound(errors.New("SSO provider type mismatch"))
	}
	if instance.config.DomainVerification && !provider.DomainVerified {
		return nil, forbidden(errors.New("SSO provider domain is not verified"))
	}
	returnTo, err := safeReturnTo(ctx, request.CallbackURL)
	if err != nil {
		return nil, badRequest(err)
	}
	newUserTo, err := safeReturnTo(ctx, request.NewUserCallbackURL)
	if err != nil {
		return nil, badRequest(err)
	}
	errorTo, err := safeReturnTo(ctx, request.ErrorCallbackURL)
	if err != nil {
		return nil, badRequest(err)
	}
	if provider.SAML != nil {
		return instance.startSAML(ctx, provider, protocolState{
			ReturnTo: returnTo, NewUserTo: newUserTo, ErrorTo: errorTo,
			RequestSignUp: request.RequestSignUp,
		})
	}
	configCopy := *provider.OIDC
	configCopy.Scopes = append(slices.Clone(configCopy.Scopes), request.Scopes...)
	provider.OIDC = &configCopy
	verifier, err := ctx.GenerateToken(32)
	if err != nil {
		return nil, internal(err)
	}
	nonce, err := ctx.GenerateToken(32)
	if err != nil {
		return nil, internal(err)
	}
	redirectURI := instance.oidcRedirectURI(ctx, provider.ProviderID)
	state, err := instance.createState(ctx, stateIdentifierOIDC, protocolState{
		ProviderID: provider.ProviderID, Verifier: verifier, Nonce: nonce,
		RedirectURI: redirectURI, ReturnTo: returnTo, NewUserTo: newUserTo,
		ErrorTo: errorTo, RequestSignUp: request.RequestSignUp,
	})
	if err != nil {
		return nil, internal(err)
	}
	oauthProvider, err := instance.oidcProvider(ctx.Context, provider, ctx.Clock)
	if err != nil {
		return nil, providerFailure(err)
	}
	destination, err := oauthProvider.AuthorizationURL(
		state, pkceChallenge(verifier), nonce, redirectURI,
	)
	if err != nil {
		return nil, providerFailure(err)
	}
	if request.LoginHint != "" {
		parsed, parseErr := url.Parse(destination)
		if parseErr != nil {
			return nil, providerFailure(parseErr)
		}
		query := parsed.Query()
		query.Set("login_hint", request.LoginHint)
		parsed.RawQuery = query.Encode()
		destination = parsed.String()
	}
	return betterauth.JSONResponse(http.StatusOK, map[string]any{
		"url": destination, "redirect": true,
	})
}

func (instance *runtime) oidcCallback(
	ctx *betterauth.HookContext,
) (*betterauth.PluginResponse, error) {
	if err := ctx.Request.ParseForm(); err != nil {
		return nil, invalidState(err)
	}
	rawState := ctx.Request.FormValue("state")
	state, err := instance.consumeState(ctx, stateIdentifierOIDC, rawState)
	if err != nil {
		return nil, invalidState(err)
	}
	pathProviderID := ctx.Params["providerId"]
	if pathProviderID != "" && pathProviderID != state.ProviderID {
		return nil, invalidState(errors.New("provider state mismatch"))
	}
	if ctx.Request.FormValue("error") != "" {
		if state.ErrorTo != "" {
			errorURL, _ := url.Parse(state.ErrorTo)
			query := errorURL.Query()
			query.Set("error", "provider_error")
			errorURL.RawQuery = query.Encode()
			return &betterauth.PluginResponse{
				Status:  http.StatusFound,
				Headers: http.Header{"Location": []string{errorURL.String()}},
			}, nil
		}
		return nil, providerFailure(errors.New("identity provider rejected request"))
	}
	code := ctx.Request.FormValue("code")
	if code == "" || len(code) > 4096 {
		return nil, invalidState(errors.New("missing authorization code"))
	}
	provider, err := instance.findProvider(ctx, state.ProviderID)
	if err != nil || provider.OIDC == nil {
		return nil, notFound(err)
	}
	oauthProvider, err := instance.oidcProvider(ctx.Context, provider, ctx.Clock)
	if err != nil {
		return nil, providerFailure(err)
	}
	result, err := oauthProvider.Exchange(
		ctx.Context, code, state.Verifier, state.Nonce, state.RedirectURI,
	)
	if err != nil {
		return nil, providerFailure(err)
	}
	if result.Tokens.IDToken == "" {
		return nil, providerFailure(errors.New("OIDC provider returned no ID token"))
	}
	result.Profile.Provider = provider.ProviderID
	if !result.Profile.EmailVerified ||
		!domainAllowed(provider.Domain, emailDomain(result.Profile.Email)) {
		return nil, providerFailure(errors.New("SSO provider returned an unverified or mismatched email"))
	}
	info := UserInfo{
		ID: result.Profile.ProviderAccountID, Email: result.Profile.Email,
		EmailVerified: result.Profile.EmailVerified, Name: result.Profile.Name,
		Image: result.Profile.ImageURL,
	}
	tokens := &Tokens{
		AccessToken: result.Tokens.AccessToken, RefreshToken: result.Tokens.RefreshToken,
		IDToken: result.Tokens.IDToken, Scope: result.Tokens.Scope,
		ExpiresAt: result.Tokens.AccessTokenExpiresAt,
	}
	return instance.completeIdentityWithState(ctx, provider, info, tokens, result.Tokens, state)
}

func (instance *runtime) completeIdentityWithState(
	ctx *betterauth.HookContext,
	provider storedProvider,
	info UserInfo,
	tokens *Tokens,
	coreTokens betterauth.ProviderTokens,
	state protocolState,
) (*betterauth.PluginResponse, error) {
	if ctx.AuthenticateOAuth == nil {
		return nil, internal(errors.New("SSO identity completion is unavailable"))
	}
	if instance.config.DisableImplicitSignUp && !state.RequestSignUp {
		exists, err := ssoIdentityExists(ctx, provider.ProviderID, info.ID, info.Email)
		if err != nil {
			return nil, internal(err)
		}
		if !exists {
			return nil, forbidden(errors.New("implicit SSO sign-up is disabled"))
		}
	}
	issued, isNew, err := ctx.AuthenticateOAuth(betterauth.OAuthProfile{
		Provider: provider.ProviderID, ProviderAccountID: info.ID,
		Email: info.Email, EmailVerified: info.EmailVerified,
		Name: info.Name, ImageURL: info.Image,
	}, coreTokens)
	if err != nil {
		return nil, err
	}
	if provider.OrganizationID != "" && !instance.config.OrganizationProvisioning.Disabled {
		role := instance.config.OrganizationProvisioning.DefaultRole
		if role == "" {
			role = "member"
		}
		if instance.config.OrganizationProvisioning.GetRole != nil {
			role, err = instance.config.OrganizationProvisioning.GetRole(
				ctx, issued.User, info, provider.Provider,
			)
			if err != nil {
				return nil, forbidden(err)
			}
		}
		if err = instance.config.OrganizationAuthorizer.ProvisionSSOUser(
			ctx, provider.OrganizationID, issued.User.ID, role,
		); err != nil {
			return nil, forbidden(err)
		}
	}
	if callback := instance.config.ProvisionUser; callback != nil &&
		(isNew || instance.config.ProvisionUserOnEveryLogin) {
		if err = callback(ctx, issued.User, info, tokens, provider.Provider); err != nil {
			return nil, internal(err)
		}
	}
	response, err := betterauth.JSONResponse(http.StatusOK, map[string]any{
		"redirect": false, "token": nil, "user": issued.User, "isNewUser": isNew,
	})
	if err != nil {
		return nil, err
	}
	destination := state.ReturnTo
	if isNew && state.NewUserTo != "" {
		destination = state.NewUserTo
	}
	if destination != "" {
		response.Status = http.StatusFound
		response.Headers.Set("Location", destination)
		response.Body = nil
	}
	if err = issued.Apply(response); err != nil {
		return nil, internal(err)
	}
	return response, nil
}

func ssoIdentityExists(
	ctx *betterauth.HookContext,
	providerID, accountID, email string,
) (bool, error) {
	account, err := ctx.Database.FindOne(ctx.Context, betterauth.FindOneQuery{
		Model: betterauth.ModelAccount,
		Where: []betterauth.Where{
			betterauth.Eq("providerId", providerID), betterauth.Eq("accountId", accountID),
		},
	})
	if err == nil && account != nil {
		return true, nil
	}
	user, userErr := ctx.Database.FindOne(ctx.Context, betterauth.FindOneQuery{
		Model: betterauth.ModelUser,
		Where: []betterauth.Where{betterauth.Eq("email", strings.ToLower(strings.TrimSpace(email)))},
	})
	if userErr != nil && !errors.Is(userErr, betterauth.ErrNotFound) {
		return false, userErr
	}
	return user != nil, nil
}

func (instance *runtime) oidcRedirectURI(
	ctx *betterauth.HookContext,
	providerID string,
) string {
	if instance.config.RedirectURI == "" {
		return strings.TrimSuffix(ctx.BaseURL, "/") + "/sso/callback/" +
			url.PathEscape(providerID)
	}
	if strings.HasPrefix(instance.config.RedirectURI, "/") {
		return strings.TrimSuffix(ctx.BaseURL, "/") + instance.config.RedirectURI
	}
	return instance.config.RedirectURI
}

func publicProvider(provider storedProvider) map[string]any {
	result := map[string]any{
		"id": provider.ID, "issuer": provider.Issuer, "domain": provider.Domain,
		"providerId": provider.ProviderID, "userId": provider.UserID,
		"organizationId": nullableString(provider.OrganizationID), "type": provider.Type,
		"domainVerified": provider.DomainVerified, "createdAt": provider.CreatedAt,
		"updatedAt": provider.UpdatedAt,
	}
	if provider.OIDC != nil {
		clientID := provider.OIDC.ClientID
		if len(clientID) > 4 {
			clientID = clientID[len(clientID)-4:]
		}
		result["oidcConfig"] = map[string]any{
			"discoveryEndpoint": provider.OIDC.DiscoveryEndpoint,
			"clientIdLastFour":  clientID, "authorizationEndpoint": provider.OIDC.AuthorizationEndpoint,
			"tokenEndpoint":               provider.OIDC.TokenEndpoint,
			"userInfoEndpoint":            provider.OIDC.UserInfoEndpoint,
			"jwksEndpoint":                provider.OIDC.JWKSEndpoint,
			"scopes":                      slices.Clone(provider.OIDC.Scopes),
			"tokenEndpointAuthentication": provider.OIDC.TokenEndpointAuthentication,
		}
	}
	if provider.SAML != nil {
		result["samlConfig"] = map[string]any{
			"entryPoint": provider.SAML.EntryPoint, "audience": provider.SAML.Audience,
			"wantAssertionsSigned":    provider.SAML.WantAssertionsSigned,
			"authnRequestsSigned":     provider.SAML.AuthnRequestsSigned,
			"identifierFormat":        provider.SAML.IdentifierFormat,
			"idpInitiatedCallbackUrl": provider.SAML.IDPInitiatedCallbackURL,
		}
	}
	return result
}

func decodeContextBody(ctx *betterauth.HookContext, destination any) error {
	raw, err := json.Marshal(ctx.Body)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(destination); err != nil {
		return err
	}
	if err = decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("request body has trailing data")
	}
	return nil
}

func (instance *runtime) putDomainVerification(
	ctx *betterauth.HookContext,
	provider storedProvider,
) (string, error) {
	if !instance.config.DomainVerification {
		return "", badRequest(errors.New("domain verification is disabled"))
	}
	token, err := ctx.GenerateToken(24)
	if err != nil {
		return "", internal(err)
	}
	id, err := ctx.GenerateID()
	if err != nil {
		return "", internal(err)
	}
	now := ctx.Clock.Now().UTC()
	_, _ = ctx.Database.DeleteMany(ctx.Context, betterauth.DeleteQuery{
		Model: betterauth.ModelVerification,
		Where: []betterauth.Where{betterauth.Eq("identifier", domainIdentifier(provider.ProviderID))},
	})
	_, err = ctx.Database.Create(ctx.Context, betterauth.CreateQuery{
		Model: betterauth.ModelVerification, ForceAllowID: true,
		Data: betterauth.Record{
			"id": id, "identifier": domainIdentifier(provider.ProviderID),
			"value": betterauth.HashToken(token), "expiresAt": now.Add(7 * 24 * time.Hour),
			"createdAt": now, "metadata": map[string]string{"providerId": provider.ProviderID},
		},
	})
	if err != nil {
		return "", internal(err)
	}
	return token, nil
}

func (instance *runtime) requestDomainVerification(
	ctx *betterauth.HookContext,
) (*betterauth.PluginResponse, error) {
	var request struct {
		ProviderID string `json:"providerId"`
	}
	if err := decodeContextBody(ctx, &request); err != nil {
		return nil, badRequest(err)
	}
	provider, err := instance.findProvider(ctx, request.ProviderID)
	if err != nil {
		return nil, notFound(err)
	}
	if err = instance.authorizeProvider(ctx, provider); err != nil {
		return nil, err
	}
	if provider.DomainVerified {
		return nil, conflict(errors.New("domain is already verified"))
	}
	token, err := instance.putDomainVerification(ctx, provider)
	if err != nil {
		return nil, err
	}
	return betterauth.JSONResponse(http.StatusCreated, map[string]any{
		"token": token,
		"record": "_" + instance.config.DomainVerificationPrefix + "." +
			strings.Split(provider.Domain, ",")[0],
	})
}

func (instance *runtime) verifyDomain(
	ctx *betterauth.HookContext,
) (*betterauth.PluginResponse, error) {
	var request struct {
		ProviderID string `json:"providerId"`
	}
	if err := decodeContextBody(ctx, &request); err != nil {
		return nil, badRequest(err)
	}
	provider, err := instance.findProvider(ctx, request.ProviderID)
	if err != nil {
		return nil, notFound(err)
	}
	if err = instance.authorizeProvider(ctx, provider); err != nil {
		return nil, err
	}
	pending, err := ctx.Database.FindOne(ctx.Context, betterauth.FindOneQuery{
		Model: betterauth.ModelVerification,
		Where: []betterauth.Where{
			betterauth.Eq("identifier", domainIdentifier(provider.ProviderID)),
			{Field: "expiresAt", Operator: betterauth.WhereGT, Value: ctx.Clock.Now().UTC()},
		},
	})
	if err != nil || pending == nil {
		return nil, conflict(errors.New("no pending domain verification"))
	}
	expected := stringRecord(pending, "value")
	matched := false
	for _, domain := range strings.Split(provider.Domain, ",") {
		records, lookupErr := instance.config.DNSResolver.LookupTXT(
			ctx.Context, "_"+instance.config.DomainVerificationPrefix+"."+domain,
		)
		if lookupErr != nil {
			continue
		}
		for _, record := range records {
			actual := betterauth.HashToken(strings.TrimSpace(record))
			if subtle.ConstantTimeCompare([]byte(actual), []byte(expected)) == 1 {
				matched = true
			}
		}
	}
	if !matched {
		return nil, providerFailure(errors.New("domain verification record not found"))
	}
	if _, err = ctx.Database.ConsumeOne(ctx.Context, betterauth.DeleteQuery{
		Model: betterauth.ModelVerification,
		Where: []betterauth.Where{
			betterauth.Eq("id", stringRecord(pending, "id")),
			betterauth.Eq("value", expected),
		},
	}); err != nil {
		return nil, conflict(err)
	}
	if _, err = ctx.Database.Update(ctx.Context, betterauth.UpdateQuery{
		Model: ModelSSOProvider,
		Where: []betterauth.Where{betterauth.Eq("id", provider.ID)},
		Update: betterauth.Record{
			"domainVerified": true, "updatedAt": ctx.Clock.Now().UTC(),
		},
	}); err != nil {
		return nil, internal(err)
	}
	return &betterauth.PluginResponse{
		Status: http.StatusNoContent, Headers: make(http.Header),
	}, nil
}

func domainIdentifier(providerID string) string {
	return "sso_domain:" + providerID
}
