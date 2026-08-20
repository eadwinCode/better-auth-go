package sso

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	betterauth "github.com/eadwinCode/better-auth-go"
	xrv "github.com/mattermost/xml-roundtrip-validator"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/russellhaering/goxmldsig/etreeutils"
)

const (
	samlAssertionNamespace = "urn:oasis:names:tc:SAML:2.0:assertion"
	samlProtocolNamespace  = "urn:oasis:names:tc:SAML:2.0:protocol"
	xmlSignatureNamespace  = "http://www.w3.org/2000/09/xmldsig#"
)

func serviceProvider(
	providerID string,
	config *SAMLConfig,
	baseURL string,
) (*saml.ServiceProvider, error) {
	if config == nil {
		return nil, errors.New("sso: provider is not SAML")
	}
	certificate, err := normalizeCertificate(config.Certificate)
	if err != nil {
		return nil, err
	}
	metadataURL, _ := url.Parse(strings.TrimSuffix(baseURL, "/") +
		"/sso/saml2/sp/metadata?providerId=" + url.QueryEscape(providerID))
	acsURL, _ := url.Parse(strings.TrimSuffix(baseURL, "/") +
		"/sso/saml2/sp/acs/" + url.PathEscape(providerID))
	sloURL, _ := url.Parse(strings.TrimSuffix(baseURL, "/") +
		"/sso/saml2/sp/slo/" + url.PathEscape(providerID))
	sp := &saml.ServiceProvider{
		EntityID: config.SPEntityID, MetadataURL: *metadataURL, AcsURL: *acsURL,
		SloURL: *sloURL, IDPMetadata: &saml.EntityDescriptor{EntityID: config.Issuer},
		IDPCertificate: &certificate, AllowIDPInitiated: false,
		AuthnNameIDFormat: saml.NameIDFormat(config.IdentifierFormat),
	}
	if config.SPPrivateKey != "" {
		signer, parseErr := parseSigner(config.SPPrivateKey)
		if parseErr != nil {
			return nil, parseErr
		}
		sp.Key = signer
		switch signer.(type) {
		case *rsa.PrivateKey:
			sp.SignatureMethod = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
		case *ecdsa.PrivateKey:
			sp.SignatureMethod = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
		}
	}
	if config.AuthnRequestsSigned && sp.Key == nil {
		return nil, errors.New("sso: signed SAML requests require an SP private key")
	}
	return sp, nil
}

func normalizeCertificate(value string) (string, error) {
	value = strings.TrimSpace(value)
	block, _ := pem.Decode([]byte(value))
	if block == nil {
		decoded, err := base64.StdEncoding.DecodeString(
			strings.Join(strings.Fields(value), ""),
		)
		if err != nil {
			return "", errors.New("sso: invalid SAML certificate")
		}
		block = &pem.Block{Type: "CERTIFICATE", Bytes: decoded}
	}
	if block.Type != "CERTIFICATE" {
		return "", errors.New("sso: invalid SAML certificate")
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		return "", errors.New("sso: invalid SAML certificate")
	}
	return base64.StdEncoding.EncodeToString(block.Bytes), nil
}

func parseSigner(value string) (crypto.Signer, error) {
	block, _ := pem.Decode([]byte(value))
	if block == nil {
		return nil, errors.New("sso: invalid SAML SP private key")
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, errors.New("sso: unsupported SAML SP private key")
		}
		return signer, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, errors.New("sso: invalid SAML SP private key")
}

func (instance *runtime) startSAML(
	ctx *betterauth.HookContext,
	provider storedProvider,
	stateData protocolState,
) (*betterauth.PluginResponse, error) {
	sp, err := serviceProvider(provider.ProviderID, provider.SAML, ctx.BaseURL)
	if err != nil {
		return nil, providerFailure(err)
	}
	request, err := sp.MakeAuthenticationRequest(
		provider.SAML.EntryPoint, saml.HTTPRedirectBinding, saml.HTTPPostBinding,
	)
	if err != nil {
		return nil, providerFailure(err)
	}
	stateData.ProviderID = provider.ProviderID
	stateData.RequestID = request.ID
	state, err := instance.createState(ctx, stateIdentifierSAML, stateData)
	if err != nil {
		return nil, internal(err)
	}
	destination, err := request.Redirect(state, sp)
	if err != nil {
		return nil, providerFailure(err)
	}
	for key, value := range provider.SAML.AdditionalParams {
		query := destination.Query()
		query.Set(key, value)
		destination.RawQuery = query.Encode()
	}
	return betterauth.JSONResponse(http.StatusOK, map[string]any{
		"url": destination.String(), "redirect": true,
	})
}

func (instance *runtime) samlCallback(
	ctx *betterauth.HookContext,
) (*betterauth.PluginResponse, error) {
	provider, err := instance.findProvider(ctx, ctx.Params["providerId"])
	if err != nil || provider.SAML == nil {
		return nil, notFound(err)
	}
	if err = boundSAMLRequest(ctx.Request, instance.config.SAML.MaxResponseSize); err != nil {
		return nil, invalidState(err)
	}
	if err = validateSAMLAlgorithms(
		ctx.Request.FormValue("SAMLResponse"),
		instance.config.SAML.DeprecatedAlgorithms,
	); err != nil {
		return nil, invalidState(err)
	}
	relayState := ctx.Request.FormValue("RelayState")
	var state protocolState
	if relayState != "" {
		state, err = instance.consumeState(ctx, stateIdentifierSAML, relayState)
		if err != nil || state.ProviderID != provider.ProviderID {
			return nil, invalidState(err)
		}
	} else if !instance.config.SAML.AllowIDPInitiated {
		return nil, invalidState(errors.New("sso: missing SAML RelayState"))
	}
	sp, err := serviceProvider(provider.ProviderID, provider.SAML, ctx.BaseURL)
	if err != nil {
		return nil, providerFailure(err)
	}
	if err = validateRawSAMLAssertion(
		ctx.Request.FormValue("SAMLResponse"), provider.SAML,
	); err != nil {
		return nil, invalidState(err)
	}
	sp.AllowIDPInitiated = instance.config.SAML.AllowIDPInitiated
	request := ctx.Request.Clone(ctx.Context)
	request.URL = cloneURL(&sp.AcsURL)
	request.RequestURI = ""
	ids := []string(nil)
	if state.RequestID != "" {
		ids = []string{state.RequestID}
	}
	assertion, err := sp.ParseResponse(request, ids)
	if err != nil {
		return nil, invalidState(err)
	}
	if err = instance.recordSAMLAssertion(ctx, assertion.ID); err != nil {
		return nil, invalidState(err)
	}
	userInfo, err := samlUserInfo(assertion, provider.SAML.Mapping)
	if err != nil || !domainAllowed(provider.Domain, emailDomain(userInfo.Email)) {
		return nil, providerFailure(errors.New("sso: SAML identity domain mismatch"))
	}
	return instance.completeIdentityWithState(
		ctx, provider, userInfo, nil, betterauth.ProviderTokens{}, state,
	)
}

// validateRawSAMLAssertion applies the assertion-signing policy to the exact
// XML received from the IdP. This must run before ParseResponse unmarshals the
// response: verifying a reconstructed assertion would re-introduce XML
// signature-wrapping ambiguity.
func validateRawSAMLAssertion(encoded string, config *SAMLConfig) error {
	if config == nil || encoded == "" {
		return errors.New("sso: missing SAML response")
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return errors.New("sso: malformed SAML response")
	}
	if err = xrv.Validate(bytes.NewReader(raw)); err != nil {
		return errors.New("sso: malformed SAML response XML")
	}
	document := etree.NewDocument()
	if err = document.ReadFromBytes(raw); err != nil || document.Root() == nil {
		return errors.New("sso: malformed SAML response XML")
	}
	root := document.Root()
	if root.Tag != "Response" || root.NamespaceURI() != samlProtocolNamespace {
		return errors.New("sso: SAML response has an invalid root element")
	}

	var assertions []*etree.Element
	var encryptedAssertions []*etree.Element
	walkElements(root, func(element *etree.Element) {
		if element.NamespaceURI() != samlAssertionNamespace {
			return
		}
		switch element.Tag {
		case "Assertion":
			assertions = append(assertions, element)
		case "EncryptedAssertion":
			encryptedAssertions = append(encryptedAssertions, element)
		}
	})
	if len(assertions)+len(encryptedAssertions) != 1 {
		return errors.New("sso: SAML response must contain exactly one assertion")
	}
	if len(encryptedAssertions) != 0 {
		// Encrypted assertions are not currently wired into serviceProvider. Fail
		// closed instead of applying a signing policy to unverifiable ciphertext.
		return errors.New("sso: encrypted SAML assertions are not supported")
	}
	assertion := assertions[0]
	if assertion.Parent() != root {
		return errors.New("sso: SAML assertion must be a direct response child")
	}

	var signatures []*etree.Element
	walkElements(assertion, func(element *etree.Element) {
		if element.Tag == "Signature" {
			signatures = append(signatures, element)
		}
	})
	if len(signatures) > 1 {
		return errors.New("sso: SAML assertion contains multiple signatures")
	}
	if len(signatures) == 0 {
		if config.WantAssertionsSigned {
			return errors.New("sso: SAML assertion signature is required")
		}
		return nil
	}
	if signatures[0].Parent() != assertion ||
		signatures[0].NamespaceURI() != xmlSignatureNamespace {
		return errors.New("sso: SAML assertion signature is invalid")
	}
	assertionID := assertion.SelectAttrValue("ID", "")
	if assertionID == "" {
		return errors.New("sso: signed SAML assertion is missing an ID")
	}

	certificate, err := parseSAMLVerificationCertificate(config.Certificate)
	if err != nil {
		return err
	}
	namespaceContext, err := etreeutils.NSBuildParentContext(assertion)
	if err != nil {
		return fmt.Errorf("sso: prepare SAML assertion signature: %w", err)
	}
	namespaceContext, err = namespaceContext.SubContext(assertion)
	if err != nil {
		return fmt.Errorf("sso: prepare SAML assertion signature: %w", err)
	}
	detached, err := etreeutils.NSDetatch(namespaceContext, assertion)
	if err != nil {
		return fmt.Errorf("sso: prepare SAML assertion signature: %w", err)
	}
	store := &dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{certificate}}
	validation := dsig.NewDefaultValidationContext(store)
	validation.IdAttribute = "ID"
	authenticated, err := validation.Validate(detached)
	if err != nil {
		return fmt.Errorf("sso: invalid SAML assertion signature: %w", err)
	}
	if authenticated.Tag != "Assertion" ||
		authenticated.NamespaceURI() != samlAssertionNamespace ||
		authenticated.SelectAttrValue("ID", "") != assertionID {
		return errors.New("sso: SAML signature authenticated a different assertion")
	}
	return nil
}

func walkElements(root *etree.Element, visit func(*etree.Element)) {
	visit(root)
	for _, child := range root.ChildElements() {
		walkElements(child, visit)
	}
}

func parseSAMLVerificationCertificate(value string) (*x509.Certificate, error) {
	normalized, err := normalizeCertificate(value)
	if err != nil {
		return nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(normalized)
	if err != nil {
		return nil, errors.New("sso: invalid SAML certificate")
	}
	certificate, err := x509.ParseCertificate(raw)
	if err != nil {
		return nil, errors.New("sso: invalid SAML certificate")
	}
	return certificate, nil
}

func validateSAMLAlgorithms(encoded, policy string) error {
	if policy != "reject" || encoded == "" {
		return nil
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return errors.New("sso: malformed SAML response")
	}
	for _, deprecated := range [][]byte{
		[]byte("http://www.w3.org/2000/09/xmldsig#rsa-sha1"),
		[]byte("http://www.w3.org/2000/09/xmldsig#dsa-sha1"),
		[]byte("http://www.w3.org/2000/09/xmldsig#sha1"),
		[]byte("http://www.w3.org/2001/04/xmlenc#rsa-1_5"),
		[]byte("http://www.w3.org/2001/04/xmlenc#tripledes-cbc"),
	} {
		if bytes.Contains(raw, deprecated) {
			return errors.New("sso: deprecated SAML algorithm rejected")
		}
	}
	return nil
}

func (instance *runtime) recordSAMLAssertion(
	ctx *betterauth.HookContext,
	assertionID string,
) error {
	if assertionID == "" || len(assertionID) > 2048 {
		return errors.New("sso: invalid SAML assertion identifier")
	}
	id, err := ctx.GenerateID()
	if err != nil {
		return err
	}
	now := ctx.Clock.Now().UTC()
	_, err = ctx.Database.Create(ctx.Context, betterauth.CreateQuery{
		Model: betterauth.ModelVerification, ForceAllowID: true,
		Data: betterauth.Record{
			"id": id, "identifier": "sso_saml_assertion",
			"value":     betterauth.HashToken(assertionID),
			"expiresAt": now.Add(instance.config.SAML.RequestTTL), "createdAt": now,
		},
	})
	if errors.Is(err, betterauth.ErrConflict) {
		return betterauth.ErrReplay
	}
	return err
}

func boundSAMLRequest(request *http.Request, limit int64) error {
	if request.Method != http.MethodPost {
		if len(request.URL.RawQuery) > int(limit) {
			return errors.New("sso: SAML response is too large")
		}
		return request.ParseForm()
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, limit+1))
	if err != nil {
		return err
	}
	if int64(len(body)) > limit {
		return errors.New("sso: SAML response is too large")
	}
	request.Body = io.NopCloser(strings.NewReader(string(body)))
	request.ContentLength = int64(len(body))
	return request.ParseForm()
}

func samlUserInfo(assertion *saml.Assertion, mapping SAMLMapping) (UserInfo, error) {
	if assertion == nil {
		return UserInfo{}, errors.New("sso: missing SAML assertion")
	}
	attributes := map[string]any{}
	for _, statement := range assertion.AttributeStatements {
		for _, attribute := range statement.Attributes {
			if len(attribute.Values) == 0 {
				continue
			}
			attributes[attribute.Name] = attribute.Values[0].Value
			if attribute.FriendlyName != "" {
				attributes[attribute.FriendlyName] = attribute.Values[0].Value
			}
		}
	}
	nameID := ""
	if assertion.Subject != nil && assertion.Subject.NameID != nil {
		nameID = assertion.Subject.NameID.Value
	}
	id := firstAttribute(attributes, mapping.ID, "id", "uid")
	if id == "" {
		id = nameID
	}
	email := firstAttribute(
		attributes, mapping.Email, "email", "mail",
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
	)
	if email == "" && strings.Contains(nameID, "@") {
		email = nameID
	}
	name := firstAttribute(
		attributes, mapping.Name, "name", "cn",
		"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
	)
	if name == "" {
		first := firstAttribute(attributes, mapping.FirstName, "firstName", "givenName")
		last := firstAttribute(attributes, mapping.LastName, "lastName", "surname")
		name = strings.TrimSpace(first + " " + last)
	}
	if id == "" || email == "" {
		return UserInfo{}, errors.New("sso: incomplete SAML identity")
	}
	return UserInfo{
		ID: id, Email: email, EmailVerified: true, Name: name, Attributes: attributes,
	}, nil
}

func firstAttribute(values map[string]any, names ...string) string {
	for _, name := range names {
		if name == "" {
			continue
		}
		if value, ok := values[name].(string); ok && strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func cloneURL(value *url.URL) *url.URL {
	copy := *value
	return &copy
}

func (instance *runtime) samlMetadata(
	ctx *betterauth.HookContext,
) (*betterauth.PluginResponse, error) {
	provider, err := instance.findProvider(ctx, ctx.Query.Get("providerId"))
	if err != nil || provider.SAML == nil {
		return nil, notFound(err)
	}
	sp, err := serviceProvider(provider.ProviderID, provider.SAML, ctx.BaseURL)
	if err != nil {
		return nil, providerFailure(err)
	}
	body, err := marshalSAMLMetadata(sp, provider.SAML, instance.config.SAML.MaxMetadataSize)
	if err != nil {
		return nil, providerFailure(err)
	}
	return &betterauth.PluginResponse{
		Status: http.StatusOK,
		Headers: http.Header{
			"Content-Type":  []string{"application/samlmetadata+xml"},
			"Cache-Control": []string{"no-store"},
		},
		Body: body,
	}, nil
}

func marshalSAMLMetadata(
	sp *saml.ServiceProvider,
	config *SAMLConfig,
	limit int64,
) ([]byte, error) {
	if sp == nil || config == nil {
		return nil, errors.New("sso: missing SAML metadata configuration")
	}
	metadata := sp.Metadata()
	if len(metadata.SPSSODescriptors) != 1 {
		return nil, errors.New("sso: invalid generated SAML metadata")
	}
	metadata.SPSSODescriptors[0].AuthnRequestsSigned = boolPointer(config.AuthnRequestsSigned)
	metadata.SPSSODescriptors[0].WantAssertionsSigned = boolPointer(config.WantAssertionsSigned)
	body, err := xml.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return nil, err
	}
	body = append([]byte(xml.Header), body...)
	if limit <= 0 || int64(len(body)) > limit {
		return nil, errors.New("sso: generated SAML metadata is too large")
	}
	return body, nil
}

func boolPointer(value bool) *bool { return &value }

func (instance *runtime) initiateSAMLLogout(
	ctx *betterauth.HookContext,
) (*betterauth.PluginResponse, error) {
	if !instance.config.SAML.EnableSingleLogout {
		return nil, badRequest(errors.New("SAML single logout is disabled"))
	}
	var body struct {
		CallbackURL string `json:"callbackURL,omitempty"`
	}
	if err := decodeContextBody(ctx, &body); err != nil {
		return nil, badRequest(err)
	}
	provider, err := instance.findProvider(ctx, ctx.Params["providerId"])
	if err != nil || provider.SAML == nil {
		return nil, notFound(err)
	}
	if provider.SAML.LogoutEndpoint == "" {
		return nil, badRequest(errors.New("SAML logout endpoint is not configured"))
	}
	returnTo, err := safeReturnTo(ctx, body.CallbackURL)
	if err != nil {
		return nil, badRequest(err)
	}
	account, err := ctx.Database.FindOne(ctx.Context, betterauth.FindOneQuery{
		Model: betterauth.ModelAccount,
		Where: []betterauth.Where{
			betterauth.Eq("userId", ctx.User.ID),
			betterauth.Eq("providerId", provider.ProviderID),
		},
	})
	if err != nil || account == nil {
		return nil, notFound(err)
	}
	sp, err := serviceProvider(provider.ProviderID, provider.SAML, ctx.BaseURL)
	if err != nil {
		return nil, providerFailure(err)
	}
	state, err := instance.createState(ctx, stateIdentifierSLO, protocolState{
		ProviderID: provider.ProviderID, ReturnTo: returnTo,
	})
	if err != nil {
		return nil, internal(err)
	}
	logoutRequest, err := sp.MakeLogoutRequest(
		provider.SAML.LogoutEndpoint, stringRecord(account, "accountId"),
	)
	if err != nil {
		return nil, providerFailure(err)
	}
	if instance.config.SAML.WantLogoutRequestSigned {
		if err = sp.SignLogoutRequest(logoutRequest); err != nil {
			return nil, providerFailure(err)
		}
	}
	destination := logoutRequest.Redirect(state)
	now := ctx.Clock.Now().UTC()
	if _, err = ctx.Database.Update(ctx.Context, betterauth.UpdateQuery{
		Model: betterauth.ModelSession,
		Where: []betterauth.Where{
			betterauth.Eq("id", ctx.Session.ID),
			betterauth.Eq("tokenHash", ctx.Session.TokenHash),
		},
		Update: betterauth.Record{"revokedAt": now, "updatedAt": now},
	}); err != nil {
		return nil, internal(err)
	}
	response, err := betterauth.JSONResponse(http.StatusOK, map[string]any{
		"url": destination.String(), "redirect": true,
	})
	if err != nil {
		return nil, err
	}
	clearAuthCookies(ctx, response)
	return response, nil
}

func (instance *runtime) samlLogoutCallback(
	ctx *betterauth.HookContext,
) (*betterauth.PluginResponse, error) {
	if !instance.config.SAML.EnableSingleLogout {
		return nil, badRequest(errors.New("SAML single logout is disabled"))
	}
	if err := boundSAMLRequest(ctx.Request, instance.config.SAML.MaxResponseSize); err != nil {
		return nil, invalidState(err)
	}
	state, err := instance.consumeState(
		ctx, stateIdentifierSLO, ctx.Request.FormValue("RelayState"),
	)
	if err != nil || state.ProviderID != ctx.Params["providerId"] {
		return nil, invalidState(err)
	}
	provider, err := instance.findProvider(ctx, state.ProviderID)
	if err != nil || provider.SAML == nil {
		return nil, notFound(err)
	}
	if ctx.Request.FormValue("SAMLRequest") != "" {
		return nil, badRequest(errors.New("IdP-initiated logout requests are not enabled"))
	}
	sp, err := serviceProvider(provider.ProviderID, provider.SAML, ctx.BaseURL)
	if err != nil {
		return nil, providerFailure(err)
	}
	if err = sp.ValidateLogoutResponseRequest(ctx.Request); err != nil {
		return nil, invalidState(err)
	}
	response := &betterauth.PluginResponse{
		Status: http.StatusNoContent, Headers: make(http.Header),
	}
	if state.ReturnTo != "" {
		response.Status = http.StatusFound
		response.Headers.Set("Location", state.ReturnTo)
	}
	clearAuthCookies(ctx, response)
	return response, nil
}

func clearAuthCookies(ctx *betterauth.HookContext, response *betterauth.PluginResponse) {
	for _, cookie := range []*http.Cookie{
		{
			Name: ctx.Cookies.Name, Value: "", Path: "/", MaxAge: -1,
			Expires: time.Unix(1, 0), Secure: true, HttpOnly: true,
			SameSite: ctx.Cookies.SameSite,
		},
		{
			Name: ctx.Cookies.CSRFName, Value: "", Path: "/", MaxAge: -1,
			Expires: time.Unix(1, 0), Secure: true, HttpOnly: false,
			SameSite: ctx.Cookies.SameSite,
		},
	} {
		response.Headers.Add("Set-Cookie", cookie.String())
	}
}
