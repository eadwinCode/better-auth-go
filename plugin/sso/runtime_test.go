package sso

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	betterauth "github.com/eadwinCode/better-auth-go"
	"github.com/eadwinCode/better-auth-go/adapter/memory"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/russellhaering/goxmldsig/etreeutils"
)

type runtimeClock struct{ now time.Time }

func (clock runtimeClock) Now() time.Time { return clock.now }

type runtimeMailer struct{}

func (runtimeMailer) Send(context.Context, betterauth.Mail) error { return nil }

type runtimeImpersonation struct{}

func (runtimeImpersonation) CanImpersonate(
	context.Context, betterauth.User, betterauth.User,
) error {
	return errors.New("denied")
}

type staticSPMetadata struct{ metadata *saml.EntityDescriptor }

func (provider staticSPMetadata) GetServiceProvider(
	*http.Request,
	string,
) (*saml.EntityDescriptor, error) {
	return provider.metadata, nil
}

func TestSAMLBlackBoxSignedAssertionCorrelationAndReplay(t *testing.T) {
	t.Parallel()
	idpKey, idpCertificate, certificatePEM := samlCertificate(t)
	cipher, _ := betterauth.NewAESGCMTokenCipher(
		[]byte("0123456789abcdef0123456789abcdef"),
	)
	samlConfig := &SAMLConfig{
		Issuer:               "https://idp.example.com/metadata",
		EntryPoint:           "https://idp.example.com/sso",
		Certificate:          certificatePEM,
		SPEntityID:           "https://auth.example.com/api/auth/sso/saml2/sp/metadata",
		WantAssertionsSigned: true,
	}
	plugin, err := New(Config{
		Cipher:            cipher,
		SAML:              SAMLPolicy{DeprecatedAlgorithms: "allow"},
		OutboundURLPolicy: func(context.Context, *url.URL) error { return nil },
		DefaultProviders: []ProviderRegistration{{
			Issuer: samlConfig.Issuer, Domain: "example.com",
			ProviderID: "enterprise-saml", SAML: samlConfig,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	database := memory.New()
	server, err := betterauth.New(betterauth.Config{
		PublicURL:      "https://auth.example.com",
		TrustedOrigins: []string{"https://app.example.com"},
		Database:       database, Mailer: runtimeMailer{},
		ImpersonationAuthorizer: runtimeImpersonation{},
		ProviderTokenCipher:     cipher, Plugins: []betterauth.Plugin{plugin},
	})
	if err != nil {
		t.Fatal(err)
	}
	start := ssoRequest(t, server.Handler(), http.MethodPost, "/sign-in/sso",
		map[string]any{
			"providerId":  "enterprise-saml",
			"callbackURL": "https://app.example.com/dashboard",
		}, nil)
	if start.Code != http.StatusOK {
		t.Fatalf("SAML start: %d %s", start.Code, start.Body.String())
	}
	var startResult struct {
		URL string `json:"url"`
	}
	if err = json.Unmarshal(start.Body.Bytes(), &startResult); err != nil {
		t.Fatal(err)
	}
	redirect, err := url.Parse(startResult.URL)
	if err != nil {
		t.Fatal(err)
	}
	relayState := redirect.Query().Get("RelayState")
	pending, err := database.FindOne(context.Background(), betterauth.FindOneQuery{
		Model: betterauth.ModelVerification,
		Where: []betterauth.Where{betterauth.Eq("identifier", stateIdentifierSAML)},
	})
	if err != nil {
		t.Fatal(err)
	}
	requestID := stringMapRecord(pending["metadata"])["requestId"]
	if relayState == "" || requestID == "" {
		t.Fatal("SAML request omitted durable correlation")
	}
	sp, err := serviceProvider(
		"enterprise-saml", samlConfig, "https://auth.example.com/api/auth",
	)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	authnRequest := saml.AuthnRequest{
		ID: requestID, Version: "2.0", IssueInstant: now,
		Destination:                 samlConfig.EntryPoint,
		Issuer:                      &saml.Issuer{Value: samlConfig.SPEntityID},
		AssertionConsumerServiceURL: sp.AcsURL.String(),
		ProtocolBinding:             saml.HTTPPostBinding,
	}
	requestBuffer, err := xml.Marshal(authnRequest)
	if err != nil {
		t.Fatal(err)
	}
	idp := saml.IdentityProvider{
		Key: idpKey, Certificate: idpCertificate,
		MetadataURL:             *mustURL(t, samlConfig.Issuer),
		SSOURL:                  *mustURL(t, samlConfig.EntryPoint),
		ServiceProviderProvider: staticSPMetadata{metadata: sp.Metadata()},
		AssertionMaker:          saml.DefaultAssertionMaker{},
	}
	idpRequest := saml.IdpAuthnRequest{
		Now: now, IDP: &idp, RequestBuffer: requestBuffer, RelayState: relayState,
	}
	idpRequest.HTTPRequest = httptest.NewRequest(
		http.MethodPost, samlConfig.EntryPoint, nil,
	)
	if err = idpRequest.Validate(); err != nil {
		t.Fatal(err)
	}
	if err = (saml.DefaultAssertionMaker{}).MakeAssertion(
		&idpRequest,
		&saml.Session{
			ID: "idp-session", Index: "idp-session-index",
			NameID: "enterprise-user-2", UserName: "enterprise-user-2",
			UserEmail: "grace@example.com", UserCommonName: "Grace Enterprise",
			CreateTime: now, ExpireTime: now.Add(10 * time.Minute),
		},
	); err != nil {
		t.Fatal(err)
	}
	if err = idpRequest.MakeAssertionEl(); err != nil {
		t.Fatal(err)
	}
	if err = idpRequest.MakeResponse(); err != nil {
		t.Fatal(err)
	}
	form, err := idpRequest.PostBinding()
	if err != nil {
		t.Fatal(err)
	}
	direct := httptest.NewRequest(
		http.MethodPost, sp.AcsURL.String(),
		strings.NewReader(url.Values{
			"SAMLResponse": {form.SAMLResponse}, "RelayState": {relayState},
		}.Encode()),
	)
	direct.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err = direct.ParseForm(); err != nil {
		t.Fatal(err)
	}
	if _, err = sp.ParseResponse(direct, []string{requestID}); err != nil {
		var invalid *saml.InvalidResponseError
		if errors.As(err, &invalid) {
			t.Fatalf("generated SAML fixture is invalid: %v", invalid.PrivateErr)
		}
		t.Fatalf("generated SAML fixture is invalid: %v", err)
	}
	callback := ssoFormRequest(
		t, server.Handler(), http.MethodPost, "/sso/saml2/sp/acs/enterprise-saml",
		url.Values{"SAMLResponse": {form.SAMLResponse}, "RelayState": {relayState}},
	)
	if callback.Code != http.StatusFound ||
		callback.Header().Get("Location") != "https://app.example.com/dashboard" {
		t.Fatalf("SAML callback: %d %s %s", callback.Code, callback.Header().Get("Location"), callback.Body.String())
	}
	replay := ssoFormRequest(
		t, server.Handler(), http.MethodPost, "/sso/saml2/sp/acs/enterprise-saml",
		url.Values{"SAMLResponse": {form.SAMLResponse}, "RelayState": {relayState}},
	)
	if replay.Code != http.StatusBadRequest {
		t.Fatalf("SAML replay status = %d body=%s", replay.Code, replay.Body.String())
	}
}

func TestSAMLDeprecatedAlgorithmsFailClosed(t *testing.T) {
	t.Parallel()
	raw := base64.StdEncoding.EncodeToString([]byte(
		`<ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>`,
	))
	if err := validateSAMLAlgorithms(raw, "reject"); err == nil {
		t.Fatal("expected deprecated SAML signature algorithm to be rejected")
	}
	if err := validateSAMLAlgorithms(raw, "allow"); err != nil {
		t.Fatalf("explicit compatibility policy failed: %v", err)
	}
}

func TestSAMLRawAssertionSigningPolicyMatrix(t *testing.T) {
	t.Parallel()
	key, certificate, certificatePEM := samlCertificate(t)
	cases := []struct {
		name           string
		signResponse   bool
		signAssertion  bool
		wantAssertions bool
		wantError      bool
	}{
		{"signed response, unsigned assertion, response policy", true, false, false, false},
		{"signed response, unsigned assertion, assertion policy", true, false, true, true},
		{"unsigned response, signed assertion, response policy", false, true, false, false},
		{"unsigned response, signed assertion, assertion policy", false, true, true, false},
		{"both signed, assertion policy", true, true, true, false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			encoded := signedSAMLResponse(
				t, key, certificate, testCase.signResponse, testCase.signAssertion,
			)
			err := validateRawSAMLAssertion(encoded, &SAMLConfig{
				Certificate: certificatePEM, WantAssertionsSigned: testCase.wantAssertions,
			})
			if (err != nil) != testCase.wantError {
				t.Fatalf("validateRawSAMLAssertion() error = %v, wantError %v", err, testCase.wantError)
			}
		})
	}
}

func TestSAMLRawAssertionRejectsSignatureWrapping(t *testing.T) {
	t.Parallel()
	key, certificate, certificatePEM := samlCertificate(t)
	encoded := signedSAMLResponse(t, key, certificate, false, true)
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	document := etree.NewDocument()
	if err = document.ReadFromBytes(raw); err != nil {
		t.Fatal(err)
	}
	wrapper := document.Root().CreateElement("saml:Advice")
	wrapper.CreateElement("saml:Assertion").CreateAttr("ID", "_attacker")
	encoded = encodeXMLDocument(t, document)
	if err = validateRawSAMLAssertion(encoded, &SAMLConfig{
		Certificate: certificatePEM, WantAssertionsSigned: true,
	}); err == nil {
		t.Fatal("signature-wrapping response was accepted")
	}
}

func TestSAMLRawAssertionRejectsMalformedAndForeignSignatureXML(t *testing.T) {
	t.Parallel()
	_, _, certificatePEM := samlCertificate(t)
	malformed := base64.StdEncoding.EncodeToString([]byte(
		`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">`,
	))
	if err := validateRawSAMLAssertion(malformed, &SAMLConfig{
		Certificate: certificatePEM, WantAssertionsSigned: true,
	}); err == nil {
		t.Fatal("malformed XML was accepted")
	}
	foreignSignature := base64.StdEncoding.EncodeToString([]byte(
		`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:evil="urn:attacker"><saml:Assertion ID="_a"><evil:Signature/></saml:Assertion></samlp:Response>`,
	))
	if err := validateRawSAMLAssertion(foreignSignature, &SAMLConfig{
		Certificate: certificatePEM, WantAssertionsSigned: true,
	}); err == nil {
		t.Fatal("foreign-namespace signature decoy was accepted")
	}
}

func TestSAMLMetadataReflectsSigningPolicyAndEnforcesSize(t *testing.T) {
	t.Parallel()
	key, _, certificatePEM := samlCertificate(t)
	for _, wantAssertionsSigned := range []bool{false, true} {
		config := &SAMLConfig{
			Issuer: "https://idp.example.com/metadata", EntryPoint: "https://idp.example.com/sso",
			Certificate: certificatePEM, SPEntityID: "https://auth.example.com/saml/metadata",
			WantAssertionsSigned: wantAssertionsSigned,
		}
		sp, err := serviceProvider("policy", config, "https://auth.example.com/api/auth")
		if err != nil {
			t.Fatal(err)
		}
		body, err := marshalSAMLMetadata(sp, config, 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		var metadata saml.EntityDescriptor
		if err = xml.Unmarshal(body, &metadata); err != nil {
			t.Fatal(err)
		}
		if len(metadata.SPSSODescriptors) != 1 ||
			metadata.SPSSODescriptors[0].WantAssertionsSigned == nil ||
			*metadata.SPSSODescriptors[0].WantAssertionsSigned != wantAssertionsSigned ||
			metadata.SPSSODescriptors[0].AuthnRequestsSigned == nil ||
			*metadata.SPSSODescriptors[0].AuthnRequestsSigned {
			t.Fatalf("metadata signing policy mismatch: %s", body)
		}
		if _, err = marshalSAMLMetadata(sp, config, 1); err == nil {
			t.Fatal("oversized SAML metadata was accepted")
		}
	}
	privateKey, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	signedConfig := &SAMLConfig{
		Issuer: "https://idp.example.com/metadata", EntryPoint: "https://idp.example.com/sso",
		Certificate: certificatePEM, SPEntityID: "https://auth.example.com/saml/metadata",
		SPPrivateKey: string(pem.EncodeToMemory(&pem.Block{
			Type: "PRIVATE KEY", Bytes: privateKey,
		})),
		AuthnRequestsSigned: true,
	}
	sp, err := serviceProvider("signed-policy", signedConfig, "https://auth.example.com/api/auth")
	if err != nil {
		t.Fatal(err)
	}
	body, err := marshalSAMLMetadata(sp, signedConfig, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	var metadata saml.EntityDescriptor
	if err = xml.Unmarshal(body, &metadata); err != nil {
		t.Fatal(err)
	}
	if metadata.SPSSODescriptors[0].AuthnRequestsSigned == nil ||
		!*metadata.SPSSODescriptors[0].AuthnRequestsSigned {
		t.Fatalf("signed-request metadata policy mismatch: %s", body)
	}
}

func signedSAMLResponse(
	t *testing.T,
	key crypto.Signer,
	certificate *x509.Certificate,
	signResponse bool,
	signAssertion bool,
) string {
	t.Helper()
	document := etree.NewDocument()
	if err := document.ReadFromString(
		`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_response"><saml:Assertion ID="_assertion"><saml:Issuer>https://idp.example.com/metadata</saml:Issuer></saml:Assertion></samlp:Response>`,
	); err != nil {
		t.Fatal(err)
	}
	context, err := dsig.NewSigningContext(key, [][]byte{certificate.Raw})
	if err != nil {
		t.Fatal(err)
	}
	context.IdAttribute = "ID"
	if signAssertion {
		assertion := document.Root().ChildElements()[0]
		namespaceContext, contextErr := etreeutils.NSBuildParentContext(assertion)
		if contextErr != nil {
			t.Fatal(contextErr)
		}
		namespaceContext, contextErr = namespaceContext.SubContext(assertion)
		if contextErr != nil {
			t.Fatal(contextErr)
		}
		detached, contextErr := etreeutils.NSDetatch(namespaceContext, assertion)
		if contextErr != nil {
			t.Fatal(contextErr)
		}
		signed, signErr := context.SignEnveloped(detached)
		if signErr != nil {
			t.Fatal(signErr)
		}
		document.Root().RemoveChild(assertion)
		document.Root().AddChild(signed)
	}
	if signResponse {
		signed, signErr := context.SignEnveloped(document.Root())
		if signErr != nil {
			t.Fatal(signErr)
		}
		document.SetRoot(signed)
	}
	return encodeXMLDocument(t, document)
}

func encodeXMLDocument(t *testing.T, document *etree.Document) string {
	t.Helper()
	raw, err := document.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func samlCertificate(t *testing.T) (*rsa.PrivateKey, *x509.Certificate, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "idp.example.com"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(
		rand.Reader, template, template, &key.PublicKey, key,
	)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return key, certificate, string(pem.EncodeToMemory(
		&pem.Block{Type: "CERTIFICATE", Bytes: der},
	))
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	value, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

type oidcFixture struct {
	mu    sync.Mutex
	key   *rsa.PrivateKey
	clock runtimeClock
	nonce string
}

func newOIDCFixture(t *testing.T, clock runtimeClock) *oidcFixture {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return &oidcFixture{key: key, clock: clock}
}

func (fixture *oidcFixture) Do(request *http.Request) (*http.Response, error) {
	switch request.URL.Path {
	case "/.well-known/openid-configuration":
		return fixture.response(http.StatusOK, map[string]any{
			"issuer":                                "https://idp.example.com",
			"authorization_endpoint":                "https://idp.example.com/authorize",
			"token_endpoint":                        "https://idp.example.com/token",
			"jwks_uri":                              "https://idp.example.com/jwks",
			"response_types_supported":              []string{"code"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
			"token_endpoint_auth_methods_supported": []string{"client_secret_basic"},
		}), nil
	case "/token":
		if err := request.ParseForm(); err != nil {
			return nil, err
		}
		if request.Form.Get("code") != "valid-code" ||
			request.Form.Get("code_verifier") == "" {
			return fixture.response(http.StatusBadRequest, map[string]any{"error": "invalid_grant"}), nil
		}
		fixture.mu.Lock()
		nonce := fixture.nonce
		fixture.mu.Unlock()
		token, err := fixture.idToken(nonce)
		if err != nil {
			return nil, err
		}
		return fixture.response(http.StatusOK, map[string]any{
			"access_token":  "plain-sso-access",
			"refresh_token": "plain-sso-refresh",
			"id_token":      token, "token_type": "Bearer", "expires_in": 600,
		}), nil
	case "/jwks":
		exponent := big.NewInt(int64(fixture.key.PublicKey.E)).Bytes()
		return fixture.response(http.StatusOK, map[string]any{
			"keys": []map[string]any{{
				"kty": "RSA", "kid": "sso-key", "use": "sig", "alg": "RS256",
				"n": base64.RawURLEncoding.EncodeToString(fixture.key.PublicKey.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(exponent),
			}},
		}), nil
	default:
		return fixture.response(http.StatusNotFound, map[string]any{"error": "not_found"}), nil
	}
}

func (fixture *oidcFixture) idToken(nonce string) (string, error) {
	header, _ := json.Marshal(map[string]any{"alg": "RS256", "kid": "sso-key", "typ": "JWT"})
	claims, _ := json.Marshal(map[string]any{
		"iss": "https://idp.example.com", "aud": "sso-client",
		"sub": "enterprise-user-1", "email": "ada@example.com",
		"email_verified": true, "name": "Ada Enterprise", "nonce": nonce,
		"iat": fixture.clock.now.Unix(), "exp": fixture.clock.now.Add(10 * time.Minute).Unix(),
	})
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." +
		base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, fixture.key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func (fixture *oidcFixture) response(status int, value any) *http.Response {
	body, _ := json.Marshal(value)
	return &http.Response{
		StatusCode: status, Header: make(http.Header),
		Body: io.NopCloser(bytes.NewReader(body)),
	}
}

func TestOIDCBlackBoxStatePKCENonceSessionAndReplay(t *testing.T) {
	t.Parallel()
	clock := runtimeClock{now: time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)}
	fixture := newOIDCFixture(t, clock)
	cipher, err := betterauth.NewAESGCMTokenCipher(
		[]byte("0123456789abcdef0123456789abcdef"),
	)
	if err != nil {
		t.Fatal(err)
	}
	plugin, err := New(Config{
		Cipher: cipher, HTTPClient: fixture,
		OutboundURLPolicy: func(context.Context, *url.URL) error { return nil },
		DefaultProviders: []ProviderRegistration{{
			Issuer: "https://idp.example.com", Domain: "example.com",
			ProviderID: "enterprise", OIDC: &OIDCConfig{
				Issuer: "https://idp.example.com", ClientID: "sso-client",
				ClientSecret: "sso-secret",
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	database := memory.New()
	server, err := betterauth.New(betterauth.Config{
		PublicURL:      "https://auth.example.com",
		TrustedOrigins: []string{"https://app.example.com"},
		Database:       database, Clock: clock, Mailer: runtimeMailer{},
		ImpersonationAuthorizer: runtimeImpersonation{},
		ProviderTokenCipher:     cipher, Plugins: []betterauth.Plugin{plugin},
	})
	if err != nil {
		t.Fatal(err)
	}
	signIn := ssoRequest(t, server.Handler(), http.MethodPost, "/sign-in/sso",
		map[string]any{
			"providerId":  "enterprise",
			"callbackURL": "https://app.example.com/dashboard",
		}, nil)
	if signIn.Code != http.StatusOK {
		t.Fatalf("sign in start: %d %s", signIn.Code, signIn.Body.String())
	}
	var authorization struct {
		URL string `json:"url"`
	}
	if err = json.Unmarshal(signIn.Body.Bytes(), &authorization); err != nil {
		t.Fatal(err)
	}
	destination, err := url.Parse(authorization.URL)
	if err != nil {
		t.Fatal(err)
	}
	state := destination.Query().Get("state")
	nonce := destination.Query().Get("nonce")
	challenge := destination.Query().Get("code_challenge")
	if state == "" || nonce == "" || challenge == "" ||
		destination.Query().Get("code_challenge_method") != "S256" {
		t.Fatalf("authorization URL omitted security parameters: %s", authorization.URL)
	}
	fixture.mu.Lock()
	fixture.nonce = nonce
	fixture.mu.Unlock()
	pending, err := database.FindOne(context.Background(), betterauth.FindOneQuery{
		Model: betterauth.ModelVerification,
		Where: []betterauth.Where{betterauth.Eq("identifier", stateIdentifierOIDC)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if stringRecord(pending, "value") == state || stringRecord(pending, "value") == "" {
		t.Fatal("raw OAuth state was persisted")
	}
	callback := ssoRequest(
		t, server.Handler(), http.MethodGet,
		"/sso/callback/enterprise?code=valid-code&state="+url.QueryEscape(state), nil, nil,
	)
	if callback.Code != http.StatusFound ||
		callback.Header().Get("Location") != "https://app.example.com/dashboard" {
		t.Fatalf("callback: %d %s %s", callback.Code, callback.Header().Get("Location"), callback.Body.String())
	}
	cookies := callback.Result().Cookies()
	sessionCookie := findCookie(cookies, "__Host-better_auth_session")
	if sessionCookie == nil || !sessionCookie.Secure || !sessionCookie.HttpOnly ||
		sessionCookie.Domain != "" || sessionCookie.Path != "/" {
		t.Fatal("SSO callback did not issue a secure host-only session")
	}
	account, err := database.FindOne(context.Background(), betterauth.FindOneQuery{
		Model: betterauth.ModelAccount,
		Where: []betterauth.Where{
			betterauth.Eq("providerId", "enterprise"),
			betterauth.Eq("accountId", "enterprise-user-1"),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if stringRecord(account, "accessToken") == "plain-sso-access" ||
		stringRecord(account, "refreshToken") == "plain-sso-refresh" {
		t.Fatal("SSO provider tokens were persisted in plaintext")
	}
	replay := ssoRequest(
		t, server.Handler(), http.MethodGet,
		"/sso/callback/enterprise?code=valid-code&state="+url.QueryEscape(state), nil, nil,
	)
	if replay.Code != http.StatusBadRequest {
		t.Fatalf("state replay status = %d body=%s", replay.Code, replay.Body.String())
	}
}

func TestOIDCProviderErrorConsumesState(t *testing.T) {
	t.Parallel()
	// Covered at the handler boundary so the failure cannot be retried with a
	// successful code after an IdP error.
	clock := runtimeClock{now: time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)}
	fixture := newOIDCFixture(t, clock)
	cipher, _ := betterauth.NewAESGCMTokenCipher(
		[]byte("0123456789abcdef0123456789abcdef"),
	)
	plugin, err := New(Config{
		Cipher: cipher, HTTPClient: fixture,
		OutboundURLPolicy: func(context.Context, *url.URL) error { return nil },
		DefaultProviders: []ProviderRegistration{{
			Issuer: "https://idp.example.com", Domain: "example.com",
			ProviderID: "enterprise", OIDC: &OIDCConfig{
				Issuer: "https://idp.example.com", ClientID: "sso-client",
				ClientSecret: "sso-secret",
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	database := memory.New()
	server, err := betterauth.New(betterauth.Config{
		PublicURL:      "https://auth.example.com",
		TrustedOrigins: []string{"https://app.example.com"},
		Database:       database, Clock: clock, Mailer: runtimeMailer{},
		ImpersonationAuthorizer: runtimeImpersonation{},
		ProviderTokenCipher:     cipher, Plugins: []betterauth.Plugin{plugin},
	})
	if err != nil {
		t.Fatal(err)
	}
	start := ssoRequest(t, server.Handler(), http.MethodPost, "/sign-in/sso",
		map[string]any{
			"providerId": "enterprise", "callbackURL": "https://app.example.com/",
			"errorCallbackURL": "https://app.example.com/error",
		}, nil)
	var result struct {
		URL string `json:"url"`
	}
	_ = json.Unmarshal(start.Body.Bytes(), &result)
	parsed, _ := url.Parse(result.URL)
	state := parsed.Query().Get("state")
	failed := ssoRequest(
		t, server.Handler(), http.MethodGet,
		"/sso/callback/enterprise?error=access_denied&state="+url.QueryEscape(state), nil, nil,
	)
	if failed.Code != http.StatusFound ||
		!strings.HasPrefix(failed.Header().Get("Location"), "https://app.example.com/error?") {
		t.Fatalf("provider error response = %d %s", failed.Code, failed.Header().Get("Location"))
	}
	replay := ssoRequest(
		t, server.Handler(), http.MethodGet,
		"/sso/callback/enterprise?code=valid-code&state="+url.QueryEscape(state), nil, nil,
	)
	if replay.Code != http.StatusBadRequest {
		t.Fatalf("provider-error replay status = %d", replay.Code)
	}
}

func ssoRequest(
	t *testing.T,
	handler http.Handler,
	method, path string,
	body map[string]any,
	cookies []*http.Cookie,
) *httptest.ResponseRecorder {
	t.Helper()
	var payload []byte
	if body != nil {
		var err error
		payload, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	request := httptest.NewRequest(
		method, "https://auth.example.com/api/auth"+path, bytes.NewReader(payload),
	)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Origin", "https://app.example.com")
	}
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func ssoFormRequest(
	t *testing.T,
	handler http.Handler,
	method, path string,
	form url.Values,
) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(
		method, "https://auth.example.com/api/auth"+path,
		strings.NewReader(form.Encode()),
	)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func findCookie(cookies []*http.Cookie, name string) *http.Cookie {
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}
