package passkey

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"

	betterauth "github.com/eadwinCode/better-auth-go"
)

const (
	ceremonyRegistration   = "registration"
	ceremonyAuthentication = "authentication"
)

func (instance *runtime) plugin() betterauth.Plugin {
	ownership, err := betterauth.RequireResourceOwnership(betterauth.ResourceOwnershipConfig{
		Model: ModelPasskey, IDSource: betterauth.ResourceIDBody,
		IDParam: "id", OwnerField: "userId",
	})
	if err != nil {
		panic(err)
	}
	generationMatcher := func(context *betterauth.HookContext) bool {
		return context.Path == "/passkey/generate-register-options" ||
			context.Path == "/passkey/generate-authenticate-options"
	}
	verificationMatcher := func(context *betterauth.HookContext) bool {
		return context.Path == "/passkey/verify-registration" ||
			context.Path == "/passkey/verify-authentication"
	}
	registrationGenerateUse := []betterauth.RequestHook{betterauth.FreshSessionMiddleware}
	registrationVerifyUse := []betterauth.RequestHook{
		betterauth.FreshSessionMiddleware, betterauth.CSRFMiddleware,
	}
	if instance.config.Registration.AllowWithoutSession {
		registrationGenerateUse = []betterauth.RequestHook{optionalFreshSession}
		registrationVerifyUse = []betterauth.RequestHook{optionalFreshSessionAndCSRF}
	}
	return betterauth.Plugin{
		ID:             "passkey",
		Schema:         instance.schema,
		TrustedOrigins: instance.config.Origins,
		RateLimits: []betterauth.PluginRateLimitRule{
			{
				Matcher: generationMatcher, Action: "passkey.challenge",
				Window: 10 * time.Minute, Max: 60,
				AccountKey: func(context *betterauth.HookContext) string {
					if context.User != nil {
						return context.User.ID
					}
					return ""
				},
			},
			{
				Matcher: verificationMatcher, Action: "passkey.verify",
				Window: 10 * time.Minute, Max: 20,
				AccountKey: func(context *betterauth.HookContext) string {
					if context.User != nil {
						return context.User.ID
					}
					return ""
				},
			},
		},
		Endpoints: []betterauth.PluginEndpoint{
			{
				Name: "generatePasskeyRegistrationOptions",
				Path: "/passkey/generate-register-options", Method: http.MethodGet,
				Use: registrationGenerateUse,
				QueryValidator: betterauth.ObjectValidator{Fields: map[string]betterauth.FieldValidation{
					"authenticatorAttachment": {
						Kind: betterauth.ValidationString,
						Enum: []string{"platform", "cross-platform"},
					},
					"name":    {Kind: betterauth.ValidationString, MaxLength: 254},
					"context": {Kind: betterauth.ValidationString, MaxLength: 512},
				}},
				Handler: instance.generateRegistrationOptions,
			},
			{
				Name: "verifyPasskeyRegistration",
				Path: "/passkey/verify-registration", Method: http.MethodPost,
				Use: registrationVerifyUse,
				BodyValidator: betterauth.ObjectValidator{Fields: map[string]betterauth.FieldValidation{
					"response":      {Kind: betterauth.ValidationObject, Required: true},
					"createSession": {Kind: betterauth.ValidationBoolean},
					"name": {
						Kind: betterauth.ValidationString, MinLength: 1, MaxLength: 128,
					},
				}},
				Handler: instance.verifyRegistration,
			},
			{
				Name: "generatePasskeyAuthenticationOptions",
				Path: "/passkey/generate-authenticate-options", Method: http.MethodGet,
				QueryValidator: betterauth.ObjectValidator{Fields: map[string]betterauth.FieldValidation{}},
				Handler:        instance.generateAuthenticationOptions,
			},
			{
				Name: "verifyPasskeyAuthentication",
				Path: "/passkey/verify-authentication", Method: http.MethodPost,
				BodyValidator: betterauth.ObjectValidator{Fields: map[string]betterauth.FieldValidation{
					"response": {Kind: betterauth.ValidationObject, Required: true},
				}},
				Handler: instance.verifyAuthentication,
			},
			{
				Name: "listPasskeys",
				Path: "/passkey/list-user-passkeys", Method: http.MethodGet,
				Use:     []betterauth.RequestHook{betterauth.SessionMiddleware},
				Handler: instance.listPasskeys,
			},
			{
				Name: "updatePasskey",
				Path: "/passkey/update-passkey", Method: http.MethodPost,
				Use: []betterauth.RequestHook{
					betterauth.SessionMiddleware, betterauth.CSRFMiddleware, ownership,
				},
				BodyValidator: betterauth.ObjectValidator{Fields: map[string]betterauth.FieldValidation{
					"id":   {Kind: betterauth.ValidationString, Required: true, MinLength: 1, MaxLength: 512},
					"name": {Kind: betterauth.ValidationString, Required: true, MinLength: 1, MaxLength: 128},
				}},
				Handler: instance.updatePasskey,
			},
			{
				Name: "deletePasskey",
				Path: "/passkey/delete-passkey", Method: http.MethodPost,
				Use: []betterauth.RequestHook{
					betterauth.SessionMiddleware, betterauth.CSRFMiddleware, ownership,
				},
				BodyValidator: betterauth.ObjectValidator{Fields: map[string]betterauth.FieldValidation{
					"id": {Kind: betterauth.ValidationString, Required: true, MinLength: 1, MaxLength: 512},
				}},
				Handler: instance.deletePasskey,
			},
		},
	}
}

func basePasskeySchema() betterauth.Schema {
	return betterauth.Schema{
		ModelPasskey: {
			Fields: map[string]betterauth.FieldSchema{
				"id":             {Type: betterauth.FieldString, Required: true, Unique: true},
				"name":           {Type: betterauth.FieldString, Returned: true},
				"publicKey":      {Type: betterauth.FieldString, Required: true, Returned: true},
				"userId":         {Type: betterauth.FieldString, Required: true, Index: true, References: betterauth.ModelUser},
				"credentialID":   {Type: betterauth.FieldString, Required: true, Unique: true, Returned: true},
				"counter":        {Type: betterauth.FieldNumber, Required: true, Returned: true},
				"deviceType":     {Type: betterauth.FieldString, Required: true, Returned: true},
				"backedUp":       {Type: betterauth.FieldBoolean, Required: true, Returned: true},
				"transports":     {Type: betterauth.FieldString, Returned: true},
				"createdAt":      {Type: betterauth.FieldDate, Required: true, Returned: true},
				"updatedAt":      {Type: betterauth.FieldDate, Required: true, Returned: true},
				"aaguid":         {Type: betterauth.FieldString, Returned: true},
				"userHandle":     {Type: betterauth.FieldString, Required: true, Index: true},
				"credentialData": {Type: betterauth.FieldJSON, Required: true},
			},
		},
	}
}

func (instance *runtime) generateRegistrationOptions(
	context *betterauth.HookContext,
) (*betterauth.PluginResponse, error) {
	registrationUser, err := instance.resolveRegistrationUser(context)
	if err != nil {
		return nil, err
	}
	passkeys, err := instance.findUserPasskeys(context, registrationUser.ID)
	if err != nil {
		return nil, internalError(err)
	}
	if len(passkeys) >= instance.config.MaxCredentials {
		return nil, betterauth.NewError(
			betterauth.CodeConflict, "The maximum number of passkeys has been reached.",
			http.StatusConflict, nil,
		)
	}
	handle, err := instance.registrationUserHandle(context, passkeys)
	if err != nil {
		return nil, internalError(err)
	}
	name := strings.TrimSpace(context.Query.Get("name"))
	if name == "" {
		name = registrationUser.Name
	}
	displayName := registrationUser.DisplayName
	if displayName == "" {
		displayName = name
	}
	user := makeWebAuthnUser(registrationUser.ID, handle, name, displayName, passkeys)
	selection := instance.webAuthn.Config.AuthenticatorSelection
	if attachment := context.Query.Get("authenticatorAttachment"); attachment != "" {
		selection.AuthenticatorAttachment = protocol.AuthenticatorAttachment(attachment)
	}
	registrationOptions := []webauthn.RegistrationOption{
		webauthn.WithAuthenticatorSelection(selection),
		webauthn.WithExclusions(credentialDescriptors(passkeys)),
	}
	extensions, err := resolveExtensions(instance.config.Registration.Extensions, context)
	if err != nil {
		return nil, internalError(err)
	}
	if len(extensions) > 0 {
		registrationOptions = append(
			registrationOptions,
			webauthn.WithExtensions(protocol.AuthenticationExtensions(extensions)),
		)
	}
	options, session, err := instance.webAuthn.BeginRegistration(user, registrationOptions...)
	if err != nil {
		return nil, internalError(err)
	}
	challenge := storedChallenge{
		Type: ceremonyRegistration, UserID: registrationUser.ID,
		UserName: name, DisplayName: displayName,
		Context: context.Query.Get("context"), Session: *session,
	}
	response, err := betterauth.JSONResponse(http.StatusOK, options.Response)
	if err != nil {
		return nil, err
	}
	if err := instance.putChallenge(context, response, challenge); err != nil {
		return nil, internalError(err)
	}
	return response, nil
}

func (instance *runtime) verifyRegistration(
	context *betterauth.HookContext,
) (*betterauth.PluginResponse, error) {
	challenge, err := instance.consumeChallenge(context, ceremonyRegistration)
	if err != nil {
		return nil, challengeError(err)
	}
	if context.User != nil && challenge.UserID != context.User.ID {
		return nil, betterauth.NewError(
			betterauth.CodeUnauthorized, "You are not allowed to register this passkey.",
			http.StatusUnauthorized, nil,
		)
	}
	responseBytes, err := responseBytes(context)
	if err != nil {
		return nil, verificationError("Failed to verify registration.", err)
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(responseBytes)
	if err != nil {
		return nil, verificationError("Failed to verify registration.", err)
	}
	existing, err := instance.findUserPasskeys(context, challenge.UserID)
	if err != nil {
		return nil, internalError(err)
	}
	user := makeWebAuthnUser(
		challenge.UserID, challenge.Session.UserID, challenge.UserName,
		challenge.DisplayName, existing,
	)
	credential, err := instance.webAuthn.CreateCredential(user, challenge.Session, parsed)
	if err != nil {
		return nil, verificationError("Failed to verify registration.", err)
	}
	targetUserID := challenge.UserID
	name := strings.TrimSpace(bodyString(context, "name"))
	if callback := instance.config.Registration.AfterVerification; callback != nil {
		clientData, clientErr := clientResponse(context)
		if clientErr != nil {
			return nil, verificationError("Failed to verify registration.", clientErr)
		}
		resolution, callbackErr := callback(context, RegistrationVerification{
			User: RegistrationUser{
				ID: challenge.UserID, Name: challenge.UserName,
				DisplayName: challenge.DisplayName,
			},
			Context: challenge.Context, CredentialID: encodeCredentialID(credential.ID),
			AAGUID: credentialAAGUID(credential), DeviceType: deviceType(credential),
			BackedUp: credential.Flags.BackupState, ClientData: clientData,
		})
		if callbackErr != nil {
			return nil, verificationError("Failed to verify registration.", callbackErr)
		}
		if resolution.UserID != "" {
			targetUserID = strings.TrimSpace(resolution.UserID)
		}
		if name == "" {
			name = strings.TrimSpace(resolution.Name)
		}
	}
	if targetUserID == "" || context.User != nil && targetUserID != context.User.ID {
		return nil, betterauth.NewError(
			betterauth.CodeUnauthorized, "You are not allowed to register this passkey.",
			http.StatusUnauthorized, nil,
		)
	}
	target, err := context.Database.FindOne(context.Context, betterauth.FindOneQuery{
		Model:  betterauth.ModelUser,
		Where:  []betterauth.Where{betterauth.Eq("id", targetUserID)},
		Select: []string{"id"},
	})
	if err != nil || target == nil {
		return nil, verificationError("Resolved user is invalid.", err)
	}
	createSession := bodyBool(context, "createSession")
	var (
		passkey Passkey
		issued  *betterauth.IssuedSession
	)
	err = context.Database.Transaction(context.Context, func(tx betterauth.DatabaseAdapter) error {
		txContext := *context
		txContext.Database = tx
		created, createErr := instance.createPasskey(
			&txContext, targetUserID, name, challenge.Session.UserID, credential,
		)
		if createErr != nil {
			return createErr
		}
		passkey = created
		if !createSession {
			return nil
		}
		if context.IssueSessionWithDatabase == nil {
			return errors.New("passkey: transactional session issuance is unavailable")
		}
		issued, createErr = context.IssueSessionWithDatabase(tx, targetUserID)
		return createErr
	})
	if err != nil {
		if errors.Is(err, betterauth.ErrConflict) {
			return nil, betterauth.NewError(
				betterauth.CodeConflict, "Previously registered.",
				http.StatusConflict, err,
			)
		}
		return nil, internalError(err)
	}
	var responseBody any = passkey
	if issued != nil {
		encoded, marshalErr := json.Marshal(passkey)
		if marshalErr != nil {
			return nil, internalError(marshalErr)
		}
		withSession := make(map[string]any)
		if unmarshalErr := json.Unmarshal(encoded, &withSession); unmarshalErr != nil {
			return nil, internalError(unmarshalErr)
		}
		withSession["session"] = issued.Session
		withSession["user"] = issued.User
		responseBody = withSession
	}
	response, err := betterauth.JSONResponse(http.StatusOK, responseBody)
	if err != nil {
		return nil, err
	}
	if issued != nil {
		if err := issued.Apply(response); err != nil {
			return nil, internalError(err)
		}
	}
	_ = instance.clearChallengeCookie(context, response)
	return response, nil
}

func (instance *runtime) generateAuthenticationOptions(
	context *betterauth.HookContext,
) (*betterauth.PluginResponse, error) {
	var (
		options  *protocol.CredentialAssertion
		session  *webauthn.SessionData
		userID   string
		passkeys []Passkey
		err      error
	)
	if context.User != nil {
		userID = context.User.ID
		passkeys, err = instance.findUserPasskeys(context, userID)
		if err != nil {
			return nil, internalError(err)
		}
	}
	if len(passkeys) > 0 {
		user := makeWebAuthnUser(
			userID, passkeys[0].userHandle, context.User.Email, context.User.Name, passkeys,
		)
		loginOptions, extensionErr := instance.loginOptions(context)
		if extensionErr != nil {
			return nil, internalError(extensionErr)
		}
		options, session, err = instance.webAuthn.BeginLogin(user, loginOptions...)
	} else {
		// Discoverable authentication is bound to the credential owner found at
		// verification, not to an unrelated browser session.
		userID = ""
		loginOptions, extensionErr := instance.loginOptions(context)
		if extensionErr != nil {
			return nil, internalError(extensionErr)
		}
		options, session, err = instance.webAuthn.BeginDiscoverableLogin(loginOptions...)
	}
	if err != nil {
		return nil, verificationError("Authentication failed.", err)
	}
	response, err := betterauth.JSONResponse(http.StatusOK, options.Response)
	if err != nil {
		return nil, err
	}
	if err := instance.putChallenge(context, response, storedChallenge{
		Type: ceremonyAuthentication, UserID: userID, Session: *session,
	}); err != nil {
		return nil, internalError(err)
	}
	return response, nil
}

func (instance *runtime) verifyAuthentication(
	context *betterauth.HookContext,
) (*betterauth.PluginResponse, error) {
	challenge, err := instance.consumeChallenge(context, ceremonyAuthentication)
	if err != nil {
		return nil, challengeError(err)
	}
	responseBytes, err := responseBytes(context)
	if err != nil {
		return nil, authenticationError(err)
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(responseBytes)
	if err != nil {
		return nil, authenticationError(err)
	}

	var (
		owner           webAuthnUser
		credential      *webauthn.Credential
		expectedCounter uint32
	)
	if challenge.UserID != "" {
		passkeys, findErr := instance.findUserPasskeys(context, challenge.UserID)
		if findErr != nil || len(passkeys) == 0 {
			return nil, authenticationError(findErr)
		}
		owner = makeWebAuthnUser(
			challenge.UserID, passkeys[0].userHandle, "", "", passkeys,
		)
		var verifyErr error
		credential, verifyErr = instance.webAuthn.ValidateLogin(owner, challenge.Session, parsed)
		if verifyErr != nil {
			return nil, authenticationError(verifyErr)
		}
		var counterErr error
		expectedCounter, counterErr = credentialCounter(owner, credential.ID)
		if counterErr != nil {
			return nil, authenticationError(counterErr)
		}
	} else {
		user, verifiedCredential, verifyErr := instance.webAuthn.ValidatePasskeyLogin(
			func(rawID, userHandle []byte) (webauthn.User, error) {
				resolved, resolveErr := instance.findDiscoverableUser(context, rawID, userHandle)
				if resolveErr == nil {
					owner = resolved
				}
				return resolved, resolveErr
			},
			challenge.Session,
			parsed,
		)
		if verifyErr != nil || user == nil {
			return nil, authenticationError(verifyErr)
		}
		credential = verifiedCredential
		var counterErr error
		expectedCounter, counterErr = credentialCounter(owner, credential.ID)
		if counterErr != nil {
			return nil, authenticationError(counterErr)
		}
	}
	if callback := instance.config.Authentication.AfterVerification; callback != nil {
		clientData, clientErr := clientResponse(context)
		if clientErr != nil {
			return nil, authenticationError(clientErr)
		}
		if err := callback(context, AuthenticationVerification{
			UserID: owner.id, CredentialID: encodeCredentialID(credential.ID),
			NewCounter: credential.Authenticator.SignCount,
			BackedUp:   credential.Flags.BackupState, ClientData: clientData,
		}); err != nil {
			return nil, authenticationError(err)
		}
	}
	if err := instance.persistAuthentication(
		context, owner.id, expectedCounter, credential,
	); err != nil {
		return nil, authenticationError(err)
	}
	if context.IssueSession == nil {
		return nil, internalError(errors.New("passkey: session issuance is unavailable"))
	}
	issued, err := context.IssueSession(owner.id)
	if err != nil {
		return nil, betterauth.NewError(
			betterauth.CodeInternal, "Unable to create session.",
			http.StatusInternalServerError, err,
		)
	}
	response, err := betterauth.JSONResponse(http.StatusOK, map[string]any{
		"session": issued.Session,
		"user":    issued.User,
	})
	if err != nil {
		return nil, err
	}
	if err := issued.Apply(response); err != nil {
		return nil, internalError(err)
	}
	_ = instance.clearChallengeCookie(context, response)
	return response, nil
}

func (instance *runtime) listPasskeys(
	context *betterauth.HookContext,
) (*betterauth.PluginResponse, error) {
	passkeys, err := instance.findUserPasskeys(context, context.User.ID)
	if err != nil {
		return nil, internalError(err)
	}
	return betterauth.JSONResponse(http.StatusOK, passkeys)
}

func (instance *runtime) updatePasskey(
	context *betterauth.HookContext,
) (*betterauth.PluginResponse, error) {
	id := bodyString(context, "id")
	name := strings.TrimSpace(bodyString(context, "name"))
	if name == "" {
		return nil, betterauth.NewError(
			betterauth.CodeBadRequest, "Invalid endpoint input.",
			http.StatusBadRequest, nil,
		)
	}
	row, err := context.Database.Update(context.Context, betterauth.UpdateQuery{
		Model: ModelPasskey,
		Where: []betterauth.Where{
			betterauth.Eq("id", id), betterauth.Eq("userId", context.User.ID),
		},
		Update: betterauth.Record{
			"name": name, "updatedAt": context.Clock.Now().UTC(),
		},
	})
	if err != nil || row == nil {
		return nil, internalError(err)
	}
	passkey, err := passkeyFromRecord(row)
	if err != nil {
		return nil, internalError(err)
	}
	return betterauth.JSONResponse(http.StatusOK, map[string]any{"passkey": passkey})
}

func (instance *runtime) deletePasskey(
	context *betterauth.HookContext,
) (*betterauth.PluginResponse, error) {
	err := context.Database.Delete(context.Context, betterauth.DeleteQuery{
		Model: ModelPasskey,
		Where: []betterauth.Where{
			betterauth.Eq("id", bodyString(context, "id")),
			betterauth.Eq("userId", context.User.ID),
		},
	})
	if err != nil {
		return nil, internalError(err)
	}
	return betterauth.JSONResponse(http.StatusOK, map[string]bool{"status": true})
}

func makeWebAuthnUser(
	id string,
	handle []byte,
	name string,
	displayName string,
	passkeys []Passkey,
) webAuthnUser {
	credentials := make([]webauthn.Credential, len(passkeys))
	for index := range passkeys {
		credentials[index] = passkeys[index].credential
	}
	return webAuthnUser{
		id: id, handle: handle, name: name,
		displayName: displayName, credentials: credentials,
	}
}

func credentialDescriptors(passkeys []Passkey) []protocol.CredentialDescriptor {
	result := make([]protocol.CredentialDescriptor, len(passkeys))
	for index := range passkeys {
		result[index] = passkeys[index].credential.Descriptor()
	}
	return result
}

func credentialCounter(user webAuthnUser, credentialID []byte) (uint32, error) {
	encoded := encodeCredentialID(credentialID)
	for _, credential := range user.credentials {
		if encodeCredentialID(credential.ID) == encoded {
			return credential.Authenticator.SignCount, nil
		}
	}
	return 0, betterauth.ErrNotFound
}

func optionalFreshSession(context *betterauth.HookContext) (*betterauth.PluginResponse, error) {
	if context.Session == nil {
		return nil, nil
	}
	return betterauth.FreshSessionMiddleware(context)
}

func optionalFreshSessionAndCSRF(
	context *betterauth.HookContext,
) (*betterauth.PluginResponse, error) {
	if context.Session == nil {
		return nil, nil
	}
	if response, err := betterauth.FreshSessionMiddleware(context); response != nil || err != nil {
		return response, err
	}
	return betterauth.CSRFMiddleware(context)
}

func (instance *runtime) resolveRegistrationUser(
	context *betterauth.HookContext,
) (RegistrationUser, error) {
	if context.User != nil {
		name := context.User.Email
		if name == "" {
			name = context.User.ID
		}
		displayName := context.User.Name
		if displayName == "" {
			displayName = name
		}
		return RegistrationUser{
			ID: context.User.ID, Name: name, DisplayName: displayName,
		}, nil
	}
	if !instance.config.Registration.AllowWithoutSession ||
		instance.config.Registration.ResolveUser == nil {
		return RegistrationUser{}, betterauth.NewError(
			betterauth.CodeUnauthorized, "Passkey registration requires an authenticated session.",
			http.StatusUnauthorized, nil,
		)
	}
	user, err := instance.config.Registration.ResolveUser(
		context, context.Query.Get("context"),
	)
	user.ID = strings.TrimSpace(user.ID)
	user.Name = strings.TrimSpace(user.Name)
	user.DisplayName = strings.TrimSpace(user.DisplayName)
	if err != nil || user.ID == "" || user.Name == "" ||
		len(user.ID) > 512 || len(user.Name) > 254 || len(user.DisplayName) > 254 {
		return RegistrationUser{}, betterauth.NewError(
			betterauth.CodeBadRequest, "Resolved user is invalid.",
			http.StatusBadRequest, err,
		)
	}
	return user, nil
}

func resolveExtensions(
	resolver ExtensionsResolver,
	context *betterauth.HookContext,
) (map[string]any, error) {
	if resolver == nil {
		return nil, nil
	}
	extensions, err := resolver(context)
	if err != nil {
		return nil, err
	}
	return maps.Clone(extensions), nil
}

func (instance *runtime) loginOptions(
	context *betterauth.HookContext,
) ([]webauthn.LoginOption, error) {
	extensions, err := resolveExtensions(instance.config.Authentication.Extensions, context)
	if err != nil || len(extensions) == 0 {
		return nil, err
	}
	return []webauthn.LoginOption{
		webauthn.WithAssertionExtensions(protocol.AuthenticationExtensions(extensions)),
	}, nil
}

func clientResponse(context *betterauth.HookContext) (map[string]any, error) {
	body, ok := context.Body.(map[string]any)
	if !ok {
		return nil, errors.New("passkey: invalid request body")
	}
	response, ok := body["response"].(map[string]any)
	if !ok {
		return nil, errors.New("passkey: invalid credential response")
	}
	return maps.Clone(response), nil
}

func bodyString(context *betterauth.HookContext, key string) string {
	body, _ := context.Body.(map[string]any)
	value, _ := body[key].(string)
	return value
}

func bodyBool(context *betterauth.HookContext, key string) bool {
	body, _ := context.Body.(map[string]any)
	value, _ := body[key].(bool)
	return value
}

func responseBytes(context *betterauth.HookContext) ([]byte, error) {
	body, ok := context.Body.(map[string]any)
	if !ok {
		return nil, errors.New("passkey: invalid request body")
	}
	return json.Marshal(body["response"])
}

func verificationError(message string, cause error) error {
	return betterauth.NewError(betterauth.CodeBadRequest, message, http.StatusBadRequest, cause)
}

func authenticationError(cause error) error {
	return betterauth.NewError(
		betterauth.CodeUnauthorized, "Authentication failed.", http.StatusUnauthorized, cause,
	)
}

func challengeError(cause error) error {
	return betterauth.NewError(
		betterauth.CodeBadRequest, "Challenge not found.", http.StatusBadRequest, cause,
	)
}

func internalError(cause error) error {
	if cause == nil {
		cause = errors.New("passkey: unexpected empty result")
	}
	return betterauth.NewError(
		betterauth.CodeInternal, "The request could not be completed.",
		http.StatusInternalServerError, cause,
	)
}

func encodeCredentialID(value []byte) string {
	return base64.RawURLEncoding.EncodeToString(value)
}

func credentialAAGUID(credential *webauthn.Credential) string {
	if credential == nil || len(credential.Authenticator.AAGUID) != 16 {
		return ""
	}
	value, err := uuid.FromBytes(credential.Authenticator.AAGUID)
	if err != nil || value == uuid.Nil {
		return ""
	}
	return value.String()
}

func deviceType(credential *webauthn.Credential) string {
	if credential.Flags.BackupEligible {
		return "multiDevice"
	}
	return "singleDevice"
}

func credentialTransports(credential *webauthn.Credential) string {
	values := make([]string, len(credential.Transport))
	for index := range credential.Transport {
		values[index] = string(credential.Transport[index])
	}
	return strings.Join(values, ",")
}

func credentialRecord(credential *webauthn.Credential) (any, error) {
	raw, err := json.Marshal(credential)
	if err != nil {
		return nil, fmt.Errorf("passkey: encode credential: %w", err)
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, fmt.Errorf("passkey: normalize credential: %w", err)
	}
	return value, nil
}
