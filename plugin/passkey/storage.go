package passkey

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"

	betterauth "github.com/eadwinCode/better-auth-go"
)

func (instance *runtime) putChallenge(
	context *betterauth.HookContext,
	response *betterauth.PluginResponse,
	challenge storedChallenge,
) error {
	if context.GenerateID == nil || context.GenerateToken == nil {
		return errors.New("passkey: token generation is unavailable")
	}
	handle, err := context.GenerateToken(32)
	if err != nil {
		return err
	}
	id, err := context.GenerateID()
	if err != nil {
		return err
	}
	metadata, err := normalizeJSON(challenge)
	if err != nil {
		return err
	}
	now := context.Clock.Now().UTC()
	expires := now.Add(instance.config.ChallengeTTL)
	if _, err := context.Database.Create(context.Context, betterauth.CreateQuery{
		Model: betterauth.ModelVerification,
		Data: betterauth.Record{
			"id": id, "identifier": "passkey:" + challenge.Type,
			"value": betterauth.HashToken(handle), "expiresAt": expires,
			"createdAt": now, "metadata": metadata,
		},
		ForceAllowID: true,
	}); err != nil {
		return err
	}
	return response.SetCookie(&http.Cookie{
		Name: instance.config.ChallengeCookie, Value: handle, Path: "/",
		Expires: expires, MaxAge: int(instance.config.ChallengeTTL.Seconds()),
		Secure: true, HttpOnly: true, SameSite: context.Cookies.SameSite,
	})
}

func (instance *runtime) consumeChallenge(
	context *betterauth.HookContext,
	ceremony string,
) (storedChallenge, error) {
	handle, err := challengeHandle(context.Request, instance.config.ChallengeCookie)
	if err != nil {
		return storedChallenge{}, betterauth.ErrNotFound
	}
	now := context.Clock.Now().UTC()
	row, err := context.Database.ConsumeOne(context.Context, betterauth.DeleteQuery{
		Model: betterauth.ModelVerification,
		Where: []betterauth.Where{
			betterauth.Eq("identifier", "passkey:"+ceremony),
			betterauth.Eq("value", betterauth.HashToken(handle)),
			{Field: "expiresAt", Operator: betterauth.WhereGT, Value: now},
		},
	})
	if err != nil || row == nil {
		if err == nil {
			err = betterauth.ErrNotFound
		}
		return storedChallenge{}, err
	}
	var challenge storedChallenge
	raw, err := json.Marshal(row["metadata"])
	if err != nil {
		return storedChallenge{}, err
	}
	if err := json.Unmarshal(raw, &challenge); err != nil ||
		challenge.Type != ceremony || challenge.Session.Challenge == "" ||
		challenge.Session.RelyingPartyID != instance.config.RPID {
		return storedChallenge{}, betterauth.ErrReplay
	}
	return challenge, nil
}

func challengeHandle(request *http.Request, cookieName string) (string, error) {
	if request == nil || cookieName == "" {
		return "", betterauth.ErrNotFound
	}
	cookie, err := request.Cookie(cookieName)
	if err != nil || cookie.Value == "" || len(cookie.Value) > 512 {
		return "", betterauth.ErrNotFound
	}
	return cookie.Value, nil
}

func (instance *runtime) clearChallengeCookie(
	context *betterauth.HookContext,
	response *betterauth.PluginResponse,
) error {
	return response.SetCookie(&http.Cookie{
		Name: instance.config.ChallengeCookie, Value: "", Path: "/",
		Expires: time.Unix(1, 0), MaxAge: -1,
		Secure: true, HttpOnly: true, SameSite: context.Cookies.SameSite,
	})
}

func (instance *runtime) registrationUserHandle(
	context *betterauth.HookContext,
	passkeys []Passkey,
) ([]byte, error) {
	if len(passkeys) > 0 {
		handle := passkeys[0].userHandle
		expected := base64.RawURLEncoding.EncodeToString(handle)
		for index := 1; index < len(passkeys); index++ {
			if base64.RawURLEncoding.EncodeToString(passkeys[index].userHandle) != expected {
				return nil, errors.New("passkey: inconsistent user handles")
			}
		}
		return handle, nil
	}
	if context.GenerateToken == nil {
		return nil, errors.New("passkey: token generation is unavailable")
	}
	raw, err := context.GenerateToken(32)
	if err != nil {
		return nil, err
	}
	return []byte(raw), nil
}

func (instance *runtime) createPasskey(
	context *betterauth.HookContext,
	userID string,
	name string,
	userHandle []byte,
	credential *webauthn.Credential,
) (Passkey, error) {
	id, err := context.GenerateID()
	if err != nil {
		return Passkey{}, err
	}
	data, err := credentialRecord(credential)
	if err != nil {
		return Passkey{}, err
	}
	now := context.Clock.Now().UTC()
	handle := base64.RawURLEncoding.EncodeToString(userHandle)
	var row betterauth.Record
	err = context.Database.Transaction(context.Context, func(tx betterauth.DatabaseAdapter) error {
		count, countErr := tx.Count(context.Context, betterauth.CountQuery{
			Model: ModelPasskey,
			Where: []betterauth.Where{betterauth.Eq("userId", userID)},
		})
		if countErr != nil {
			return countErr
		}
		if count >= int64(instance.config.MaxCredentials) {
			return betterauth.ErrConflict
		}
		existing, findErr := tx.FindOne(context.Context, betterauth.FindOneQuery{
			Model:  ModelPasskey,
			Where:  []betterauth.Where{betterauth.Eq("userId", userID)},
			Select: []string{"userHandle"},
		})
		if findErr != nil {
			return findErr
		}
		if existing != nil && existing["userHandle"] != handle {
			return betterauth.ErrConflict
		}
		duplicate, findErr := tx.FindOne(context.Context, betterauth.FindOneQuery{
			Model: ModelPasskey,
			Where: []betterauth.Where{
				betterauth.Eq("credentialID", encodeCredentialID(credential.ID)),
			},
			Select: []string{"id"},
		})
		if findErr != nil {
			return findErr
		}
		if duplicate != nil {
			return betterauth.ErrConflict
		}
		row, err = tx.Create(context.Context, betterauth.CreateQuery{
			Model: ModelPasskey,
			Data: betterauth.Record{
				"id": id, "name": name, "userId": userID,
				"credentialID": encodeCredentialID(credential.ID),
				"publicKey":    base64.RawURLEncoding.EncodeToString(credential.PublicKey),
				"counter":      float64(credential.Authenticator.SignCount),
				"deviceType":   deviceType(credential),
				"backedUp":     credential.Flags.BackupState,
				"transports":   credentialTransports(credential),
				"createdAt":    now, "updatedAt": now,
				"aaguid":         credentialAAGUID(credential),
				"userHandle":     handle,
				"credentialData": data,
			},
			ForceAllowID: true,
		})
		return err
	})
	if err != nil {
		return Passkey{}, err
	}
	return passkeyFromRecord(row)
}

func (instance *runtime) findUserPasskeys(
	context *betterauth.HookContext,
	userID string,
) ([]Passkey, error) {
	rows, err := context.Database.FindMany(context.Context, betterauth.FindManyQuery{
		Model: ModelPasskey, Where: []betterauth.Where{betterauth.Eq("userId", userID)},
		Limit: instance.config.MaxCredentials + 1,
		Sort:  &betterauth.Sort{Field: "createdAt", Direction: "asc"},
	})
	if err != nil {
		return nil, err
	}
	result := make([]Passkey, len(rows))
	for index := range rows {
		result[index], err = passkeyFromRecord(rows[index])
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}

func (instance *runtime) findDiscoverableUser(
	context *betterauth.HookContext,
	rawID []byte,
	userHandle []byte,
) (webAuthnUser, error) {
	row, err := context.Database.FindOne(context.Context, betterauth.FindOneQuery{
		Model: ModelPasskey,
		Where: []betterauth.Where{
			betterauth.Eq("credentialID", encodeCredentialID(rawID)),
			betterauth.Eq("userHandle", base64.RawURLEncoding.EncodeToString(userHandle)),
		},
	})
	if err != nil || row == nil {
		if err == nil {
			err = betterauth.ErrNotFound
		}
		return webAuthnUser{}, err
	}
	passkey, err := passkeyFromRecord(row)
	if err != nil {
		return webAuthnUser{}, err
	}
	all, err := instance.findUserPasskeys(context, passkey.UserID)
	if err != nil {
		return webAuthnUser{}, err
	}
	return makeWebAuthnUser(
		passkey.UserID, userHandle, passkey.UserID, passkey.UserID, all,
	), nil
}

func (instance *runtime) persistAuthentication(
	context *betterauth.HookContext,
	userID string,
	expectedCounter uint32,
	credential *webauthn.Credential,
) error {
	if credential == nil || userID == "" {
		return betterauth.ErrNotFound
	}
	if credential.Authenticator.CloneWarning {
		return betterauth.ErrReplay
	}
	credentialData, err := credentialRecord(credential)
	if err != nil {
		return err
	}
	id := encodeCredentialID(credential.ID)
	row, err := context.Database.Update(context.Context, betterauth.UpdateQuery{
		Model: ModelPasskey,
		Where: []betterauth.Where{
			betterauth.Eq("credentialID", id), betterauth.Eq("userId", userID),
			betterauth.Eq("counter", float64(expectedCounter)),
		},
		Update: betterauth.Record{
			"counter":        float64(credential.Authenticator.SignCount),
			"backedUp":       credential.Flags.BackupState,
			"credentialData": credentialData,
			"updatedAt":      context.Clock.Now().UTC(),
		},
	})
	if err != nil {
		return err
	}
	if row == nil {
		return betterauth.ErrReplay
	}
	return nil
}

func passkeyFromRecord(row betterauth.Record) (Passkey, error) {
	if row == nil {
		return Passkey{}, betterauth.ErrNotFound
	}
	var result Passkey
	var err error
	if result.ID, err = recordString(row, "id", true); err != nil {
		return Passkey{}, err
	}
	result.Name, _ = recordString(row, "name", false)
	if result.PublicKey, err = recordString(row, "publicKey", true); err != nil {
		return Passkey{}, err
	}
	if result.UserID, err = recordString(row, "userId", true); err != nil {
		return Passkey{}, err
	}
	if result.CredentialID, err = recordString(row, "credentialID", true); err != nil {
		return Passkey{}, err
	}
	if result.Counter, err = recordUint32(row["counter"]); err != nil {
		return Passkey{}, err
	}
	if result.DeviceType, err = recordString(row, "deviceType", true); err != nil {
		return Passkey{}, err
	}
	result.BackedUp, _ = row["backedUp"].(bool)
	result.Transports, _ = recordString(row, "transports", false)
	result.AAGUID, _ = recordString(row, "aaguid", false)
	if result.CreatedAt, err = recordTime(row["createdAt"]); err != nil {
		return Passkey{}, err
	}
	if result.UpdatedAt, err = recordTime(row["updatedAt"]); err != nil {
		return Passkey{}, err
	}
	handle, err := recordString(row, "userHandle", true)
	if err != nil {
		return Passkey{}, err
	}
	if result.userHandle, err = base64.RawURLEncoding.DecodeString(handle); err != nil {
		return Passkey{}, fmt.Errorf("passkey: invalid user handle: %w", err)
	}
	raw, err := json.Marshal(row["credentialData"])
	if err != nil {
		return Passkey{}, err
	}
	if err := json.Unmarshal(raw, &result.credential); err != nil {
		return Passkey{}, fmt.Errorf("passkey: invalid credential record: %w", err)
	}
	if encodeCredentialID(result.credential.ID) != result.CredentialID ||
		base64.RawURLEncoding.EncodeToString(result.credential.PublicKey) != result.PublicKey ||
		result.credential.Authenticator.SignCount != result.Counter ||
		result.credential.Flags.BackupEligible != (result.DeviceType == "multiDevice") ||
		result.credential.Flags.BackupState != result.BackedUp {
		return Passkey{}, errors.New("passkey: inconsistent credential record")
	}
	return result, nil
}

func recordString(row betterauth.Record, field string, required bool) (string, error) {
	value, ok := row[field]
	if !ok || value == nil {
		if required {
			return "", fmt.Errorf("passkey: missing %s", field)
		}
		return "", nil
	}
	text, ok := value.(string)
	if !ok || required && text == "" {
		return "", fmt.Errorf("passkey: invalid %s", field)
	}
	return text, nil
}

func recordUint32(value any) (uint32, error) {
	var parsed uint64
	var err error
	switch typed := value.(type) {
	case float64:
		if typed < 0 || typed != float64(uint64(typed)) {
			return 0, errors.New("passkey: invalid counter")
		}
		parsed = uint64(typed)
	case int:
		if typed < 0 {
			return 0, errors.New("passkey: invalid counter")
		}
		parsed = uint64(typed)
	case int64:
		if typed < 0 {
			return 0, errors.New("passkey: invalid counter")
		}
		parsed = uint64(typed)
	case json.Number:
		parsed, err = strconv.ParseUint(string(typed), 10, 32)
	case string:
		parsed, err = strconv.ParseUint(typed, 10, 32)
	default:
		return 0, errors.New("passkey: invalid counter")
	}
	if err != nil || parsed > uint64(^uint32(0)) {
		return 0, errors.New("passkey: invalid counter")
	}
	return uint32(parsed), nil
}

func recordTime(value any) (time.Time, error) {
	switch typed := value.(type) {
	case time.Time:
		return typed.UTC(), nil
	case string:
		parsed, err := time.Parse(time.RFC3339Nano, typed)
		return parsed.UTC(), err
	default:
		return time.Time{}, errors.New("passkey: invalid timestamp")
	}
}

func normalizeJSON(value any) (any, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var normalized any
	if err := json.Unmarshal(raw, &normalized); err != nil {
		return nil, err
	}
	return normalized, nil
}
