package twofactor

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"

	betterauth "github.com/eadwinCode/better-auth-go"
)

const (
	auditEnabled              = "two_factor.enabled"
	auditDisabled             = "two_factor.disabled"
	auditBackupCodesGenerated = "two_factor.backup_codes.generated"
	auditBackupCodeUsed       = "two_factor.backup_code.used"
	auditAccountLocked        = "two_factor.account.locked"
	auditSignInVerified       = "two_factor.sign_in.verified"
	auditTrustedDeviceCreated = "two_factor.trusted_device.created"
)

func (instance *runtime) plugin() betterauth.Plugin {
	sensitive := []betterauth.RequestHook{
		betterauth.FreshSessionMiddleware, betterauth.CSRFMiddleware,
	}
	verifyUse := []betterauth.RequestHook{conditionalCSRF}
	password := betterauth.FieldValidation{
		Kind: betterauth.ValidationString, MaxLength: 1 << 20,
	}
	code := betterauth.FieldValidation{
		Kind: betterauth.ValidationString, Required: true, MinLength: 1, MaxLength: 64,
	}
	trust := betterauth.FieldValidation{Kind: betterauth.ValidationBoolean}
	return betterauth.Plugin{
		ID:     "two-factor",
		Schema: instance.schema,
		Endpoints: []betterauth.PluginEndpoint{
			{
				Name: "enableTwoFactor", Path: "/two-factor/enable", Method: http.MethodPost,
				Use: sensitive,
				BodyValidator: betterauth.ObjectValidator{
					Fields: map[string]betterauth.FieldValidation{
						"password": password,
						"issuer": {
							Kind: betterauth.ValidationString, MaxLength: 128,
						},
					},
				},
				Handler: instance.enable,
			},
			{
				Name: "disableTwoFactor", Path: "/two-factor/disable", Method: http.MethodPost,
				Use: sensitive,
				BodyValidator: betterauth.ObjectValidator{
					Fields: map[string]betterauth.FieldValidation{"password": password},
				},
				Handler: instance.disable,
			},
			{
				Name: "getTOTPURI", Path: "/two-factor/get-totp-uri", Method: http.MethodPost,
				Use: sensitive,
				BodyValidator: betterauth.ObjectValidator{
					Fields: map[string]betterauth.FieldValidation{"password": password},
				},
				Handler: instance.getTOTPURI,
			},
			{
				Name: "verifyTOTP", Path: "/two-factor/verify-totp", Method: http.MethodPost,
				Use: verifyUse,
				BodyValidator: betterauth.ObjectValidator{
					Fields: map[string]betterauth.FieldValidation{
						"code": code, "trustDevice": trust,
					},
				},
				Handler: instance.verifyTOTP,
			},
			{
				Name: "sendTwoFactorOTP", Path: "/two-factor/send-otp", Method: http.MethodPost,
				Use: verifyUse,
				BodyValidator: betterauth.ObjectValidator{
					Fields: map[string]betterauth.FieldValidation{"trustDevice": trust},
				},
				Handler: instance.sendOTP,
			},
			{
				Name: "verifyTwoFactorOTP", Path: "/two-factor/verify-otp", Method: http.MethodPost,
				Use: verifyUse,
				BodyValidator: betterauth.ObjectValidator{
					Fields: map[string]betterauth.FieldValidation{
						"code": code, "trustDevice": trust,
					},
				},
				Handler: instance.verifyOTP,
			},
			{
				Name: "generateBackupCodes",
				Path: "/two-factor/generate-backup-codes", Method: http.MethodPost,
				Use: sensitive,
				BodyValidator: betterauth.ObjectValidator{
					Fields: map[string]betterauth.FieldValidation{"password": password},
				},
				Handler: instance.regenerateBackupCodes,
			},
			{
				Name: "verifyBackupCode",
				Path: "/two-factor/verify-backup-code", Method: http.MethodPost,
				Use: verifyUse,
				BodyValidator: betterauth.ObjectValidator{
					Fields: map[string]betterauth.FieldValidation{
						"code": code, "trustDevice": trust,
						"disableSession": {Kind: betterauth.ValidationBoolean},
					},
				},
				Handler: instance.verifyBackupCode,
			},
		},
		After: []betterauth.PluginAfterHook{
			{
				Matcher: func(context *betterauth.HookContext) bool {
					return context.Path == "/sign-in/email"
				},
				Handler: instance.interceptCredentialSignIn,
			},
			{
				Matcher: func(context *betterauth.HookContext) bool {
					switch context.Path {
					case "/sign-up/email", "/sign-in/email", "/get-session",
						"/refresh-session", "/two-factor/verify-totp",
						"/two-factor/verify-otp", "/two-factor/verify-backup-code":
						return true
					default:
						return false
					}
				},
				Handler: instance.enrichUserResponse,
			},
		},
		RateLimits: []betterauth.PluginRateLimitRule{{
			Matcher: func(context *betterauth.HookContext) bool {
				return strings.HasPrefix(context.Path, "/two-factor/")
			},
			Action: "two-factor.verify", Window: 10 * time.Minute, Max: 30,
			AccountKey: func(context *betterauth.HookContext) string {
				if context.User != nil {
					return context.User.ID
				}
				return ""
			},
		}},
	}
}

func conditionalCSRF(context *betterauth.HookContext) (*betterauth.PluginResponse, error) {
	if context.Session == nil {
		return nil, nil
	}
	return betterauth.CSRFMiddleware(context)
}

func (instance *runtime) enable(
	context *betterauth.HookContext,
) (*betterauth.PluginResponse, error) {
	if err := instance.requirePassword(
		context, context.User.ID, stringBody(context, "password"),
	); err != nil {
		return nil, err
	}
	raw, err := context.GenerateToken(20)
	if err != nil {
		return nil, internalError(err)
	}
	secret := generateTOTPSecret(raw)
	sealedSecret, err := instance.config.Cipher.Seal(context.Context, secret)
	if err != nil {
		return nil, internalError(err)
	}
	codes, sealedCodes, err := instance.generateBackupCodes(context)
	if err != nil {
		return nil, internalError(err)
	}
	id, err := context.GenerateID()
	if err != nil {
		return nil, internalError(err)
	}
	now := context.Clock.Now().UTC()
	verified := instance.config.SkipVerificationOnEnable
	err = context.Database.Transaction(context.Context, func(tx betterauth.DatabaseAdapter) error {
		if _, deleteErr := tx.DeleteMany(context.Context, betterauth.DeleteQuery{
			Model: ModelTwoFactor,
			Where: []betterauth.Where{betterauth.Eq("userId", context.User.ID)},
		}); deleteErr != nil {
			return deleteErr
		}
		if _, createErr := tx.Create(context.Context, betterauth.CreateQuery{
			Model: ModelTwoFactor,
			Data: betterauth.Record{
				"id": id, "userId": context.User.ID, "secret": sealedSecret,
				"backupCodes": sealedCodes, "verified": verified,
				"failedVerificationCount": float64(0), "lockedUntil": nil,
				"createdAt": now, "updatedAt": now,
			},
			ForceAllowID: true,
		}); createErr != nil {
			return createErr
		}
		if verified {
			updated, updateErr := tx.Update(context.Context, betterauth.UpdateQuery{
				Model: betterauth.ModelUser,
				Where: []betterauth.Where{betterauth.Eq("id", context.User.ID)},
				Update: betterauth.Record{
					"twoFactorEnabled": true, "updatedAt": now,
				},
			})
			if updateErr != nil || updated == nil {
				if updateErr == nil {
					updateErr = betterauth.ErrNotFound
				}
				return updateErr
			}
			if auditErr := instance.audit(
				context, tx, auditEnabled, context.User.ID,
				map[string]any{"factor": "totp", "verificationSkipped": true},
			); auditErr != nil {
				return auditErr
			}
		}
		return instance.audit(
			context, tx, auditBackupCodesGenerated, context.User.ID,
			map[string]any{"reason": "enrollment"},
		)
	})
	if err != nil {
		return nil, internalError(err)
	}
	issuer := stringBody(context, "issuer")
	if issuer == "" {
		issuer = instance.config.Issuer
	}
	response, err := betterauth.JSONResponse(http.StatusOK, map[string]any{
		"totpURI": totpURI(
			issuer, context.User.Email, secret,
			instance.config.TOTPPeriod, instance.config.TOTPDigits,
		),
		"backupCodes": codes,
	})
	if err != nil {
		return nil, err
	}
	if err := instance.rotateAuthenticatedSession(context, response); err != nil {
		return nil, err
	}
	return response, nil
}

func (instance *runtime) disable(
	context *betterauth.HookContext,
) (*betterauth.PluginResponse, error) {
	if err := instance.requirePassword(
		context, context.User.ID, stringBody(context, "password"),
	); err != nil {
		return nil, err
	}
	now := context.Clock.Now().UTC()
	err := context.Database.Transaction(context.Context, func(tx betterauth.DatabaseAdapter) error {
		updated, updateErr := tx.Update(context.Context, betterauth.UpdateQuery{
			Model: betterauth.ModelUser,
			Where: []betterauth.Where{betterauth.Eq("id", context.User.ID)},
			Update: betterauth.Record{
				"twoFactorEnabled": false, "updatedAt": now,
			},
		})
		if updateErr != nil || updated == nil {
			if updateErr == nil {
				updateErr = betterauth.ErrNotFound
			}
			return updateErr
		}
		if _, deleteErr := tx.DeleteMany(context.Context, betterauth.DeleteQuery{
			Model: ModelTwoFactor,
			Where: []betterauth.Where{betterauth.Eq("userId", context.User.ID)},
		}); deleteErr != nil {
			return deleteErr
		}
		return instance.audit(
			context, tx, auditDisabled, context.User.ID, map[string]any{},
		)
	})
	if err != nil {
		return nil, internalError(err)
	}
	response, err := betterauth.JSONResponse(
		http.StatusOK, map[string]bool{"status": true},
	)
	if err != nil {
		return nil, err
	}
	if raw, cookieErr := cookieValue(
		context.Request, instance.config.TrustedDeviceCookie,
	); cookieErr == nil {
		_, _ = context.Database.ConsumeOne(context.Context, betterauth.DeleteQuery{
			Model: betterauth.ModelVerification,
			Where: []betterauth.Where{
				betterauth.Eq("identifier", verificationTrusted),
				betterauth.Eq("value", verificationValue("trusted", raw)),
			},
		})
	}
	_ = instance.clearPluginCookie(
		context, response, instance.config.TrustedDeviceCookie,
	)
	if err := instance.rotateAuthenticatedSession(context, response); err != nil {
		return nil, err
	}
	return response, nil
}

func (instance *runtime) getTOTPURI(
	context *betterauth.HookContext,
) (*betterauth.PluginResponse, error) {
	if instance.config.DisableTOTP {
		return nil, betterauth.NewError(
			betterauth.CodeBadRequest, "TOTP is not enabled.", http.StatusBadRequest, nil,
		)
	}
	if err := instance.requirePassword(
		context, context.User.ID, stringBody(context, "password"),
	); err != nil {
		return nil, err
	}
	record, err := instance.findTwoFactor(context, context.User.ID)
	if err != nil {
		return nil, invalidFactor(err)
	}
	secret, err := instance.config.Cipher.Open(context.Context, record.Secret)
	if err != nil {
		return nil, internalError(err)
	}
	return betterauth.JSONResponse(http.StatusOK, map[string]string{
		"totpURI": totpURI(
			instance.config.Issuer, context.User.Email, secret,
			instance.config.TOTPPeriod, instance.config.TOTPDigits,
		),
	})
}

type verificationState struct {
	UserID        string
	Key           string
	Pending       bool
	Attempt       verificationMetadata
	AttemptExpiry time.Time
}

func (instance *runtime) verificationState(
	context *betterauth.HookContext,
	spendAttempt bool,
) (verificationState, error) {
	if context.Session != nil && context.User != nil {
		return verificationState{
			UserID: context.User.ID,
			Key:    context.User.ID + "!" + context.Session.ID,
		}, nil
	}
	handle, err := cookieValue(context.Request, instance.config.PendingCookie)
	if err != nil {
		return verificationState{}, invalidChallenge(err)
	}
	row, err := findVerification(
		context, verificationPending, verificationValue("pending", handle),
	)
	if err != nil {
		return verificationState{}, invalidChallenge(err)
	}
	metadata, err := parseMetadata(row)
	if err != nil || metadata.UserID == "" {
		return verificationState{}, invalidChallenge(err)
	}
	state := verificationState{
		UserID: metadata.UserID, Key: handle, Pending: true,
	}
	if spendAttempt {
		state.Attempt, state.AttemptExpiry, err = instance.beginAttempt(context, handle)
		if err != nil {
			return verificationState{}, tooManyAttempts(err)
		}
	}
	return state, nil
}

func (instance *runtime) verifyTOTP(
	context *betterauth.HookContext,
) (*betterauth.PluginResponse, error) {
	if instance.config.DisableTOTP {
		return nil, invalidFactor(errors.New("twofactor: TOTP is disabled"))
	}
	state, err := instance.verificationState(context, true)
	if err != nil {
		return nil, err
	}
	record, err := instance.findTwoFactor(context, state.UserID)
	if err != nil || state.Pending && !record.Verified {
		instance.restoreAttempt(context, state)
		return nil, invalidFactor(err)
	}
	if err := instance.assertNotLocked(context, record, state.Pending); err != nil {
		instance.restoreAttempt(context, state)
		return nil, err
	}
	secret, err := instance.config.Cipher.Open(context.Context, record.Secret)
	if err != nil {
		instance.restoreAttempt(context, state)
		return nil, internalError(err)
	}
	if !verifyTOTP(
		secret, stringBody(context, "code"), context.Clock.Now().UTC(),
		instance.config.TOTPPeriod, instance.config.TOTPDigits,
	) {
		return nil, instance.failedFactor(context, state, record)
	}
	if !state.Pending && !record.Verified {
		if err := instance.completeEnrollment(context, record); err != nil {
			return nil, err
		}
	}
	return instance.completeVerification(
		context, state, record, "totp", boolBody(context, "trustDevice"), false,
	)
}

func (instance *runtime) sendOTP(
	context *betterauth.HookContext,
) (*betterauth.PluginResponse, error) {
	if instance.config.DeliverOTP == nil {
		return nil, betterauth.NewError(
			betterauth.CodeBadRequest, "OTP is not enabled.", http.StatusBadRequest, nil,
		)
	}
	state, err := instance.verificationState(context, false)
	if err != nil {
		return nil, err
	}
	record, err := instance.findTwoFactor(context, state.UserID)
	if err != nil || state.Pending && !record.Verified {
		return nil, invalidFactor(err)
	}
	if err := instance.assertNotLocked(context, record, state.Pending); err != nil {
		return nil, err
	}
	user, err := findPublicUser(context, state.UserID)
	if err != nil {
		return nil, internalError(err)
	}
	code, err := numericCode(context)
	if err != nil {
		return nil, internalError(err)
	}
	value := verificationValue("otp", state.Key)
	_, _ = context.Database.DeleteMany(context.Context, betterauth.DeleteQuery{
		Model: betterauth.ModelVerification,
		Where: []betterauth.Where{
			betterauth.Eq("identifier", verificationOTP),
			betterauth.Eq("value", value),
		},
	})
	expires := context.Clock.Now().UTC().Add(instance.config.OTPTTL)
	if err := instance.createVerification(
		context, context.Database, verificationOTP, value, expires,
		verificationMetadata{UserID: state.UserID, CodeHash: betterauth.HashToken(code)},
	); err != nil {
		return nil, internalError(err)
	}
	if err := instance.config.DeliverOTP(context, user, code); err != nil {
		_, _ = context.Database.DeleteMany(context.Context, betterauth.DeleteQuery{
			Model: betterauth.ModelVerification,
			Where: []betterauth.Where{
				betterauth.Eq("identifier", verificationOTP),
				betterauth.Eq("value", value),
			},
		})
		return nil, internalError(err)
	}
	return betterauth.JSONResponse(http.StatusOK, map[string]bool{"status": true})
}

func (instance *runtime) verifyOTP(
	context *betterauth.HookContext,
) (*betterauth.PluginResponse, error) {
	if instance.config.DeliverOTP == nil {
		return nil, invalidFactor(errors.New("twofactor: OTP is disabled"))
	}
	state, err := instance.verificationState(context, true)
	if err != nil {
		return nil, err
	}
	record, err := instance.findTwoFactor(context, state.UserID)
	if err != nil || state.Pending && !record.Verified {
		instance.restoreAttempt(context, state)
		return nil, invalidFactor(err)
	}
	if err := instance.assertNotLocked(context, record, state.Pending); err != nil {
		instance.restoreAttempt(context, state)
		return nil, err
	}
	value := verificationValue("otp", state.Key)
	otpRow, err := consumeVerification(context, verificationOTP, value)
	if err != nil {
		instance.restoreAttempt(context, state)
		return nil, invalidFactor(err)
	}
	metadata, err := parseMetadata(otpRow)
	if err != nil || metadata.UserID != state.UserID {
		instance.restoreAttempt(context, state)
		return nil, invalidFactor(err)
	}
	valid := subtle.ConstantTimeCompare(
		[]byte(metadata.CodeHash),
		[]byte(betterauth.HashToken(stringBody(context, "code"))),
	) == 1
	if !valid {
		expires, timeErr := timeValue(otpRow["expiresAt"])
		if timeErr == nil {
			_ = instance.createVerification(
				context, context.Database, verificationOTP, value, expires, metadata,
			)
		}
		return nil, instance.failedFactor(context, state, record)
	}
	return instance.completeVerification(
		context, state, record, "otp", boolBody(context, "trustDevice"), false,
	)
}

func (instance *runtime) regenerateBackupCodes(
	context *betterauth.HookContext,
) (*betterauth.PluginResponse, error) {
	if err := instance.requirePassword(
		context, context.User.ID, stringBody(context, "password"),
	); err != nil {
		return nil, err
	}
	record, err := instance.findTwoFactor(context, context.User.ID)
	if err != nil || !record.Verified {
		return nil, invalidFactor(err)
	}
	codes, sealed, err := instance.generateBackupCodes(context)
	if err != nil {
		return nil, internalError(err)
	}
	err = context.Database.Transaction(context.Context, func(tx betterauth.DatabaseAdapter) error {
		updated, updateErr := tx.Update(context.Context, betterauth.UpdateQuery{
			Model: ModelTwoFactor,
			Where: []betterauth.Where{
				betterauth.Eq("id", record.ID),
				betterauth.Eq("backupCodes", record.BackupCodes),
			},
			Update: betterauth.Record{
				"backupCodes": sealed, "updatedAt": context.Clock.Now().UTC(),
			},
		})
		if updateErr != nil || updated == nil {
			if updateErr == nil {
				updateErr = betterauth.ErrConflict
			}
			return updateErr
		}
		return instance.audit(
			context, tx, auditBackupCodesGenerated, context.User.ID,
			map[string]any{"reason": "regeneration"},
		)
	})
	if err != nil {
		return nil, conflictError("Backup codes changed concurrently.", err)
	}
	response, err := betterauth.JSONResponse(http.StatusOK, map[string]any{
		"status": true, "backupCodes": codes,
	})
	if err != nil {
		return nil, err
	}
	if err := instance.rotateAuthenticatedSession(context, response); err != nil {
		return nil, err
	}
	return response, nil
}

func (instance *runtime) verifyBackupCode(
	context *betterauth.HookContext,
) (*betterauth.PluginResponse, error) {
	state, err := instance.verificationState(context, true)
	if err != nil {
		return nil, err
	}
	record, err := instance.findTwoFactor(context, state.UserID)
	if err != nil || state.Pending && !record.Verified {
		instance.restoreAttempt(context, state)
		return nil, invalidFactor(err)
	}
	if err := instance.assertNotLocked(context, record, state.Pending); err != nil {
		instance.restoreAttempt(context, state)
		return nil, err
	}
	codes, err := instance.openBackupCodes(context.Context, record.BackupCodes)
	if err != nil {
		instance.restoreAttempt(context, state)
		return nil, internalError(err)
	}
	index := backupCodeIndex(codes, stringBody(context, "code"))
	if index < 0 {
		return nil, instance.failedFactor(context, state, record)
	}
	remaining := append([]string(nil), codes[:index]...)
	remaining = append(remaining, codes[index+1:]...)
	plaintext, err := json.Marshal(remaining)
	if err != nil {
		instance.restoreAttempt(context, state)
		return nil, internalError(err)
	}
	sealed, err := instance.config.Cipher.Seal(context.Context, string(plaintext))
	if err != nil {
		instance.restoreAttempt(context, state)
		return nil, internalError(err)
	}
	updated, err := context.Database.Update(context.Context, betterauth.UpdateQuery{
		Model: ModelTwoFactor,
		Where: []betterauth.Where{
			betterauth.Eq("id", record.ID),
			betterauth.Eq("backupCodes", record.BackupCodes),
		},
		Update: betterauth.Record{
			"backupCodes": sealed, "updatedAt": context.Clock.Now().UTC(),
		},
	})
	if err != nil || updated == nil {
		instance.restoreAttempt(context, state)
		return nil, conflictError("Backup code was already used.", err)
	}
	if err := instance.audit(
		context, context.Database, auditBackupCodeUsed, state.UserID, map[string]any{},
	); err != nil {
		return nil, internalError(err)
	}
	return instance.completeVerification(
		context, state, record, "backup_code", boolBody(context, "trustDevice"),
		boolBody(context, "disableSession"),
	)
}

func (instance *runtime) completeEnrollment(
	context *betterauth.HookContext,
	record twoFactorRecord,
) error {
	now := context.Clock.Now().UTC()
	err := context.Database.Transaction(context.Context, func(tx betterauth.DatabaseAdapter) error {
		updated, updateErr := tx.Update(context.Context, betterauth.UpdateQuery{
			Model: ModelTwoFactor,
			Where: []betterauth.Where{
				betterauth.Eq("id", record.ID), betterauth.Eq("verified", false),
			},
			Update: betterauth.Record{"verified": true, "updatedAt": now},
		})
		if updateErr != nil || updated == nil {
			if updateErr == nil {
				updateErr = betterauth.ErrConflict
			}
			return updateErr
		}
		user, updateErr := tx.Update(context.Context, betterauth.UpdateQuery{
			Model: betterauth.ModelUser,
			Where: []betterauth.Where{betterauth.Eq("id", record.UserID)},
			Update: betterauth.Record{
				"twoFactorEnabled": true, "updatedAt": now,
			},
		})
		if updateErr != nil || user == nil {
			if updateErr == nil {
				updateErr = betterauth.ErrNotFound
			}
			return updateErr
		}
		return instance.audit(
			context, tx, auditEnabled, record.UserID, map[string]any{"factor": "totp"},
		)
	})
	if err != nil {
		return internalError(err)
	}
	return nil
}

func (instance *runtime) completeVerification(
	context *betterauth.HookContext,
	state verificationState,
	record twoFactorRecord,
	factor string,
	trustDevice bool,
	disableSession bool,
) (*betterauth.PluginResponse, error) {
	if state.Pending {
		consumed, err := consumeVerification(
			context, verificationPending, verificationValue("pending", state.Key),
		)
		if err != nil {
			return nil, invalidChallenge(err)
		}
		metadata, err := parseMetadata(consumed)
		if err != nil || metadata.UserID != state.UserID {
			return nil, invalidChallenge(err)
		}
	}
	if err := instance.resetFailures(context, record); err != nil {
		return nil, internalError(err)
	}
	if state.Pending && disableSession {
		user, err := findPublicUser(context, state.UserID)
		if err != nil {
			return nil, internalError(err)
		}
		response, err := betterauth.JSONResponse(http.StatusOK, map[string]any{
			"token": nil, "user": user,
		})
		if err == nil {
			_ = instance.clearPluginCookie(
				context, response, instance.config.PendingCookie,
			)
		}
		return response, err
	}
	if !state.Pending {
		response, err := betterauth.JSONResponse(http.StatusOK, map[string]any{
			"token": nil, "user": context.User,
		})
		if err != nil {
			return nil, err
		}
		if !record.Verified {
			if err := instance.rotateAuthenticatedSession(context, response); err != nil {
				return nil, err
			}
		}
		return response, nil
	}
	if context.IssueSession == nil {
		return nil, internalError(errors.New("twofactor: session issuance is unavailable"))
	}
	issued, err := context.IssueSession(state.UserID)
	if err != nil {
		return nil, internalError(err)
	}
	response, err := betterauth.JSONResponse(http.StatusOK, map[string]any{
		"session": issued.Session, "user": issued.User,
	})
	if err != nil {
		return nil, err
	}
	if trustDevice {
		if err := instance.createTrustedDevice(context, response, state.UserID); err != nil {
			return nil, internalError(err)
		}
	}
	if err := instance.audit(
		context, context.Database, auditSignInVerified, state.UserID,
		formatFactor(factor),
	); err != nil {
		return nil, internalError(err)
	}
	if err := issued.Apply(response); err != nil {
		return nil, internalError(err)
	}
	_ = instance.clearPluginCookie(context, response, instance.config.PendingCookie)
	return response, nil
}

func (instance *runtime) rotateAuthenticatedSession(
	context *betterauth.HookContext,
	response *betterauth.PluginResponse,
) error {
	if context.IssueSession == nil {
		return internalError(errors.New("twofactor: session issuance is unavailable"))
	}
	issued, err := context.IssueSession(context.User.ID)
	if err != nil {
		return internalError(err)
	}
	if err := issued.Apply(response); err != nil {
		return internalError(err)
	}
	return nil
}

func (instance *runtime) restoreAttempt(
	context *betterauth.HookContext,
	state verificationState,
) {
	if state.Pending && !state.AttemptExpiry.IsZero() {
		instance.rearmAttempt(context, state.Key, state.Attempt, state.AttemptExpiry)
	}
}

func (instance *runtime) failedFactor(
	context *betterauth.HookContext,
	state verificationState,
	record twoFactorRecord,
) error {
	if state.Pending {
		state.Attempt.Attempts++
		if state.Attempt.Attempts < instance.config.ChallengeMaxAttempts {
			instance.rearmAttempt(
				context, state.Key, state.Attempt, state.AttemptExpiry,
			)
		} else {
			_, _ = context.Database.ConsumeOne(
				context.Context,
				betterauth.DeleteQuery{
					Model: betterauth.ModelVerification,
					Where: []betterauth.Where{
						betterauth.Eq("identifier", verificationPending),
						betterauth.Eq(
							"value", verificationValue("pending", state.Key),
						),
					},
				},
			)
		}
		if err := instance.recordFailure(context, record); err != nil {
			return internalError(err)
		}
	}
	return invalidFactor(nil)
}

func (instance *runtime) assertNotLocked(
	context *betterauth.HookContext,
	record twoFactorRecord,
	pending bool,
) error {
	if !pending || record.LockedUntil == nil {
		return nil
	}
	now := context.Clock.Now().UTC()
	if record.LockedUntil.After(now) {
		return tooManyAttempts(nil)
	}
	_, err := context.Database.Update(context.Context, betterauth.UpdateQuery{
		Model: ModelTwoFactor,
		Where: []betterauth.Where{
			betterauth.Eq("id", record.ID),
			{Field: "lockedUntil", Operator: betterauth.WhereLTE, Value: now},
		},
		Update: betterauth.Record{
			"failedVerificationCount": float64(0), "lockedUntil": nil,
			"updatedAt": now,
		},
	})
	return err
}

func (instance *runtime) recordFailure(
	context *betterauth.HookContext,
	record twoFactorRecord,
) error {
	updated, err := context.Database.IncrementOne(context.Context, betterauth.IncrementQuery{
		Model:     ModelTwoFactor,
		Where:     []betterauth.Where{betterauth.Eq("id", record.ID)},
		Increment: map[string]float64{"failedVerificationCount": 1},
		Set:       betterauth.Record{"updatedAt": context.Clock.Now().UTC()},
	})
	if err != nil || updated == nil {
		if err == nil {
			err = betterauth.ErrNotFound
		}
		return err
	}
	count, err := integerValue(updated["failedVerificationCount"])
	if err != nil || count < instance.config.AccountMaxFailedAttempts {
		return err
	}
	lockedUntil := context.Clock.Now().UTC().Add(instance.config.AccountLockoutDuration)
	_, err = context.Database.Update(context.Context, betterauth.UpdateQuery{
		Model: ModelTwoFactor,
		Where: []betterauth.Where{betterauth.Eq("id", record.ID)},
		Update: betterauth.Record{
			"lockedUntil": lockedUntil, "updatedAt": context.Clock.Now().UTC(),
		},
	})
	if err != nil {
		return err
	}
	return instance.audit(
		context, context.Database, auditAccountLocked, record.UserID,
		map[string]any{"until": lockedUntil.Format(time.RFC3339)},
	)
}

func (instance *runtime) resetFailures(
	context *betterauth.HookContext,
	record twoFactorRecord,
) error {
	_, err := context.Database.Update(context.Context, betterauth.UpdateQuery{
		Model: ModelTwoFactor,
		Where: []betterauth.Where{betterauth.Eq("id", record.ID)},
		Update: betterauth.Record{
			"failedVerificationCount": float64(0), "lockedUntil": nil,
			"updatedAt": context.Clock.Now().UTC(),
		},
	})
	return err
}

func (instance *runtime) createTrustedDevice(
	context *betterauth.HookContext,
	response *betterauth.PluginResponse,
	userID string,
) error {
	raw, err := context.GenerateToken(32)
	if err != nil {
		return err
	}
	expires := context.Clock.Now().UTC().Add(instance.config.TrustedDeviceTTL)
	if err := instance.createVerification(
		context, context.Database, verificationTrusted,
		verificationValue("trusted", raw), expires,
		verificationMetadata{UserID: userID},
	); err != nil {
		return err
	}
	if err := instance.audit(
		context, context.Database, auditTrustedDeviceCreated, userID, map[string]any{},
	); err != nil {
		return err
	}
	return instance.setPluginCookie(
		context, response, instance.config.TrustedDeviceCookie, raw, expires,
	)
}

func (instance *runtime) acceptTrustedDevice(
	context *betterauth.HookContext,
	response *betterauth.PluginResponse,
	userID string,
) bool {
	raw, err := cookieValue(context.Request, instance.config.TrustedDeviceCookie)
	if err != nil {
		return false
	}
	row, err := consumeVerification(
		context, verificationTrusted, verificationValue("trusted", raw),
	)
	if err != nil {
		_ = instance.clearPluginCookie(
			context, response, instance.config.TrustedDeviceCookie,
		)
		return false
	}
	metadata, err := parseMetadata(row)
	if err != nil || metadata.UserID != userID {
		_ = instance.clearPluginCookie(
			context, response, instance.config.TrustedDeviceCookie,
		)
		return false
	}
	if err := instance.createTrustedDevice(context, response, userID); err != nil {
		return false
	}
	return true
}

func (instance *runtime) interceptCredentialSignIn(
	context *betterauth.HookContext,
	response *betterauth.PluginResponse,
) error {
	if response.Status != http.StatusOK {
		return nil
	}
	var signIn signInResponse
	if err := json.Unmarshal(response.Body, &signIn); err != nil || signIn.User.ID == "" {
		return nil
	}
	userRow, err := context.Database.FindOne(context.Context, betterauth.FindOneQuery{
		Model:  betterauth.ModelUser,
		Where:  []betterauth.Where{betterauth.Eq("id", signIn.User.ID)},
		Select: []string{"twoFactorEnabled"},
	})
	if err != nil {
		return err
	}
	enabled, _ := userRow["twoFactorEnabled"].(bool)
	if !enabled {
		return nil
	}
	record, err := instance.findTwoFactor(context, signIn.User.ID)
	if err != nil || !record.Verified {
		return errors.New("twofactor: enabled user has no verified configuration")
	}
	if instance.acceptTrustedDevice(context, response, signIn.User.ID) {
		return nil
	}
	methods := make([]string, 0, 2)
	if !instance.config.DisableTOTP {
		methods = append(methods, "totp")
	}
	if instance.config.DeliverOTP != nil {
		methods = append(methods, "otp")
	}
	if len(methods) == 0 {
		return errors.New("twofactor: enabled user has no verification method")
	}
	rawSession, err := removeResponseCookie(response, context.Cookies.Name)
	if err != nil {
		return fmt.Errorf("twofactor: provisional session cookie: %w", err)
	}
	handle, err := context.GenerateToken(32)
	if err != nil {
		return err
	}
	expires := context.Clock.Now().UTC().Add(instance.config.PendingTTL)
	err = context.Database.Transaction(context.Context, func(tx betterauth.DatabaseAdapter) error {
		if err := instance.createVerification(
			context, tx, verificationPending, verificationValue("pending", handle),
			expires, verificationMetadata{UserID: signIn.User.ID},
		); err != nil {
			return err
		}
		if err := instance.createVerification(
			context, tx, verificationAttempts, verificationValue("attempt", handle),
			expires, verificationMetadata{UserID: signIn.User.ID},
		); err != nil {
			return err
		}
		revoked, err := tx.Update(context.Context, betterauth.UpdateQuery{
			Model: betterauth.ModelSession,
			Where: []betterauth.Where{
				betterauth.Eq("tokenHash", betterauth.HashToken(rawSession)),
				betterauth.Eq("revokedAt", nil),
			},
			Update: betterauth.Record{
				"revokedAt": context.Clock.Now().UTC(),
				"updatedAt": context.Clock.Now().UTC(),
			},
		})
		if err != nil || revoked == nil {
			if err == nil {
				err = betterauth.ErrReplay
			}
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}
	if err := response.SetCookie(&http.Cookie{
		Name: context.Cookies.Name, Value: "", Path: "/", MaxAge: -1,
		Expires: time.Unix(1, 0), Secure: true, HttpOnly: true,
		SameSite: context.Cookies.SameSite,
	}); err != nil {
		return err
	}
	if err := instance.setPluginCookie(
		context, response, instance.config.PendingCookie, handle, expires,
	); err != nil {
		return err
	}
	return response.SetJSON(map[string]any{
		"twoFactorRedirect": true, "twoFactorMethods": methods,
	})
}

func (instance *runtime) enrichUserResponse(
	context *betterauth.HookContext,
	response *betterauth.PluginResponse,
) error {
	if response == nil || response.Status < 200 || response.Status >= 300 ||
		len(response.Body) == 0 || string(response.Body) == "null\n" {
		return nil
	}
	var body map[string]any
	if err := json.Unmarshal(response.Body, &body); err != nil {
		return nil
	}
	user, ok := body["user"].(map[string]any)
	if !ok {
		return nil
	}
	userID, _ := user["id"].(string)
	if userID == "" {
		return nil
	}
	row, err := context.Database.FindOne(context.Context, betterauth.FindOneQuery{
		Model:  betterauth.ModelUser,
		Where:  []betterauth.Where{betterauth.Eq("id", userID)},
		Select: []string{"twoFactorEnabled"},
	})
	if err != nil {
		return err
	}
	enabled, _ := row["twoFactorEnabled"].(bool)
	user["twoFactorEnabled"] = enabled
	body["user"] = user
	return response.SetJSON(body)
}

func numericCode(context *betterauth.HookContext) (string, error) {
	raw, err := context.GenerateToken(16)
	if err != nil {
		return "", err
	}
	value := new(big.Int).SetBytes([]byte(betterauth.HashToken(raw)))
	value.Mod(value, big.NewInt(1_000_000))
	return fmt.Sprintf("%06d", value.Int64()), nil
}

func findPublicUser(
	context *betterauth.HookContext,
	userID string,
) (betterauth.User, error) {
	row, err := context.Database.FindOne(context.Context, betterauth.FindOneQuery{
		Model: betterauth.ModelUser,
		Where: []betterauth.Where{betterauth.Eq("id", userID)},
	})
	if err != nil || row == nil {
		if err == nil {
			err = betterauth.ErrNotFound
		}
		return betterauth.User{}, err
	}
	created, err := timeValue(row["createdAt"])
	if err != nil {
		return betterauth.User{}, err
	}
	updated, err := timeValue(row["updatedAt"])
	if err != nil {
		return betterauth.User{}, err
	}
	return betterauth.User{
		ID: recordString(row["id"]), Email: recordString(row["email"]),
		Name: recordString(row["name"]), ImageURL: recordString(row["image"]),
		EmailVerified: row["emailVerified"] == true,
		CreatedAt:     created, UpdatedAt: updated,
	}, nil
}
