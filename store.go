package betterauth

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"time"
)

const credentialProvider = "credential"

type databaseStore struct {
	db DatabaseAdapter
}

func newDatabaseStore(db DatabaseAdapter) *databaseStore {
	return &databaseStore{db: db}
}

func (s *databaseStore) CreateEmailUser(ctx context.Context, params CreateEmailUserParams) (User, error) {
	var created User
	err := s.db.Transaction(ctx, func(tx DatabaseAdapter) error {
		userRow, err := tx.Create(ctx, CreateQuery{Model: ModelUser, Data: userRecord(params.User), ForceAllowID: true})
		if err != nil {
			return err
		}
		created, err = userFromRecord(userRow)
		if err != nil {
			return err
		}
		_, err = tx.Create(ctx, CreateQuery{Model: ModelAccount, ForceAllowID: true, Data: Record{
			"id": params.User.ID + ":credential", "userId": params.User.ID,
			"providerId": credentialProvider, "issuer": CredentialAccountIssuer,
			"accountId": params.User.ID,
			"password":  params.PasswordHash, "createdAt": params.User.CreatedAt,
			"updatedAt": params.User.UpdatedAt,
		}})
		if err != nil {
			return err
		}
		if params.CreateSession {
			if _, err = tx.Create(ctx, CreateQuery{
				Model: ModelSession, Data: sessionRecord(params.Session), ForceAllowID: true,
			}); err != nil {
				return err
			}
		}
		_, err = tx.Create(ctx, CreateQuery{Model: ModelOutboxEvent, Data: domainEventRecord(params.Event), ForceAllowID: true})
		return err
	})
	return created, err
}

func (s *databaseStore) FindUserByEmail(ctx context.Context, email string) (User, error) {
	row, err := s.db.FindOne(ctx, FindOneQuery{Model: ModelUser, Where: []Where{Eq("email", email)}})
	if err != nil {
		return User{}, err
	}
	return userFromRecord(row)
}

func (s *databaseStore) FindUserByID(ctx context.Context, id string) (User, error) {
	row, err := s.db.FindOne(ctx, FindOneQuery{Model: ModelUser, Where: []Where{Eq("id", id)}})
	if err != nil {
		return User{}, err
	}
	return userFromRecord(row)
}

func (s *databaseStore) PasswordCredential(ctx context.Context, userID string) (PasswordCredential, error) {
	row, err := s.db.FindOne(ctx, FindOneQuery{
		Model: ModelAccount, Where: credentialIdentityWhere(userID),
	})
	if err != nil {
		return PasswordCredential{}, err
	}
	password, err := recordString(row, "password")
	if err != nil {
		return PasswordCredential{}, err
	}
	updated, err := recordTime(row, "updatedAt")
	if err != nil {
		return PasswordCredential{}, err
	}
	return PasswordCredential{UserID: userID, PasswordHash: password, UpdatedAt: updated}, nil
}

func (s *databaseStore) ReplacePasswordHash(ctx context.Context, userID, previous, replacement string, now time.Time) error {
	where := append(credentialIdentityWhere(userID), Eq("password", previous))
	_, err := s.db.Update(ctx, UpdateQuery{Model: ModelAccount, Where: where,
		Update: Record{"password": replacement, "updatedAt": now.UTC()}})
	return err
}

func (s *databaseStore) SetPasswordHash(ctx context.Context, userID, passwordHash string, now time.Time) error {
	return s.db.Transaction(ctx, func(tx DatabaseAdapter) error {
		where := append(credentialIdentityWhere(userID), Eq("userId", userID))
		account, err := tx.FindOne(ctx, FindOneQuery{Model: ModelAccount, Where: where})
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		if account != nil {
			updated, err := tx.Update(ctx, UpdateQuery{Model: ModelAccount, Where: where,
				Update: Record{"password": passwordHash, "updatedAt": now.UTC()}})
			if err != nil {
				return err
			}
			if updated == nil {
				return ErrReplay
			}
			return nil
		}
		_, err = tx.Create(ctx, CreateQuery{Model: ModelAccount, ForceAllowID: true, Data: Record{
			"id": userID + ":credential", "userId": userID,
			"providerId": credentialProvider, "issuer": CredentialAccountIssuer, "accountId": userID,
			"password": passwordHash, "createdAt": now.UTC(), "updatedAt": now.UTC(),
		}})
		return err
	})
}

func (s *databaseStore) ChangePasswordAndRotate(ctx context.Context, params ChangePasswordParams) (Session, error) {
	var created Session
	err := s.db.Transaction(ctx, func(tx DatabaseAdapter) error {
		where := append(credentialIdentityWhere(params.UserID),
			Eq("userId", params.UserID), Eq("password", params.PreviousHash))
		account, err := tx.Update(ctx, UpdateQuery{Model: ModelAccount, Where: where, Update: Record{
			"password": params.ReplacementHash, "updatedAt": params.ReplacementSession.CreatedAt,
		}})
		if err != nil {
			return err
		}
		if account == nil {
			return ErrReplay
		}
		if params.RevokeOtherSessions {
			if _, err = tx.UpdateMany(ctx, UpdateQuery{Model: ModelSession, Where: []Where{
				Eq("userId", params.UserID), Eq("revokedAt", nil),
			}, Update: Record{
				"revokedAt": params.ReplacementSession.CreatedAt,
				"updatedAt": params.ReplacementSession.CreatedAt,
			}}); err != nil {
				return err
			}
		} else {
			current, updateErr := tx.Update(ctx, UpdateQuery{Model: ModelSession, Where: []Where{
				Eq("userId", params.UserID), Eq("tokenHash", params.CurrentTokenHash), Eq("revokedAt", nil),
			}, Update: Record{
				"revokedAt": params.ReplacementSession.CreatedAt,
				"updatedAt": params.ReplacementSession.CreatedAt,
			}})
			if updateErr != nil {
				return updateErr
			}
			if current == nil {
				return ErrReplay
			}
		}
		row, err := tx.Create(ctx, CreateQuery{
			Model: ModelSession, Data: sessionRecord(params.ReplacementSession), ForceAllowID: true,
		})
		if err != nil {
			return err
		}
		created, err = sessionFromRecord(row)
		return err
	})
	return created, err
}

func (s *databaseStore) UpdateUser(
	ctx context.Context,
	userID string,
	fields Record,
	now time.Time,
) (User, error) {
	update := maps.Clone(fields)
	update["updatedAt"] = now.UTC()
	row, err := s.db.Update(ctx, UpdateQuery{
		Model: ModelUser, Where: []Where{Eq("id", userID)}, Update: update,
	})
	if err != nil {
		return User{}, err
	}
	if row == nil {
		return User{}, ErrNotFound
	}
	return userFromRecord(row)
}

func (s *databaseStore) ListAccounts(ctx context.Context, userID string) ([]OAuthAccount, error) {
	rows, err := s.db.FindMany(ctx, FindManyQuery{
		Model: ModelAccount, Where: []Where{Eq("userId", userID)},
		Sort: &Sort{Field: "createdAt", Direction: "asc"},
	})
	if err != nil {
		return nil, err
	}
	accounts := make([]OAuthAccount, 0, len(rows))
	for _, row := range rows {
		account, err := accountFromRecord(row)
		if err != nil {
			return nil, err
		}
		accounts = append(accounts, account)
	}
	return accounts, nil
}

func (s *databaseStore) UnlinkAccount(
	ctx context.Context,
	userID string,
	providerID string,
	accountID string,
	allowLast bool,
) error {
	return s.db.Transaction(ctx, func(tx DatabaseAdapter) error {
		if !allowLast {
			count, err := tx.Count(ctx, CountQuery{
				Model: ModelAccount,
				Where: []Where{Eq("userId", userID)},
			})
			if err != nil {
				return err
			}
			if count <= 1 {
				return ErrConflict
			}
		}
		where := []Where{Eq("userId", userID), Eq("providerId", providerID)}
		if accountID != "" {
			where = append(where, Eq("accountId", accountID))
		}
		account, err := tx.FindOne(ctx, FindOneQuery{Model: ModelAccount, Where: where})
		if err != nil {
			return err
		}
		if account == nil {
			return ErrNotFound
		}
		id, err := recordString(account, "id")
		if err != nil {
			return err
		}
		return tx.Delete(ctx, DeleteQuery{Model: ModelAccount, Where: []Where{
			Eq("id", id), Eq("userId", userID),
		}})
	})
}

func (s *databaseStore) UnlinkAccountByID(
	ctx context.Context,
	userID string,
	accountRecordID string,
	allowLast bool,
) error {
	return s.db.Transaction(ctx, func(tx DatabaseAdapter) error {
		if !allowLast {
			count, err := tx.Count(ctx, CountQuery{
				Model: ModelAccount, Where: []Where{Eq("userId", userID)},
			})
			if err != nil {
				return err
			}
			if count <= 1 {
				return ErrConflict
			}
		}
		row, err := tx.FindOne(ctx, FindOneQuery{
			Model:  ModelAccount,
			Where:  []Where{Eq("id", accountRecordID), Eq("userId", userID)},
			Select: []string{"id"},
		})
		if err != nil {
			return err
		}
		if row == nil {
			return ErrNotFound
		}
		return tx.Delete(ctx, DeleteQuery{Model: ModelAccount, Where: []Where{
			Eq("id", accountRecordID), Eq("userId", userID),
		}})
	})
}

func (s *databaseStore) DeleteUser(ctx context.Context, userID string) error {
	return s.db.Transaction(ctx, func(tx DatabaseAdapter) error {
		if _, err := tx.DeleteMany(ctx, DeleteQuery{
			Model: ModelSession, Where: []Where{Eq("userId", userID)},
		}); err != nil {
			return err
		}
		if _, err := tx.DeleteMany(ctx, DeleteQuery{
			Model: ModelAccount, Where: []Where{Eq("userId", userID)},
		}); err != nil {
			return err
		}
		return tx.Delete(ctx, DeleteQuery{Model: ModelUser, Where: []Where{Eq("id", userID)}})
	})
}

func (s *databaseStore) ConsumeUserDeletion(
	ctx context.Context,
	hash string,
	userID string,
	now time.Time,
) error {
	token, err := s.db.ConsumeOne(ctx, DeleteQuery{Model: ModelVerification, Where: []Where{
		Eq("identifier", string(PurposeUserDeletion)),
		Eq("value", hash),
		{Field: "expiresAt", Operator: WhereGT, Value: now.UTC()},
	}})
	if err != nil {
		return err
	}
	if token == nil || recordStringMap(token["metadata"])["userId"] != userID {
		return ErrReplay
	}
	return nil
}

func (s *databaseStore) ConsumeEmailChange(ctx context.Context, hash string, now time.Time) (User, string, error) {
	var user User
	var returnTo string
	err := s.db.Transaction(ctx, func(tx DatabaseAdapter) error {
		token, err := tx.ConsumeOne(ctx, DeleteQuery{Model: ModelVerification, Where: []Where{
			{Field: "identifier", Operator: WhereStartsWith, Value: string(PurposeEmailChange) + ":"},
			Eq("value", hash),
			{Field: "expiresAt", Operator: WhereGT, Value: now.UTC()},
		}})
		if err != nil {
			return err
		}
		if token == nil {
			return ErrReplay
		}
		metadata := recordStringMap(token["metadata"])
		if metadata["userId"] == "" || metadata["newEmail"] == "" {
			return ErrReplay
		}
		returnTo = metadata["returnTo"]
		row, err := tx.Update(ctx, UpdateQuery{Model: ModelUser, Where: []Where{
			Eq("id", metadata["userId"]),
		}, Update: Record{
			"email": metadata["newEmail"], "emailVerified": true, "updatedAt": now.UTC(),
		}})
		if err != nil {
			return err
		}
		if row == nil {
			return ErrNotFound
		}
		user, err = userFromRecord(row)
		return err
	})
	return user, returnTo, err
}

func (s *databaseStore) ConsumeEmailChangeConfirmation(
	ctx context.Context,
	hash string,
	now time.Time,
) (User, string, string, error) {
	row, err := s.db.ConsumeOne(ctx, DeleteQuery{Model: ModelVerification, Where: []Where{
		{Field: "identifier", Operator: WhereStartsWith, Value: string(PurposeEmailChangeConfirmation) + ":"},
		Eq("value", hash),
		{Field: "expiresAt", Operator: WhereGT, Value: now.UTC()},
	}})
	if err != nil {
		return User{}, "", "", err
	}
	if row == nil {
		return User{}, "", "", ErrReplay
	}
	metadata := recordStringMap(row["metadata"])
	if metadata["userId"] == "" || metadata["newEmail"] == "" {
		return User{}, "", "", ErrReplay
	}
	user, err := s.FindUserByID(ctx, metadata["userId"])
	return user, metadata["newEmail"], metadata["returnTo"], err
}

func (s *databaseStore) LinkOAuthAccount(
	ctx context.Context,
	accountID string,
	userID string,
	profile OAuthProfile,
	tokens ProviderTokens,
	now time.Time,
) error {
	return s.db.Transaction(ctx, func(tx DatabaseAdapter) error {
		existing, err := tx.FindOne(ctx, FindOneQuery{Model: ModelAccount,
			Where: accountIdentityWhere(profile.Issuer, profile.ProviderAccountID)})
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		if existing != nil {
			owner, err := recordString(existing, "userId")
			if err != nil {
				return err
			}
			if owner != userID {
				return ErrConflict
			}
			id, err := recordString(existing, "id")
			if err != nil {
				return err
			}
			tokens.Scope = mergeOAuthScopes(optionalString(existing["scope"]), tokens.Scope)
			_, err = tx.Update(ctx, UpdateQuery{Model: ModelAccount, Where: []Where{
				Eq("id", id), Eq("userId", userID),
			}, Update: Record{
				"accessToken": tokens.AccessToken, "refreshToken": tokens.RefreshToken,
				"idToken": tokens.IDToken, "scope": tokens.Scope,
				"accessTokenExpiresAt":  nullableTimeValue(tokens.AccessTokenExpiresAt),
				"refreshTokenExpiresAt": nullableTimeValue(tokens.RefreshTokenExpiresAt),
				"updatedAt":             now.UTC(),
			}})
			return err
		}
		_, err = tx.Create(ctx, CreateQuery{Model: ModelAccount, ForceAllowID: true, Data: Record{
			"id": accountID, "userId": userID, "providerId": profile.Provider,
			"issuer": profile.Issuer, "accountId": profile.ProviderAccountID,
			"accessToken": tokens.AccessToken, "refreshToken": tokens.RefreshToken,
			"idToken": tokens.IDToken, "scope": tokens.Scope,
			"accessTokenExpiresAt":  nullableTimeValue(tokens.AccessTokenExpiresAt),
			"refreshTokenExpiresAt": nullableTimeValue(tokens.RefreshTokenExpiresAt),
			"createdAt":             now.UTC(), "updatedAt": now.UTC(),
		}})
		return err
	})
}

func (s *databaseStore) OAuthAccountTokens(
	ctx context.Context,
	userID string,
	providerID string,
	accountID string,
) (StoredOAuthAccount, error) {
	where := []Where{Eq("userId", userID), Eq("providerId", providerID)}
	if accountID != "" {
		where = append(where, Eq("accountId", accountID))
	}
	row, err := s.db.FindOne(ctx, FindOneQuery{Model: ModelAccount, Where: where})
	if err != nil {
		return StoredOAuthAccount{}, err
	}
	if row == nil {
		return StoredOAuthAccount{}, ErrNotFound
	}
	account, err := accountFromRecord(row)
	if err != nil {
		return StoredOAuthAccount{}, err
	}
	return StoredOAuthAccount{Account: account, Tokens: ProviderTokens{
		AccessToken:           optionalString(row["accessToken"]),
		RefreshToken:          optionalString(row["refreshToken"]),
		IDToken:               optionalString(row["idToken"]),
		Scope:                 optionalString(row["scope"]),
		AccessTokenExpiresAt:  optionalTime(row["accessTokenExpiresAt"]),
		RefreshTokenExpiresAt: optionalTime(row["refreshTokenExpiresAt"]),
	}}, nil
}

func (s *databaseStore) OAuthAccountTokensByID(
	ctx context.Context,
	userID string,
	accountRecordID string,
) (StoredOAuthAccount, error) {
	row, err := s.db.FindOne(ctx, FindOneQuery{
		Model: ModelAccount,
		Where: []Where{Eq("id", accountRecordID), Eq("userId", userID)},
	})
	if err != nil {
		return StoredOAuthAccount{}, err
	}
	if row == nil {
		return StoredOAuthAccount{}, ErrNotFound
	}
	account, err := accountFromRecord(row)
	if err != nil {
		return StoredOAuthAccount{}, err
	}
	return StoredOAuthAccount{Account: account, Tokens: ProviderTokens{
		AccessToken:           optionalString(row["accessToken"]),
		RefreshToken:          optionalString(row["refreshToken"]),
		IDToken:               optionalString(row["idToken"]),
		Scope:                 optionalString(row["scope"]),
		AccessTokenExpiresAt:  optionalTime(row["accessTokenExpiresAt"]),
		RefreshTokenExpiresAt: optionalTime(row["refreshTokenExpiresAt"]),
	}}, nil
}

func (s *databaseStore) UpdateOAuthAccountTokens(
	ctx context.Context,
	userID string,
	accountID string,
	tokens ProviderTokens,
	now time.Time,
) error {
	row, err := s.db.Update(ctx, UpdateQuery{Model: ModelAccount, Where: []Where{
		Eq("id", accountID), Eq("userId", userID),
	}, Update: Record{
		"accessToken": tokens.AccessToken, "refreshToken": tokens.RefreshToken,
		"idToken": tokens.IDToken, "scope": tokens.Scope,
		"accessTokenExpiresAt":  nullableTimeValue(tokens.AccessTokenExpiresAt),
		"refreshTokenExpiresAt": nullableTimeValue(tokens.RefreshTokenExpiresAt),
		"updatedAt":             now.UTC(),
	}})
	if err != nil {
		return err
	}
	if row == nil {
		return ErrNotFound
	}
	return nil
}

func (s *databaseStore) CreateSession(ctx context.Context, session Session) (Session, error) {
	row, err := s.db.Create(ctx, CreateQuery{Model: ModelSession, Data: sessionRecord(session), ForceAllowID: true})
	if err != nil {
		return Session{}, err
	}
	return sessionFromRecord(row)
}

func (s *databaseStore) SessionByTokenHash(ctx context.Context, hash string) (Session, User, error) {
	row, err := s.db.FindOne(ctx, FindOneQuery{Model: ModelSession, Where: []Where{Eq("tokenHash", hash)}})
	if err != nil {
		return Session{}, User{}, err
	}
	session, err := sessionFromRecord(row)
	if err != nil {
		return Session{}, User{}, err
	}
	user, err := s.FindUserByID(ctx, session.UserID)
	return session, user, err
}

func (s *databaseStore) RotateSession(ctx context.Context, oldHash string, replacement Session) (Session, error) {
	var created Session
	err := s.db.Transaction(ctx, func(tx DatabaseAdapter) error {
		old, err := tx.Update(ctx, UpdateQuery{Model: ModelSession, Where: []Where{
			Eq("tokenHash", oldHash), Eq("revokedAt", nil),
		}, Update: Record{"revokedAt": replacement.CreatedAt, "updatedAt": replacement.CreatedAt}})
		if err != nil {
			return err
		}
		if old == nil {
			return ErrReplay
		}
		row, err := tx.Create(ctx, CreateQuery{Model: ModelSession, Data: sessionRecord(replacement), ForceAllowID: true})
		if err != nil {
			return err
		}
		created, err = sessionFromRecord(row)
		return err
	})
	return created, err
}

func (s *databaseStore) RevokeSession(ctx context.Context, hash string, at time.Time) error {
	_, err := s.db.Update(ctx, UpdateQuery{Model: ModelSession, Where: []Where{
		Eq("tokenHash", hash), Eq("revokedAt", nil),
	}, Update: Record{"revokedAt": at, "updatedAt": at}})
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	return err
}

func (s *databaseStore) RevokeUserSessions(ctx context.Context, userID string, at time.Time) error {
	_, err := s.db.UpdateMany(ctx, UpdateQuery{Model: ModelSession, Where: []Where{
		Eq("userId", userID), Eq("revokedAt", nil),
	}, Update: Record{"revokedAt": at, "updatedAt": at}})
	return err
}

func (s *databaseStore) ListSessions(ctx context.Context, userID string, now time.Time) ([]Session, error) {
	rows, err := s.db.FindMany(ctx, FindManyQuery{
		Model: ModelSession,
		Where: []Where{
			Eq("userId", userID), Eq("revokedAt", nil),
			{Field: "expiresAt", Operator: WhereGT, Value: now.UTC()},
		},
		Sort: &Sort{Field: "createdAt", Direction: "desc"},
	})
	if err != nil {
		return nil, err
	}
	sessions := make([]Session, 0, len(rows))
	for _, row := range rows {
		session, err := sessionFromRecord(row)
		if err != nil {
			return nil, err
		}
		sessions = append(sessions, session)
	}
	return sessions, nil
}

func (s *databaseStore) RevokeSessionByID(
	ctx context.Context,
	userID string,
	sessionID string,
	at time.Time,
) (bool, error) {
	row, err := s.db.Update(ctx, UpdateQuery{Model: ModelSession, Where: []Where{
		Eq("id", sessionID), Eq("userId", userID), Eq("revokedAt", nil),
	}, Update: Record{"revokedAt": at.UTC(), "updatedAt": at.UTC()}})
	if err != nil {
		return false, err
	}
	return row != nil, nil
}

func (s *databaseStore) RevokeOtherSessions(
	ctx context.Context,
	userID string,
	currentSessionID string,
	at time.Time,
) error {
	_, err := s.db.UpdateMany(ctx, UpdateQuery{Model: ModelSession, Where: []Where{
		Eq("userId", userID), {Field: "id", Operator: WhereNE, Value: currentSessionID},
		Eq("revokedAt", nil),
	}, Update: Record{"revokedAt": at.UTC(), "updatedAt": at.UTC()}})
	return err
}

func (s *databaseStore) UpdateSession(
	ctx context.Context,
	userID string,
	tokenHash string,
	fields Record,
	now time.Time,
) (Session, error) {
	update := maps.Clone(fields)
	update["updatedAt"] = now.UTC()
	row, err := s.db.Update(ctx, UpdateQuery{Model: ModelSession, Where: []Where{
		Eq("userId", userID), Eq("tokenHash", tokenHash), Eq("revokedAt", nil),
	}, Update: update})
	if err != nil {
		return Session{}, err
	}
	if row == nil {
		return Session{}, ErrNotFound
	}
	return sessionFromRecord(row)
}

func (s *databaseStore) PutOneTimeToken(ctx context.Context, token OneTimeToken) error {
	identifier := string(token.Purpose)
	if token.Purpose == PurposeEmailChange || token.Purpose == PurposeEmailChangeConfirmation {
		identifier += ":" + token.UserID
	}
	create := func(database DatabaseAdapter) error {
		_, err := database.Create(ctx, CreateQuery{Model: ModelVerification, ForceAllowID: true, Data: Record{
			"id": token.ID, "identifier": identifier, "value": token.Hash,
			"expiresAt": token.ExpiresAt, "createdAt": token.CreatedAt,
			"metadata": mergeStringMaps(token.Metadata, map[string]string{"userId": token.UserID}),
		}})
		return err
	}
	if token.Purpose != PurposeEmailChange && token.Purpose != PurposeEmailChangeConfirmation {
		return create(s.db)
	}
	return s.db.Transaction(ctx, func(tx DatabaseAdapter) error {
		if _, err := tx.DeleteMany(ctx, DeleteQuery{Model: ModelVerification, Where: []Where{
			Eq("identifier", identifier),
		}}); err != nil {
			return err
		}
		return create(tx)
	})
}

func (s *databaseStore) HasOneTimeToken(
	ctx context.Context,
	purpose OneTimePurpose,
	hash string,
	now time.Time,
) (bool, error) {
	row, err := s.db.FindOne(ctx, FindOneQuery{Model: ModelVerification, Where: []Where{
		Eq("identifier", string(purpose)),
		Eq("value", hash),
		{Field: "expiresAt", Operator: WhereGT, Value: now},
	}})
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return false, nil
		}
		return false, err
	}
	return row != nil, nil
}

func (s *databaseStore) ConsumePasswordReset(
	ctx context.Context,
	hash string,
	passwordHash string,
	now time.Time,
) (User, error) {
	var user User
	err := s.db.Transaction(ctx, func(tx DatabaseAdapter) error {
		token, err := tx.ConsumeOne(ctx, DeleteQuery{Model: ModelVerification, Where: []Where{
			Eq("identifier", string(PurposePasswordReset)),
			Eq("value", hash),
			{Field: "expiresAt", Operator: WhereGT, Value: now},
		}})
		if err != nil {
			return err
		}
		if token == nil {
			return ErrReplay
		}
		metadata := recordStringMap(token["metadata"])
		userID := metadata["userId"]
		if userID == "" {
			return ErrReplay
		}
		where := append(credentialIdentityWhere(userID), Eq("userId", userID))
		account, err := tx.Update(ctx, UpdateQuery{Model: ModelAccount, Where: where,
			Update: Record{"password": passwordHash, "updatedAt": now}})
		if err != nil {
			return err
		}
		if account == nil {
			if _, err = tx.Create(ctx, CreateQuery{
				Model: ModelAccount, ForceAllowID: true, Data: Record{
					"id": userID + ":credential", "userId": userID,
					"providerId": credentialProvider, "issuer": CredentialAccountIssuer,
					"accountId": userID,
					"password":  passwordHash, "createdAt": now, "updatedAt": now,
				},
			}); err != nil {
				return err
			}
		}
		userRow, err := tx.FindOne(ctx, FindOneQuery{Model: ModelUser, Where: []Where{Eq("id", userID)}})
		if err != nil {
			return err
		}
		user, err = userFromRecord(userRow)
		return err
	})
	return user, err
}

func (s *databaseStore) ConsumeEmailVerification(ctx context.Context, hash string, now time.Time) (User, error) {
	token, err := s.db.ConsumeOne(ctx, DeleteQuery{Model: ModelVerification, Where: []Where{
		Eq("identifier", string(PurposeEmailVerify)), Eq("value", hash),
		{Field: "expiresAt", Operator: WhereGT, Value: now},
	}})
	if err != nil {
		return User{}, err
	}
	if token == nil {
		return User{}, ErrReplay
	}
	userID := recordStringMap(token["metadata"])["userId"]
	if userID == "" {
		return User{}, ErrReplay
	}
	return s.FindUserByID(ctx, userID)
}

func (s *databaseStore) VerifyUserEmail(ctx context.Context, userID string, now time.Time) (User, error) {
	return s.UpdateUser(ctx, userID, Record{"emailVerified": true}, now)
}

func (s *databaseStore) PutOAuthState(ctx context.Context, state OAuthState) error {
	_, err := s.db.Create(ctx, CreateQuery{Model: ModelVerification, ForceAllowID: true, Data: Record{
		"id": state.ID, "identifier": string(PurposeOAuthState), "value": state.Hash,
		"expiresAt": state.ExpiresAt, "createdAt": state.CreatedAt,
		"metadata": map[string]string{
			"pkceVerifier": state.PKCEVerifier, "nonce": state.Nonce,
			"redirectURI": state.RedirectURI, "returnTo": state.ReturnTo,
			"errorReturnTo": state.ErrorReturnTo, "newUserReturnTo": state.NewUserReturnTo,
			"linkUserId": state.LinkUserID, "requestSignUp": fmt.Sprintf("%t", state.RequestSignUp),
		},
	}})
	return err
}

func (s *databaseStore) ConsumeOAuthState(ctx context.Context, hash string, now time.Time) (OAuthState, error) {
	row, err := s.db.ConsumeOne(ctx, DeleteQuery{Model: ModelVerification, Where: []Where{
		Eq("identifier", string(PurposeOAuthState)), Eq("value", hash),
		{Field: "expiresAt", Operator: WhereGT, Value: now},
	}})
	if err != nil {
		return OAuthState{}, err
	}
	if row == nil {
		return OAuthState{}, ErrReplay
	}
	meta := recordStringMap(row["metadata"])
	id, _ := recordString(row, "id")
	expires, err := recordTime(row, "expiresAt")
	if err != nil {
		return OAuthState{}, err
	}
	created, err := recordTime(row, "createdAt")
	if err != nil {
		return OAuthState{}, err
	}
	return OAuthState{
		ID: id, Hash: hash, PKCEVerifier: meta["pkceVerifier"], Nonce: meta["nonce"], RedirectURI: meta["redirectURI"],
		ReturnTo: meta["returnTo"], ErrorReturnTo: meta["errorReturnTo"], NewUserReturnTo: meta["newUserReturnTo"],
		LinkUserID: meta["linkUserId"], RequestSignUp: meta["requestSignUp"] == "true",
		ExpiresAt: expires, CreatedAt: created,
	}, nil
}

func (s *databaseStore) UpsertOAuthUser(
	ctx context.Context,
	profile OAuthProfile,
	tokens ProviderTokens,
	session Session,
	event DomainEvent,
	policy OAuthUpsertPolicy,
) (User, Session, bool, error) {
	var user User
	var createdSession Session
	isNew := false
	err := s.db.Transaction(ctx, func(tx DatabaseAdapter) error {
		account, err := tx.FindOne(ctx, FindOneQuery{Model: ModelAccount,
			Where: accountIdentityWhere(profile.Issuer, profile.ProviderAccountID)})
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		if account != nil {
			userID, err := recordString(account, "userId")
			if err != nil {
				return err
			}
			row, err := tx.FindOne(ctx, FindOneQuery{Model: ModelUser, Where: []Where{Eq("id", userID)}})
			if err != nil {
				return err
			}
			user, err = userFromRecord(row)
			if err != nil {
				return err
			}
			if policy.UpdateAccountOnSignIn {
				tokens.Scope = mergeOAuthScopes(optionalString(account["scope"]), tokens.Scope)
				accountID, err := recordString(account, "id")
				if err != nil {
					return err
				}
				if _, err = tx.Update(ctx, UpdateQuery{Model: ModelAccount, Where: []Where{
					Eq("id", accountID), Eq("userId", user.ID),
				}, Update: Record{
					"accessToken": tokens.AccessToken, "refreshToken": tokens.RefreshToken,
					"idToken": tokens.IDToken, "scope": tokens.Scope,
					"accessTokenExpiresAt":  nullableTimeValue(tokens.AccessTokenExpiresAt),
					"refreshTokenExpiresAt": nullableTimeValue(tokens.RefreshTokenExpiresAt),
					"updatedAt":             session.CreatedAt,
				}}); err != nil {
					return err
				}
			}
			if profile.EmailVerified && !user.EmailVerified && profile.Email == user.Email {
				row, err = tx.Update(ctx, UpdateQuery{Model: ModelUser, Where: []Where{Eq("id", user.ID)}, Update: Record{
					"emailVerified": true, "updatedAt": session.CreatedAt,
				}})
				if err != nil {
					return err
				}
				user, err = userFromRecord(row)
				if err != nil {
					return err
				}
			}
		} else {
			row, findErr := tx.FindOne(ctx, FindOneQuery{Model: ModelUser, Where: []Where{Eq("email", profile.Email)}})
			if findErr != nil && !errors.Is(findErr, ErrNotFound) {
				return findErr
			}
			if row == nil {
				if !policy.AllowSignUp {
					return ErrSignUpDisabled
				}
				isNew = true
				now := session.CreatedAt
				user = User{
					ID: session.UserID, Email: profile.Email, Name: profile.Name, ImageURL: profile.ImageURL,
					EmailVerified: profile.EmailVerified, CreatedAt: now, UpdatedAt: now,
				}
				if _, err = tx.Create(ctx, CreateQuery{Model: ModelUser, Data: userRecord(user), ForceAllowID: true}); err != nil {
					return err
				}
				if _, err = tx.Create(ctx, CreateQuery{Model: ModelOutboxEvent, Data: domainEventRecord(event), ForceAllowID: true}); err != nil {
					return err
				}
			} else {
				user, err = userFromRecord(row)
				if err != nil {
					return err
				}
				if !policy.AllowImplicitLink || (policy.RequireLocalVerification && !user.EmailVerified) {
					return ErrAccountNotLinked
				}
				session.UserID = user.ID
			}
			accountID := event.ID + ":account"
			_, err = tx.Create(ctx, CreateQuery{Model: ModelAccount, ForceAllowID: true, Data: Record{
				"id": accountID, "userId": user.ID, "providerId": profile.Provider,
				"issuer": profile.Issuer, "accountId": profile.ProviderAccountID,
				"accessToken": tokens.AccessToken, "refreshToken": tokens.RefreshToken, "idToken": tokens.IDToken,
				"scope": tokens.Scope, "accessTokenExpiresAt": nullableTimeValue(tokens.AccessTokenExpiresAt),
				"refreshTokenExpiresAt": nullableTimeValue(tokens.RefreshTokenExpiresAt),
				"createdAt":             session.CreatedAt, "updatedAt": session.CreatedAt,
			}})
			if err != nil {
				return err
			}
			if !isNew && profile.EmailVerified && !user.EmailVerified && profile.Email == user.Email {
				row, err = tx.Update(ctx, UpdateQuery{Model: ModelUser, Where: []Where{Eq("id", user.ID)}, Update: Record{
					"emailVerified": true, "updatedAt": session.CreatedAt,
				}})
				if err != nil {
					return err
				}
				user, err = userFromRecord(row)
				if err != nil {
					return err
				}
			}
			if !isNew && policy.UpdateUserInfoOnLink {
				update := Record{"updatedAt": session.CreatedAt}
				if profile.Name != "" {
					update["name"] = profile.Name
				}
				if profile.ImageURL != "" {
					update["image"] = profile.ImageURL
				}
				if len(update) > 1 {
					row, err = tx.Update(ctx, UpdateQuery{Model: ModelUser, Where: []Where{Eq("id", user.ID)}, Update: update})
					if err != nil {
						return err
					}
					user, err = userFromRecord(row)
					if err != nil {
						return err
					}
				}
			}
		}
		session.UserID = user.ID
		row, err := tx.Create(ctx, CreateQuery{Model: ModelSession, Data: sessionRecord(session), ForceAllowID: true})
		if err != nil {
			return err
		}
		createdSession, err = sessionFromRecord(row)
		return err
	})
	return user, createdSession, isNew, err
}

func (s *databaseStore) RotateSessionWithAudit(
	ctx context.Context,
	actorTokenHash string,
	session Session,
	audit AuditEvent,
) (Session, error) {
	var created Session
	err := s.db.Transaction(ctx, func(tx DatabaseAdapter) error {
		rotated, err := tx.Update(ctx, UpdateQuery{Model: ModelSession, Where: []Where{
			Eq("tokenHash", actorTokenHash), Eq("revokedAt", nil),
		}, Update: Record{"revokedAt": session.CreatedAt, "updatedAt": session.CreatedAt}})
		if err != nil {
			return err
		}
		if rotated == nil {
			return ErrReplay
		}
		row, err := tx.Create(ctx, CreateQuery{Model: ModelSession, Data: sessionRecord(session), ForceAllowID: true})
		if err != nil {
			return err
		}
		created, err = sessionFromRecord(row)
		if err != nil {
			return err
		}
		_, err = tx.Create(ctx, CreateQuery{Model: ModelAuditEvent, Data: auditEventRecord(audit), ForceAllowID: true})
		return err
	})
	return created, err
}

func userRecord(user User) Record {
	return Record{
		"id": user.ID, "email": user.Email, "name": user.Name, "image": user.ImageURL,
		"emailVerified": user.EmailVerified, "createdAt": user.CreatedAt, "updatedAt": user.UpdatedAt,
		"disabledAt": nullableTime(user.DisabledAt),
	}
}

func userFromRecord(row Record) (User, error) {
	if row == nil {
		return User{}, ErrNotFound
	}
	id, err := recordString(row, "id")
	if err != nil {
		return User{}, err
	}
	email, err := recordString(row, "email")
	if err != nil {
		return User{}, err
	}
	created, err := recordTime(row, "createdAt")
	if err != nil {
		return User{}, err
	}
	updated, err := recordTime(row, "updatedAt")
	if err != nil {
		return User{}, err
	}
	return User{
		ID: id, Email: email, Name: optionalString(row["name"]), ImageURL: optionalString(row["image"]),
		EmailVerified: optionalBool(row["emailVerified"]), CreatedAt: created, UpdatedAt: updated,
		DisabledAt: optionalTimePtr(row["disabledAt"]),
	}, nil
}

func sessionRecord(session Session) Record {
	return Record{
		"id": session.ID, "userId": session.UserID, "tokenHash": session.TokenHash,
		"expiresAt": session.ExpiresAt, "createdAt": session.CreatedAt, "updatedAt": session.UpdatedAt,
		"lastSeenAt": session.LastSeenAt, "revokedAt": nullableTime(session.RevokedAt),
		"impersonatedBy": session.ImpersonatorID, "impersonationId": session.ImpersonationID,
	}
}

func sessionFromRecord(row Record) (Session, error) {
	if row == nil {
		return Session{}, ErrNotFound
	}
	id, err := recordString(row, "id")
	if err != nil {
		return Session{}, err
	}
	userID, err := recordString(row, "userId")
	if err != nil {
		return Session{}, err
	}
	hash, err := recordString(row, "tokenHash")
	if err != nil {
		return Session{}, err
	}
	expires, err := recordTime(row, "expiresAt")
	if err != nil {
		return Session{}, err
	}
	created, err := recordTime(row, "createdAt")
	if err != nil {
		return Session{}, err
	}
	updated, err := recordTime(row, "updatedAt")
	if err != nil {
		return Session{}, err
	}
	lastSeen, err := recordTime(row, "lastSeenAt")
	if err != nil {
		return Session{}, err
	}
	return Session{
		ID: id, UserID: userID, TokenHash: hash, ExpiresAt: expires, CreatedAt: created,
		UpdatedAt: updated, LastSeenAt: lastSeen, RevokedAt: optionalTimePtr(row["revokedAt"]),
		ImpersonatorID: optionalString(row["impersonatedBy"]), ImpersonationID: optionalString(row["impersonationId"]),
	}, nil
}

func accountFromRecord(row Record) (OAuthAccount, error) {
	if row == nil {
		return OAuthAccount{}, ErrNotFound
	}
	id, err := recordString(row, "id")
	if err != nil {
		return OAuthAccount{}, err
	}
	userID, err := recordString(row, "userId")
	if err != nil {
		return OAuthAccount{}, err
	}
	providerID, err := recordString(row, "providerId")
	if err != nil {
		return OAuthAccount{}, err
	}
	issuer, err := recordString(row, "issuer")
	if err != nil {
		return OAuthAccount{}, err
	}
	accountID, err := recordString(row, "accountId")
	if err != nil {
		return OAuthAccount{}, err
	}
	createdAt, err := recordTime(row, "createdAt")
	if err != nil {
		return OAuthAccount{}, err
	}
	updatedAt, err := recordTime(row, "updatedAt")
	if err != nil {
		return OAuthAccount{}, err
	}
	return OAuthAccount{
		ID: id, UserID: userID, Provider: providerID, Issuer: issuer, ProviderAccountID: accountID,
		Scope: optionalString(row["scope"]), CreatedAt: createdAt, UpdatedAt: updatedAt,
	}, nil
}

func domainEventRecord(event DomainEvent) Record {
	return Record{
		"id": event.ID, "schemaVersion": event.SchemaVersion, "name": event.Name,
		"aggregateId": event.AggregateID, "occurredAt": event.OccurredAt, "payload": event.Payload,
	}
}

func auditEventRecord(event AuditEvent) Record {
	return Record{
		"id": event.ID, "schemaVersion": event.SchemaVersion, "action": event.Action,
		"actorUserId": event.ActorUserID, "subjectUserId": event.SubjectUserID,
		"sessionId": event.SessionID, "occurredAt": event.OccurredAt,
		"request": event.Request, "details": event.Details,
	}
}

func recordString(row Record, field string) (string, error) {
	value, ok := row[field].(string)
	if !ok || value == "" {
		return "", fmt.Errorf("betterauth: adapter returned invalid %s", field)
	}
	return value, nil
}

func recordTime(row Record, field string) (time.Time, error) {
	value, ok := row[field].(time.Time)
	if !ok || value.IsZero() {
		return time.Time{}, fmt.Errorf("betterauth: adapter returned invalid %s", field)
	}
	return value.UTC(), nil
}

func optionalString(value any) string {
	result, _ := value.(string)
	return result
}

func optionalBool(value any) bool {
	result, _ := value.(bool)
	return result
}

func optionalTimePtr(value any) *time.Time {
	switch result := value.(type) {
	case time.Time:
		copy := result.UTC()
		return &copy
	case *time.Time:
		if result == nil {
			return nil
		}
		copy := result.UTC()
		return &copy
	default:
		return nil
	}
}

func optionalTime(value any) time.Time {
	if result := optionalTimePtr(value); result != nil {
		return *result
	}
	return time.Time{}
}

func nullableTime(value *time.Time) any {
	if value == nil {
		return nil
	}
	return value.UTC()
}

func nullableTimeValue(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value.UTC()
}

func recordStringMap(value any) map[string]string {
	switch typed := value.(type) {
	case Record:
		result := make(map[string]string, len(typed))
		for key, item := range typed {
			if stringValue, ok := item.(string); ok {
				result[key] = stringValue
			}
		}
		return result
	case map[string]string:
		return typed
	case map[string]any:
		result := make(map[string]string, len(typed))
		for key, item := range typed {
			if stringValue, ok := item.(string); ok {
				result[key] = stringValue
			}
		}
		return result
	default:
		return map[string]string{}
	}
}

func mergeStringMaps(values ...map[string]string) map[string]string {
	result := map[string]string{}
	for _, value := range values {
		for key, item := range value {
			result[key] = item
		}
	}
	return result
}
