package betterauth

import (
	"context"
	"errors"
	"fmt"
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
			"providerId": credentialProvider, "accountId": params.User.ID,
			"password": params.PasswordHash, "createdAt": params.User.CreatedAt,
			"updatedAt": params.User.UpdatedAt,
		}})
		if err != nil {
			return err
		}
		if _, err = tx.Create(ctx, CreateQuery{Model: ModelSession, Data: sessionRecord(params.Session), ForceAllowID: true}); err != nil {
			return err
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
	row, err := s.db.FindOne(ctx, FindOneQuery{Model: ModelAccount, Where: []Where{
		Eq("providerId", credentialProvider), Eq("accountId", userID),
	}})
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
	_, err := s.db.Update(ctx, UpdateQuery{Model: ModelAccount, Where: []Where{
		Eq("providerId", credentialProvider), Eq("accountId", userID), Eq("password", previous),
	}, Update: Record{"password": replacement, "updatedAt": now.UTC()}})
	return err
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

func (s *databaseStore) PutOneTimeToken(ctx context.Context, token OneTimeToken) error {
	_, err := s.db.Create(ctx, CreateQuery{Model: ModelVerification, ForceAllowID: true, Data: Record{
		"id": token.ID, "identifier": string(token.Purpose), "value": token.Hash,
		"expiresAt": token.ExpiresAt, "createdAt": token.CreatedAt,
		"metadata": mergeStringMaps(token.Metadata, map[string]string{"userId": token.UserID}),
	}})
	return err
}

func (s *databaseStore) ConsumePasswordReset(
	ctx context.Context,
	hash string,
	passwordHash string,
	session Session,
) (User, Session, error) {
	var user User
	var created Session
	err := s.db.Transaction(ctx, func(tx DatabaseAdapter) error {
		token, err := tx.ConsumeOne(ctx, DeleteQuery{Model: ModelVerification, Where: []Where{
			Eq("identifier", string(PurposePasswordReset)),
			Eq("value", hash),
			{Field: "expiresAt", Operator: WhereGT, Value: session.CreatedAt},
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
		session.UserID = userID
		if _, err = tx.Update(ctx, UpdateQuery{Model: ModelAccount, Where: []Where{
			Eq("providerId", credentialProvider), Eq("accountId", userID),
		}, Update: Record{"password": passwordHash, "updatedAt": session.CreatedAt}}); err != nil {
			return err
		}
		if _, err = tx.UpdateMany(ctx, UpdateQuery{Model: ModelSession, Where: []Where{
			Eq("userId", userID), Eq("revokedAt", nil),
		}, Update: Record{"revokedAt": session.CreatedAt, "updatedAt": session.CreatedAt}}); err != nil {
			return err
		}
		userRow, err := tx.FindOne(ctx, FindOneQuery{Model: ModelUser, Where: []Where{Eq("id", userID)}})
		if err != nil {
			return err
		}
		user, err = userFromRecord(userRow)
		if err != nil {
			return err
		}
		sessionRow, err := tx.Create(ctx, CreateQuery{Model: ModelSession, Data: sessionRecord(session), ForceAllowID: true})
		if err != nil {
			return err
		}
		created, err = sessionFromRecord(sessionRow)
		return err
	})
	return user, created, err
}

func (s *databaseStore) ConsumeEmailVerification(ctx context.Context, hash string, now time.Time) (User, error) {
	var user User
	err := s.db.Transaction(ctx, func(tx DatabaseAdapter) error {
		token, err := tx.ConsumeOne(ctx, DeleteQuery{Model: ModelVerification, Where: []Where{
			Eq("identifier", string(PurposeEmailVerify)), Eq("value", hash),
			{Field: "expiresAt", Operator: WhereGT, Value: now},
		}})
		if err != nil {
			return err
		}
		if token == nil {
			return ErrReplay
		}
		userID := recordStringMap(token["metadata"])["userId"]
		if userID == "" {
			return ErrReplay
		}
		row, err := tx.Update(ctx, UpdateQuery{Model: ModelUser, Where: []Where{Eq("id", userID)}, Update: Record{
			"emailVerified": true, "updatedAt": now,
		}})
		if err != nil {
			return err
		}
		user, err = userFromRecord(row)
		return err
	})
	return user, err
}

func (s *databaseStore) PutOAuthState(ctx context.Context, state OAuthState) error {
	_, err := s.db.Create(ctx, CreateQuery{Model: ModelVerification, ForceAllowID: true, Data: Record{
		"id": state.ID, "identifier": string(PurposeOAuthState), "value": state.Hash,
		"expiresAt": state.ExpiresAt, "createdAt": state.CreatedAt,
		"metadata": map[string]string{
			"pkceVerifier": state.PKCEVerifier, "nonce": state.Nonce,
			"redirectURI": state.RedirectURI, "returnTo": state.ReturnTo,
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
		ReturnTo: meta["returnTo"], ExpiresAt: expires, CreatedAt: created,
	}, nil
}

func (s *databaseStore) UpsertOAuthUser(
	ctx context.Context,
	profile OAuthProfile,
	tokens ProviderTokens,
	session Session,
	event DomainEvent,
) (User, Session, bool, error) {
	var user User
	var createdSession Session
	isNew := false
	err := s.db.Transaction(ctx, func(tx DatabaseAdapter) error {
		account, err := tx.FindOne(ctx, FindOneQuery{Model: ModelAccount, Where: []Where{
			Eq("providerId", profile.Provider), Eq("accountId", profile.ProviderAccountID),
		}})
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
		} else {
			row, findErr := tx.FindOne(ctx, FindOneQuery{Model: ModelUser, Where: []Where{Eq("email", profile.Email)}})
			if findErr != nil && !errors.Is(findErr, ErrNotFound) {
				return findErr
			}
			if row == nil {
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
				session.UserID = user.ID
			}
			accountID := event.ID + ":account"
			_, err = tx.Create(ctx, CreateQuery{Model: ModelAccount, ForceAllowID: true, Data: Record{
				"id": accountID, "userId": user.ID, "providerId": profile.Provider,
				"accountId":   profile.ProviderAccountID,
				"accessToken": tokens.AccessToken, "refreshToken": tokens.RefreshToken, "idToken": tokens.IDToken,
				"scope": tokens.Scope, "accessTokenExpiresAt": nullableTimeValue(tokens.AccessTokenExpiresAt),
				"refreshTokenExpiresAt": nullableTimeValue(tokens.RefreshTokenExpiresAt),
				"createdAt":             session.CreatedAt, "updatedAt": session.CreatedAt,
			}})
			if err != nil {
				return err
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
