package adaptertest

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	betterauth "github.com/eadwinCode/better-auth-go"
)

// SchemaFactory returns a fresh, empty adapter that is ready for schema: its
// tables, collections, and indexes exist, and for a SchemaConfigurableAdapter
// WithSchema has been applied. It must not wrap the adapter with
// betterauth.WrapDatabaseAdapter; the suites do that so they can also read the
// stored rows by their physical names.
type SchemaFactory func(*testing.T, betterauth.Schema) betterauth.DatabaseAdapter

func logical(t *testing.T, physical betterauth.DatabaseAdapter, schema betterauth.Schema) betterauth.DatabaseAdapter {
	t.Helper()
	wrapped, err := betterauth.WrapDatabaseAdapter(physical, schema)
	if err != nil {
		t.Fatal(err)
	}
	return wrapped
}

func createAccount(
	ctx context.Context,
	database betterauth.DatabaseAdapter,
	id, userID, providerID, accountID string,
) error {
	now := time.Now().UTC()
	_, err := database.Create(ctx, betterauth.CreateQuery{
		Model: betterauth.ModelAccount, ForceAllowID: true,
		Data: betterauth.Record{
			"id": id, "userId": userID, "providerId": providerID, "accountId": accountID,
			"createdAt": now, "updatedAt": now,
		},
	})
	return err
}

// RunAccountIdentity checks that accounts are keyed by (providerId,
// accountId), as in Better Auth 1.7.3 and later, and that a database shaped
// like better-auth-go v1.0.2 works with the current schema and no migration.
func RunAccountIdentity(t *testing.T, factory SchemaFactory) {
	t.Helper()
	t.Run("same subject at two providers is two accounts", func(t *testing.T) {
		ctx := context.Background()
		database := logical(t, factory(t, betterauth.CoreSchema()), betterauth.CoreSchema())
		if err := createAccount(ctx, database, "github-row", "user-a", "github", "subject"); err != nil {
			t.Fatal(err)
		}
		if err := createAccount(ctx, database, "gitlab-row", "user-b", "gitlab", "subject"); err != nil {
			t.Fatalf("same accountId at another provider was rejected: %v", err)
		}
		count, err := database.Count(ctx, betterauth.CountQuery{
			Model: betterauth.ModelAccount, Where: []betterauth.Where{betterauth.Eq("accountId", "subject")},
		})
		if err != nil || count != 2 {
			t.Fatalf("accounts for one subject = %d, %v; want 2", count, err)
		}
		for provider, owner := range map[string]string{"github": "user-a", "gitlab": "user-b"} {
			row, err := betterauth.FindAccountByKey(ctx, database, provider, "subject")
			if err != nil || row == nil || row["userId"] != owner {
				t.Fatalf("FindAccountByKey(%s) = %#v, %v; want owner %s", provider, row, err, owner)
			}
		}
		row, err := betterauth.FindAccountByKey(ctx, database, "bitbucket", "subject")
		if err != nil || row != nil {
			t.Fatalf("FindAccountByKey for an unknown provider = %#v, %v", row, err)
		}
	})

	t.Run("same provider key for another user conflicts", func(t *testing.T) {
		ctx := context.Background()
		database := logical(t, factory(t, betterauth.CoreSchema()), betterauth.CoreSchema())
		if err := createAccount(ctx, database, "first", "user-a", "github", "subject"); err != nil {
			t.Fatal(err)
		}
		if err := createAccount(ctx, database, "second", "user-b", "github", "subject"); !errors.Is(err, betterauth.ErrConflict) {
			t.Fatalf("duplicate providerId/accountId was accepted: %v", err)
		}
	})

	t.Run("duplicate provider key is ambiguous", func(t *testing.T) {
		ctx := context.Background()
		// A database built by Better Auth TypeScript has no unique index on
		// the provider key, so duplicates can exist there.
		schema := betterauth.CoreSchema()
		account := schema[betterauth.ModelAccount]
		account.Indexes = nil
		schema[betterauth.ModelAccount] = account
		database := logical(t, factory(t, schema), schema)
		if err := createAccount(ctx, database, "first", "user-a", "github", "subject"); err != nil {
			t.Fatal(err)
		}
		if err := createAccount(ctx, database, "second", "user-b", "github", "subject"); err != nil {
			if errors.Is(err, betterauth.ErrConflict) {
				t.Skip("adapter rejects duplicate provider keys the schema does not declare")
			}
			t.Fatal(err)
		}
		row, err := betterauth.FindAccountByKey(ctx, database, "github", "subject")
		if !errors.Is(err, betterauth.ErrAmbiguousAccount) || row != nil {
			t.Fatalf("FindAccountByKey on a duplicate key = %#v, %v; want ErrAmbiguousAccount", row, err)
		}
	})

	t.Run("release v1.0.2 database works without migration", func(t *testing.T) {
		ctx := context.Background()
		physical := factory(t, ReleaseV102CoreSchema())
		current := betterauth.CoreSchema()
		if configurable, ok := physical.(betterauth.SchemaConfigurableAdapter); ok {
			configured, err := configurable.WithSchema(current)
			if err != nil {
				t.Fatalf("current schema does not fit a v1.0.2 database: %v", err)
			}
			physical = configured
		}
		database := logical(t, physical, current)
		SeedReleaseBaseline(t, database)
		AssertReleaseUpgrade(t, database)
		if err := createAccount(ctx, database, "oauth", "upgrade-user", "github", "subject"); err != nil {
			t.Fatalf("new OAuth account on a v1.0.2 database: %v", err)
		}
		row, err := betterauth.FindAccountByKey(ctx, database, "credential", "upgrade-user")
		if err != nil || row == nil || row["password"] != "fixture-hash" {
			t.Fatalf("v1.0.2 credential account lookup = %#v, %v", row, err)
		}
	})
}

// MappedIdentitySchema returns the core schema with swapped stored names:
// user is stored as "account", account as "identity", session as "user", and
// auditEvent as "session". user.email is stored as "email_address" and
// account.accountId as "provider_account_id". An adapter that mixes logical
// and stored names stores rows in the wrong place or applies the wrong unique
// rules under this schema.
func MappedIdentitySchema() betterauth.Schema {
	schema := betterauth.CoreSchema()
	rename := func(model, storedModel string, fields map[string]string) {
		definition := schema[model]
		definition.ModelName = storedModel
		for field, storedField := range fields {
			value := definition.Fields[field]
			value.FieldName = storedField
			definition.Fields[field] = value
		}
		schema[model] = definition
	}
	rename(betterauth.ModelUser, "account", map[string]string{"email": "email_address"})
	rename(betterauth.ModelAccount, "identity", map[string]string{"accountId": "provider_account_id"})
	rename(betterauth.ModelSession, "user", nil)
	rename(betterauth.ModelAuditEvent, "session", nil)
	return schema
}

// RunMappedIdentity checks CRUD, unique rules, ConsumeOne, and IncrementOne
// under MappedIdentitySchema, and that each row lands in its stored model.
func RunMappedIdentity(t *testing.T, factory SchemaFactory) {
	t.Helper()
	schema := MappedIdentitySchema()
	setup := func(t *testing.T) (betterauth.DatabaseAdapter, betterauth.DatabaseAdapter) {
		physical := factory(t, schema)
		return physical, logical(t, physical, schema)
	}
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	createUser := func(ctx context.Context, database betterauth.DatabaseAdapter, id, email string) error {
		_, err := database.Create(ctx, betterauth.CreateQuery{
			Model: betterauth.ModelUser, ForceAllowID: true,
			Data: betterauth.Record{
				"id": id, "email": email, "emailVerified": false, "name": "User " + id,
				"createdAt": now, "updatedAt": now,
			},
		})
		return err
	}
	stored := func(t *testing.T, physical betterauth.DatabaseAdapter, model, id string) betterauth.Record {
		t.Helper()
		row, err := physical.FindOne(context.Background(), betterauth.FindOneQuery{
			Model: model, Where: []betterauth.Where{betterauth.Eq("id", id)},
		})
		if err != nil {
			t.Fatalf("read stored %s %s: %v", model, id, err)
		}
		return row
	}

	t.Run("user CRUD uses stored names", func(t *testing.T) {
		ctx := context.Background()
		physical, database := setup(t)
		if err := createUser(ctx, database, "user-1", "one@example.com"); err != nil {
			t.Fatal(err)
		}
		row, err := database.FindOne(ctx, betterauth.FindOneQuery{
			Model: betterauth.ModelUser, Where: []betterauth.Where{betterauth.Eq("email", "one@example.com")},
		})
		if err != nil || row == nil || row["id"] != "user-1" {
			t.Fatalf("find user by email = %#v, %v", row, err)
		}
		updated, err := database.Update(ctx, betterauth.UpdateQuery{
			Model: betterauth.ModelUser, Where: []betterauth.Where{betterauth.Eq("id", "user-1")},
			Update: betterauth.Record{"name": "Renamed", "updatedAt": now.Add(time.Minute)},
		})
		if err != nil || updated == nil || updated["name"] != "Renamed" {
			t.Fatalf("update user = %#v, %v", updated, err)
		}
		raw := stored(t, physical, "account", "user-1")
		if raw == nil || raw["email_address"] != "one@example.com" || raw["name"] != "Renamed" {
			t.Fatalf("user row is not in stored model %q with stored fields: %#v", "account", raw)
		}
		if row := stored(t, physical, "user", "user-1"); row != nil {
			t.Fatalf("user row leaked into the session model: %#v", row)
		}
		if err = database.Delete(ctx, betterauth.DeleteQuery{
			Model: betterauth.ModelUser, Where: []betterauth.Where{betterauth.Eq("id", "user-1")},
		}); err != nil {
			t.Fatal(err)
		}
		if row := stored(t, physical, "account", "user-1"); row != nil {
			t.Fatalf("deleted user remains: %#v", row)
		}
	})

	t.Run("user email uniqueness uses stored names", func(t *testing.T) {
		ctx := context.Background()
		_, database := setup(t)
		if err := createUser(ctx, database, "user-1", "one@example.com"); err != nil {
			t.Fatal(err)
		}
		if err := createUser(ctx, database, "user-2", "two@example.com"); err != nil {
			t.Fatalf("second user with a different email was rejected: %v", err)
		}
		if err := createUser(ctx, database, "user-3", "one@example.com"); !errors.Is(err, betterauth.ErrConflict) {
			t.Fatalf("duplicate email was accepted: %v", err)
		}
		if _, err := database.Update(ctx, betterauth.UpdateQuery{
			Model: betterauth.ModelUser, Where: []betterauth.Where{betterauth.Eq("id", "user-2")},
			Update: betterauth.Record{"email": "one@example.com"},
		}); !errors.Is(err, betterauth.ErrConflict) {
			t.Fatalf("update to a duplicate email was accepted: %v", err)
		}
	})

	t.Run("account provider key uses stored names", func(t *testing.T) {
		ctx := context.Background()
		physical, database := setup(t)
		if err := createUser(ctx, database, "user-1", "one@example.com"); err != nil {
			t.Fatal(err)
		}
		if err := createAccount(ctx, database, "github-row", "user-1", "github", "subject"); err != nil {
			t.Fatal(err)
		}
		if err := createAccount(ctx, database, "gitlab-row", "user-1", "gitlab", "subject"); err != nil {
			t.Fatalf("same subject at another provider was rejected: %v", err)
		}
		if err := createAccount(ctx, database, "github-again", "user-2", "github", "subject"); !errors.Is(err, betterauth.ErrConflict) {
			t.Fatalf("duplicate provider key was accepted: %v", err)
		}
		row, err := betterauth.FindAccountByKey(ctx, database, "github", "subject")
		if err != nil || row == nil || row["id"] != "github-row" {
			t.Fatalf("FindAccountByKey = %#v, %v", row, err)
		}
		raw := stored(t, physical, "identity", "github-row")
		if raw == nil || raw["provider_account_id"] != "subject" {
			t.Fatalf("account row is not in stored model %q with stored fields: %#v", "identity", raw)
		}
	})

	t.Run("session consume one uses stored names", func(t *testing.T) {
		ctx := context.Background()
		physical, database := setup(t)
		if err := createUser(ctx, database, "user-1", "one@example.com"); err != nil {
			t.Fatal(err)
		}
		createSession := func(id, tokenHash string) error {
			_, err := database.Create(ctx, betterauth.CreateQuery{
				Model: betterauth.ModelSession, ForceAllowID: true,
				Data: betterauth.Record{
					"id": id, "userId": "user-1", "tokenHash": tokenHash,
					"expiresAt": now.Add(time.Hour), "createdAt": now, "updatedAt": now, "lastSeenAt": now,
				},
			})
			return err
		}
		if err := createSession("session-1", "hash-1"); err != nil {
			t.Fatal(err)
		}
		if err := createSession("session-2", "hash-2"); err != nil {
			t.Fatalf("second session was rejected: %v", err)
		}
		if err := createSession("session-3", "hash-1"); !errors.Is(err, betterauth.ErrConflict) {
			t.Fatalf("duplicate token hash was accepted: %v", err)
		}
		if raw := stored(t, physical, "user", "session-1"); raw == nil || raw["tokenHash"] != "hash-1" {
			t.Fatalf("session row is not in stored model %q: %#v", "user", raw)
		}
		consume := betterauth.DeleteQuery{
			Model: betterauth.ModelSession, Where: []betterauth.Where{betterauth.Eq("tokenHash", "hash-1")},
		}
		first, err := database.ConsumeOne(ctx, consume)
		if err != nil || first == nil || first["id"] != "session-1" {
			t.Fatalf("first consume = %#v, %v", first, err)
		}
		second, err := database.ConsumeOne(ctx, consume)
		if err != nil || second != nil {
			t.Fatalf("second consume = %#v, %v", second, err)
		}
		if raw := stored(t, physical, "user", "session-2"); raw == nil {
			t.Fatal("consume removed the wrong session")
		}
	})

	t.Run("audit event increment uses stored names", func(t *testing.T) {
		ctx := context.Background()
		physical, database := setup(t)
		if _, err := database.Create(ctx, betterauth.CreateQuery{
			Model: betterauth.ModelAuditEvent, ForceAllowID: true,
			Data: betterauth.Record{
				"id": "audit-1", "schemaVersion": float64(1), "action": "fixture",
				"actorUserId": "user-1", "subjectUserId": "user-1", "occurredAt": now,
			},
		}); err != nil {
			t.Fatal(err)
		}
		query := betterauth.IncrementQuery{
			Model: betterauth.ModelAuditEvent,
			Where: []betterauth.Where{
				betterauth.Eq("id", "audit-1"),
				{Field: "schemaVersion", Operator: betterauth.WhereLT, Connector: betterauth.WhereAND, Value: float64(2)},
			},
			Increment: map[string]float64{"schemaVersion": 1},
		}
		first, err := database.IncrementOne(ctx, query)
		if err != nil || first == nil || fmt.Sprint(first["schemaVersion"]) != "2" {
			t.Fatalf("first increment = %#v, %v", first, err)
		}
		second, err := database.IncrementOne(ctx, query)
		if err != nil || second != nil {
			t.Fatalf("guarded increment had a second winner: %#v, %v", second, err)
		}
		if raw := stored(t, physical, "session", "audit-1"); raw == nil || raw["action"] != "fixture" {
			t.Fatalf("audit row is not in stored model %q: %#v", "session", raw)
		}
	})
}
