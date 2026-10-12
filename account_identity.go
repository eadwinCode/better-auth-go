package betterauth

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// accountKeyWhere matches the account row a provider identity owns. Accounts
// are keyed by (providerId, accountId), as in Better Auth 1.6 and again from
// Better Auth 1.7.3.
func accountKeyWhere(providerID, accountID string) []Where {
	return []Where{Eq("providerId", providerID), Eq("accountId", accountID)}
}

func credentialIdentityWhere(userID string) []Where {
	return accountKeyWhere(credentialProvider, userID)
}

// FindAccountByKey returns the one account row with this (providerId,
// accountId) key, or nil when there is none. db must use logical model and
// field names, such as HookContext.Database. It reads up to two rows so a
// database without the unique index cannot make it pick one owner at random:
// more than one match returns ErrAmbiguousAccount. It ports Better Auth's
// internalAdapter.findAccountByKey.
func FindAccountByKey(
	ctx context.Context,
	db DatabaseAdapter,
	providerID string,
	accountID string,
) (Record, error) {
	rows, err := db.FindMany(ctx, FindManyQuery{
		Model: ModelAccount, Where: accountKeyWhere(providerID, accountID), Limit: 2,
	})
	if err != nil {
		return nil, err
	}
	if len(rows) > 1 {
		return nil, fmt.Errorf("%w: provider %q", ErrAmbiguousAccount, providerID)
	}
	if len(rows) == 0 {
		return nil, nil
	}
	return rows[0], nil
}

// findProfileAccount finds the account for a verified profile. When no
// account has the profile's current ID but one has its previous ID (for
// example a Microsoft account stored by "sub" before "oid"), it switches that
// account to the current ID in the same transaction and returns it.
func findProfileAccount(
	ctx context.Context,
	tx DatabaseAdapter,
	profile OAuthProfile,
	now time.Time,
) (Record, error) {
	account, err := FindAccountByKey(ctx, tx, profile.Provider, profile.ProviderAccountID)
	if err != nil || account != nil {
		return account, err
	}
	previous := strings.TrimSpace(profile.PreviousProviderAccountID)
	if previous == "" || previous == profile.ProviderAccountID {
		return nil, nil
	}
	legacy, err := FindAccountByKey(ctx, tx, profile.Provider, previous)
	if err != nil || legacy == nil {
		return nil, err
	}
	id, err := recordString(legacy, "id")
	if err != nil {
		return nil, err
	}
	updated, err := tx.Update(ctx, UpdateQuery{Model: ModelAccount, Where: []Where{
		Eq("id", id), Eq("providerId", profile.Provider), Eq("accountId", previous),
	}, Update: Record{"accountId": profile.ProviderAccountID, "updatedAt": now.UTC()}})
	if err != nil {
		return nil, err
	}
	if updated == nil {
		return nil, ErrConflict
	}
	return updated, nil
}
