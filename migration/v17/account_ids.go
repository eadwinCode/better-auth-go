// Package v17 holds the data step that Better Auth 1.7 still needs after the
// account issuer revert: rewriting provider account IDs whose subject changed,
// such as Microsoft accounts that move from the "sub" claim to "oid".
//
// Accounts stay keyed by (providerId, accountId), so no schema change is
// needed. See README.md in this directory for databases that were built from
// unreleased main while it still had the account issuer column.
package v17

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	betterauth "github.com/eadwinCode/better-auth-go"
)

const defaultMaxAccounts = 100_000

// ResolveAccountID returns the new provider account ID for one account row,
// or the current value (or "") to keep it. It must use verified provider data,
// such as a checked stored ID token or a trusted provider export. It must
// never derive identity from email or other mutable profile data.
type ResolveAccountID func(context.Context, betterauth.Record) (string, error)

type Options struct {
	// Resolve chooses the new account ID for each row. It is required.
	Resolve     ResolveAccountID
	MaxAccounts int
	DryRun      bool
}

// Collision lists rows that would share one (providerId, accountId) key.
type Collision struct {
	ProviderID string
	AccountID  string
	AccountIDs []string
	UserIDs    []string
}

type Report struct {
	Scanned    int
	Updated    int
	Collisions []Collision
}

type plannedAccount struct {
	id           string
	userID       string
	providerID   string
	oldAccountID string
	newAccountID string
}

// RewriteAccountIDs plans every change before it writes anything. A resolver
// error, an invalid result, or two rows that would share one
// (providerId, accountId) key stops it with zero writes. The updates run in
// one adapter transaction. Stop sign-in and account linking while it runs.
func RewriteAccountIDs(
	ctx context.Context,
	db betterauth.DatabaseAdapter,
	options Options,
) (Report, error) {
	if db == nil {
		return Report{}, errors.New("v17 migration: database adapter is required")
	}
	if options.Resolve == nil {
		return Report{}, errors.New("v17 migration: Resolve is required")
	}
	limit := options.MaxAccounts
	if limit == 0 {
		limit = defaultMaxAccounts
	}
	if limit < 1 || limit > 1_000_000 {
		return Report{}, errors.New("v17 migration: MaxAccounts is out of bounds")
	}
	planned := make([]plannedAccount, 0)
	for offset := 0; ; offset += 1000 {
		rows, err := db.FindMany(ctx, betterauth.FindManyQuery{
			Model: betterauth.ModelAccount, Limit: 1000, Offset: offset,
			Sort: &betterauth.Sort{Field: "id", Direction: "asc"},
		})
		if err != nil {
			return Report{}, fmt.Errorf("v17 migration: list accounts: %w", err)
		}
		for _, row := range rows {
			item, err := planAccount(ctx, row, options.Resolve)
			if err != nil {
				return Report{Scanned: len(planned)}, err
			}
			planned = append(planned, item)
			if len(planned) > limit {
				return Report{Scanned: len(planned)}, errors.New("v17 migration: account inventory exceeds MaxAccounts")
			}
		}
		if len(rows) < 1000 {
			break
		}
	}
	report := Report{Scanned: len(planned), Collisions: collisions(planned)}
	if len(report.Collisions) > 0 {
		return report, errors.New("v17 migration: providerId/accountId collisions require manual ownership review")
	}
	if err := chainedRewrite(planned); err != nil {
		return report, err
	}
	if options.DryRun {
		return report, nil
	}
	err := db.Transaction(ctx, func(tx betterauth.DatabaseAdapter) error {
		for _, item := range planned {
			if item.newAccountID == item.oldAccountID {
				continue
			}
			updated, err := tx.Update(ctx, betterauth.UpdateQuery{
				Model: betterauth.ModelAccount,
				Where: []betterauth.Where{
					betterauth.Eq("id", item.id), betterauth.Eq("providerId", item.providerID),
					betterauth.Eq("accountId", item.oldAccountID),
				},
				Update: betterauth.Record{"accountId": item.newAccountID},
			})
			if err != nil {
				return err
			}
			if updated == nil {
				return errors.New("v17 migration: account changed during maintenance window")
			}
			report.Updated++
		}
		return nil
	})
	if err != nil {
		report.Updated = 0
		return report, fmt.Errorf("v17 migration: rewrite transaction: %w", err)
	}
	return report, nil
}

func planAccount(
	ctx context.Context,
	row betterauth.Record,
	resolve ResolveAccountID,
) (plannedAccount, error) {
	item := plannedAccount{}
	item.id, _ = row["id"].(string)
	item.userID, _ = row["userId"].(string)
	item.providerID, _ = row["providerId"].(string)
	item.oldAccountID, _ = row["accountId"].(string)
	if item.id == "" || item.providerID == "" || item.oldAccountID == "" {
		return plannedAccount{}, errors.New("v17 migration: malformed account row")
	}
	accountID, err := resolve(ctx, clone(row))
	if err != nil {
		return plannedAccount{}, fmt.Errorf("v17 migration: resolve account ID: %w", err)
	}
	accountID = strings.TrimSpace(accountID)
	if accountID == "" {
		accountID = item.oldAccountID
	}
	if len(accountID) > 512 {
		return plannedAccount{}, errors.New("v17 migration: resolver returned an invalid account ID")
	}
	item.newAccountID = accountID
	return item, nil
}

func collisions(planned []plannedAccount) []Collision {
	type entry struct {
		providerID string
		accountID  string
		accounts   []string
		users      []string
	}
	grouped := map[string]*entry{}
	for _, item := range planned {
		key := item.providerID + "\x00" + item.newAccountID
		group := grouped[key]
		if group == nil {
			group = &entry{providerID: item.providerID, accountID: item.newAccountID}
			grouped[key] = group
		}
		group.accounts = append(group.accounts, item.id)
		group.users = append(group.users, item.userID)
	}
	result := make([]Collision, 0)
	for _, group := range grouped {
		if len(group.accounts) < 2 {
			continue
		}
		slices.Sort(group.accounts)
		slices.Sort(group.users)
		result = append(result, Collision{
			ProviderID: group.providerID, AccountID: group.accountID,
			AccountIDs: group.accounts, UserIDs: group.users,
		})
	}
	slices.SortFunc(result, func(left, right Collision) int {
		if comparison := strings.Compare(left.ProviderID, right.ProviderID); comparison != 0 {
			return comparison
		}
		return strings.Compare(left.AccountID, right.AccountID)
	})
	return result
}

func clone(row betterauth.Record) betterauth.Record {
	result := make(betterauth.Record, len(row))
	for key, value := range row {
		result[key] = value
	}
	return result
}

// chainedRewrite rejects a plan where a row's new account ID is the current ID
// of another row that also changes (a swap or a chain). The unique
// (providerId, accountId) index is checked after every update, so such a plan
// would fail part-way and roll back; this says why before anything runs.
func chainedRewrite(planned []plannedAccount) error {
	current := make(map[[2]string]string, len(planned))
	for _, item := range planned {
		if item.newAccountID != item.oldAccountID {
			current[[2]string{item.providerID, item.oldAccountID}] = item.id
		}
	}
	for _, item := range planned {
		if item.newAccountID == item.oldAccountID {
			continue
		}
		if other, ok := current[[2]string{item.providerID, item.newAccountID}]; ok && other != item.id {
			return errors.New("v17 migration: a new account ID is another changing row's current ID " +
				"(a swap or chain); rewrite those rows in separate runs")
		}
	}
	return nil
}
