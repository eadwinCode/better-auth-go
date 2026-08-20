// Package v17 contains the reviewed manual data steps required before a
// Better Auth 1.7 schema is made authoritative.
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

// AccountIdentity is the trusted identity selected for one existing account.
type AccountIdentity struct {
	Issuer    string
	AccountID string
}

// ResolveAccountIdentity must use deployment configuration or verified
// provider exports. It must never derive identity from email or mutable user
// profile data.
type ResolveAccountIdentity func(context.Context, betterauth.Record) (AccountIdentity, error)

type Options struct {
	// ProviderIssuers maps providerId to the exact trusted issuer. Use
	// betterauth.OAuthAccountIssuer only after explicitly classifying a plain
	// OAuth provider with no protocol issuer.
	ProviderIssuers map[string]string
	// Resolve overrides account identity when a subject also changes, notably
	// Microsoft sub -> oid and legacy SSO mapping.id -> protocol subject.
	Resolve     ResolveAccountIdentity
	MaxAccounts int
	DryRun      bool
}

type Collision struct {
	Issuer     string
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
	row      betterauth.Record
	identity AccountIdentity
}

// StagingSchema makes issuer nullable and omits its unique index. Apply this
// schema first, run Backfill, review the report, then apply the final required
// CoreSchema and adapter-specific NOT NULL/index DDL.
func StagingSchema() betterauth.Schema {
	schema := betterauth.CoreSchema()
	account := schema[betterauth.ModelAccount]
	issuer := account.Fields["issuer"]
	issuer.Required = false
	account.Fields["issuer"] = issuer
	account.Indexes = nil
	schema[betterauth.ModelAccount] = account
	return schema
}

// Backfill plans the complete migration before writing anything. Any missing
// mapping or duplicate (issuer, accountId) stops the migration with zero
// writes. Updates run in one adapter transaction.
func Backfill(ctx context.Context, db betterauth.DatabaseAdapter, options Options) (Report, error) {
	if db == nil {
		return Report{}, errors.New("v17 migration: database adapter is required")
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
			identity, err := resolveIdentity(ctx, row, options)
			if err != nil {
				return Report{Scanned: len(planned)}, err
			}
			planned = append(planned, plannedAccount{row: row, identity: identity})
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
		return report, errors.New("v17 migration: issuer/accountId collisions require manual ownership review")
	}
	if options.DryRun {
		return report, nil
	}
	err := db.Transaction(ctx, func(tx betterauth.DatabaseAdapter) error {
		for _, item := range planned {
			id, _ := item.row["id"].(string)
			providerID, _ := item.row["providerId"].(string)
			oldAccountID, _ := item.row["accountId"].(string)
			if id == "" || providerID == "" || oldAccountID == "" {
				return errors.New("v17 migration: malformed account row")
			}
			updated, err := tx.Update(ctx, betterauth.UpdateQuery{
				Model: betterauth.ModelAccount,
				Where: []betterauth.Where{
					betterauth.Eq("id", id), betterauth.Eq("providerId", providerID),
					betterauth.Eq("accountId", oldAccountID),
				},
				Update: betterauth.Record{
					"issuer": item.identity.Issuer, "accountId": item.identity.AccountID,
				},
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
		return report, fmt.Errorf("v17 migration: backfill transaction: %w", err)
	}
	return report, nil
}

func resolveIdentity(ctx context.Context, row betterauth.Record, options Options) (AccountIdentity, error) {
	if options.Resolve != nil {
		identity, err := options.Resolve(ctx, clone(row))
		if err != nil {
			return AccountIdentity{}, fmt.Errorf("v17 migration: resolve account identity: %w", err)
		}
		return validateIdentity(identity)
	}
	providerID, _ := row["providerId"].(string)
	accountID, _ := row["accountId"].(string)
	userID, _ := row["userId"].(string)
	if providerID == "credential" {
		return validateIdentity(AccountIdentity{
			Issuer: betterauth.CredentialAccountIssuer, AccountID: userID,
		})
	}
	issuer := strings.TrimSpace(options.ProviderIssuers[providerID])
	if issuer == "" {
		return AccountIdentity{}, fmt.Errorf("v17 migration: no reviewed issuer mapping for provider %q", providerID)
	}
	return validateIdentity(AccountIdentity{Issuer: issuer, AccountID: accountID})
}

func validateIdentity(identity AccountIdentity) (AccountIdentity, error) {
	identity.Issuer = strings.TrimSpace(identity.Issuer)
	identity.AccountID = strings.TrimSpace(identity.AccountID)
	if identity.Issuer == "" || identity.AccountID == "" ||
		len(identity.Issuer) > 2048 || len(identity.AccountID) > 512 {
		return AccountIdentity{}, errors.New("v17 migration: resolver returned an invalid identity")
	}
	return identity, nil
}

func collisions(planned []plannedAccount) []Collision {
	type entry struct {
		accounts []string
		users    []string
	}
	grouped := map[string]*entry{}
	identities := map[string]AccountIdentity{}
	for _, item := range planned {
		key := item.identity.Issuer + "\x00" + item.identity.AccountID
		group := grouped[key]
		if group == nil {
			group = &entry{}
			grouped[key] = group
			identities[key] = item.identity
		}
		group.accounts = append(group.accounts, fmt.Sprint(item.row["id"]))
		group.users = append(group.users, fmt.Sprint(item.row["userId"]))
	}
	result := make([]Collision, 0)
	for key, group := range grouped {
		if len(group.accounts) < 2 {
			continue
		}
		identity := identities[key]
		slices.Sort(group.accounts)
		slices.Sort(group.users)
		result = append(result, Collision{
			Issuer: identity.Issuer, AccountID: identity.AccountID,
			AccountIDs: group.accounts, UserIDs: group.users,
		})
	}
	slices.SortFunc(result, func(left, right Collision) int {
		if comparison := strings.Compare(left.Issuer, right.Issuer); comparison != 0 {
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
