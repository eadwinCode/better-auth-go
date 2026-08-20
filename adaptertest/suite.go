// Package adaptertest publishes the conformance suite used by first-party and
// third-party database adapters.
package adaptertest

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	betterauth "github.com/eadwinCode/better-auth-go"
)

type Factory func(*testing.T) betterauth.DatabaseAdapter

// Run executes the core Better Auth adapter contract.
func Run(t *testing.T, factory Factory) {
	t.Helper()
	t.Run("crud projection and pagination", func(t *testing.T) {
		adapter := factory(t)
		ctx := context.Background()
		for index := range 5 {
			_, err := adapter.Create(ctx, betterauth.CreateQuery{
				Model: "conformance", ForceAllowID: true,
				Data: betterauth.Record{
					"id": fmt.Sprintf("record-%d", index), "group": "a",
					"sequence": float64(index), "name": fmt.Sprintf("Name %d", index),
				},
			})
			if err != nil {
				t.Fatal(err)
			}
		}
		record, err := adapter.FindOne(ctx, betterauth.FindOneQuery{
			Model: "conformance", Where: []betterauth.Where{betterauth.Eq("id", "record-2")},
			Select: []string{"id", "name"},
		})
		if err != nil {
			t.Fatal(err)
		}
		if record["id"] != "record-2" || record["sequence"] != nil {
			t.Fatalf("projection failed: %#v", record)
		}
		records, err := adapter.FindMany(ctx, betterauth.FindManyQuery{
			Model: "conformance", Where: []betterauth.Where{betterauth.Eq("group", "a")},
			Limit: 2, Offset: 1, Sort: &betterauth.Sort{Field: "sequence", Direction: "desc"},
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(records) != 2 || records[0]["id"] != "record-3" || records[1]["id"] != "record-2" {
			t.Fatalf("pagination/sort failed: %#v", records)
		}
		updated, err := adapter.Update(ctx, betterauth.UpdateQuery{
			Model: "conformance", Where: []betterauth.Where{betterauth.Eq("id", "record-2")},
			Update: betterauth.Record{"name": "Updated"},
		})
		if err != nil || updated["name"] != "Updated" {
			t.Fatalf("update failed: %#v, %v", updated, err)
		}
		if err := adapter.Delete(ctx, betterauth.DeleteQuery{
			Model: "conformance", Where: []betterauth.Where{betterauth.Eq("id", "record-2")},
		}); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("empty mutation predicates are rejected", func(t *testing.T) {
		adapter := factory(t)
		ctx := context.Background()
		if _, err := adapter.UpdateMany(ctx, betterauth.UpdateQuery{
			Model: "conformance", Update: betterauth.Record{"danger": true},
		}); err == nil {
			t.Fatal("empty update predicate was accepted")
		}
		if _, err := adapter.DeleteMany(ctx, betterauth.DeleteQuery{Model: "conformance"}); err == nil {
			t.Fatal("empty delete predicate was accepted")
		}
	})

	t.Run("consume one is atomic", func(t *testing.T) {
		adapter := factory(t)
		ctx := context.Background()
		_, err := adapter.Create(ctx, betterauth.CreateQuery{
			Model: "single_use", ForceAllowID: true,
			Data: betterauth.Record{"id": "token", "value": "hash"},
		})
		if err != nil {
			t.Fatal(err)
		}
		var winners atomic.Int64
		var wait sync.WaitGroup
		for range 16 {
			wait.Add(1)
			go func() {
				defer wait.Done()
				record, consumeErr := adapter.ConsumeOne(ctx, betterauth.DeleteQuery{
					Model: "single_use", Where: []betterauth.Where{betterauth.Eq("value", "hash")},
				})
				if consumeErr != nil {
					t.Errorf("consume: %v", consumeErr)
				} else if record != nil {
					winners.Add(1)
				}
			}()
		}
		wait.Wait()
		if winners.Load() != 1 {
			t.Fatalf("expected one consumer, got %d", winners.Load())
		}
	})

	t.Run("guarded increment is atomic", func(t *testing.T) {
		adapter := factory(t)
		ctx := context.Background()
		_, err := adapter.Create(ctx, betterauth.CreateQuery{
			Model: "counter", ForceAllowID: true,
			Data: betterauth.Record{"id": "counter", "remaining": float64(1)},
		})
		if err != nil {
			t.Fatal(err)
		}
		query := betterauth.IncrementQuery{
			Model: "counter", Where: []betterauth.Where{
				betterauth.Eq("id", "counter"),
				{Field: "remaining", Operator: betterauth.WhereGT, Connector: betterauth.WhereAND, Value: float64(0)},
			},
			Increment: map[string]float64{"remaining": -1},
		}
		first, err := adapter.IncrementOne(ctx, query)
		if err != nil || first == nil {
			t.Fatalf("first increment: %#v, %v", first, err)
		}
		second, err := adapter.IncrementOne(ctx, query)
		if err != nil || second != nil {
			t.Fatalf("guarded increment should have no second winner: %#v, %v", second, err)
		}
	})

	t.Run("transaction rollback", func(t *testing.T) {
		adapter := factory(t)
		if !adapter.Capabilities().Transactions {
			t.Skip("adapter does not advertise transactions")
		}
		ctx := context.Background()
		rollback := errors.New("rollback")
		err := adapter.Transaction(ctx, func(transaction betterauth.DatabaseAdapter) error {
			_, createErr := transaction.Create(ctx, betterauth.CreateQuery{
				Model: "transaction", ForceAllowID: true, Data: betterauth.Record{"id": "rolled-back"},
			})
			if createErr != nil {
				return createErr
			}
			return rollback
		})
		if !errors.Is(err, rollback) {
			t.Fatalf("unexpected transaction error: %v", err)
		}
		record, err := adapter.FindOne(ctx, betterauth.FindOneQuery{
			Model: "transaction", Where: []betterauth.Where{betterauth.Eq("id", "rolled-back")},
		})
		if err != nil || record != nil {
			t.Fatalf("transaction did not roll back: %#v, %v", record, err)
		}
	})

	t.Run("account identity is issuer scoped", func(t *testing.T) {
		adapter := factory(t)
		ctx := context.Background()
		create := func(id, issuer, provider string) error {
			_, err := adapter.Create(ctx, betterauth.CreateQuery{
				Model: betterauth.ModelAccount, ForceAllowID: true,
				Data: betterauth.Record{
					"id": id, "userId": "user-" + id, "providerId": provider,
					"issuer": issuer, "accountId": "shared-subject",
					"createdAt": time.Now().UTC(), "updatedAt": time.Now().UTC(),
				},
			})
			return err
		}
		if err := create("issuer-a", "https://issuer-a.example", "alias-a"); err != nil {
			t.Fatal(err)
		}
		if err := create("issuer-b", "https://issuer-b.example", "alias-a"); err != nil {
			t.Fatalf("same provider/accountId under a different issuer collided: %v", err)
		}
		if err := create("issuer-a-alias", "https://issuer-a.example", "alias-b"); !errors.Is(err, betterauth.ErrConflict) {
			t.Fatalf("same issuer/accountId under a provider alias was accepted: %v", err)
		}
	})

	t.Run("transaction scoped adapter commits", func(t *testing.T) {
		adapter := factory(t)
		if !adapter.Capabilities().Transactions {
			t.Skip("adapter does not advertise transactions")
		}
		ctx := context.Background()
		err := adapter.Transaction(ctx, func(transaction betterauth.DatabaseAdapter) error {
			_, createErr := transaction.Create(ctx, betterauth.CreateQuery{
				Model: "transaction", ForceAllowID: true, Data: betterauth.Record{"id": "committed"},
			})
			return createErr
		})
		if err != nil {
			t.Fatal(err)
		}
		record, err := adapter.FindOne(ctx, betterauth.FindOneQuery{
			Model: "transaction", Where: []betterauth.Where{betterauth.Eq("id", "committed")},
		})
		if err != nil || record == nil {
			t.Fatalf("transaction did not commit: %#v, %v", record, err)
		}
	})

	t.Run("nested work reuses transaction scoped adapter", func(t *testing.T) {
		adapter := factory(t)
		if !adapter.Capabilities().Transactions {
			t.Skip("adapter does not advertise transactions")
		}
		ctx := context.Background()
		err := adapter.Transaction(ctx, func(transaction betterauth.DatabaseAdapter) error {
			return transaction.Transaction(ctx, func(nested betterauth.DatabaseAdapter) error {
				_, createErr := nested.Create(ctx, betterauth.CreateQuery{
					Model: "transaction", ForceAllowID: true, Data: betterauth.Record{"id": "nested"},
				})
				return createErr
			})
		})
		if err != nil {
			t.Fatal(err)
		}
		record, err := adapter.FindOne(ctx, betterauth.FindOneQuery{
			Model: "transaction", Where: []betterauth.Where{betterauth.Eq("id", "nested")},
		})
		if err != nil || record == nil {
			t.Fatalf("nested transaction-scoped work did not commit: %#v, %v", record, err)
		}
	})
}
