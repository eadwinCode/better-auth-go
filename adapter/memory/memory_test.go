package memory

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	betterauth "github.com/eadwinCode/better-auth-go"
)

func TestConsumeOneHasExactlyOneWinner(t *testing.T) {
	t.Parallel()
	adapter := New()
	ctx := context.Background()
	_, err := adapter.Create(ctx, betterauth.CreateQuery{
		Model: "token", Data: betterauth.Record{"id": "one", "value": "secret"}, ForceAllowID: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	var winners atomic.Int64
	var wait sync.WaitGroup
	for range 32 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			record, consumeErr := adapter.ConsumeOne(ctx, betterauth.DeleteQuery{
				Model: "token", Where: []betterauth.Where{betterauth.Eq("value", "secret")},
			})
			if consumeErr != nil {
				t.Errorf("consume: %v", consumeErr)
				return
			}
			if record != nil {
				winners.Add(1)
			}
		}()
	}
	wait.Wait()
	if winners.Load() != 1 {
		t.Fatalf("expected exactly one winner, got %d", winners.Load())
	}
}

func TestTransactionRollback(t *testing.T) {
	t.Parallel()
	adapter := New()
	expected := errors.New("rollback")
	err := adapter.Transaction(context.Background(), func(transaction betterauth.DatabaseAdapter) error {
		_, createErr := transaction.Create(context.Background(), betterauth.CreateQuery{
			Model: "thing", Data: betterauth.Record{"id": "one", "value": "created"}, ForceAllowID: true,
		})
		if createErr != nil {
			return createErr
		}
		return expected
	})
	if !errors.Is(err, expected) {
		t.Fatalf("expected rollback error, got %v", err)
	}
	record, err := adapter.FindOne(context.Background(), betterauth.FindOneQuery{
		Model: "thing", Where: []betterauth.Where{betterauth.Eq("id", "one")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if record != nil {
		t.Fatalf("rolled back record remains: %#v", record)
	}
}

func TestGuardedIncrement(t *testing.T) {
	t.Parallel()
	adapter := New()
	ctx := context.Background()
	_, err := adapter.Create(ctx, betterauth.CreateQuery{
		Model: "counter", Data: betterauth.Record{"id": "one", "remaining": float64(1)}, ForceAllowID: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	query := betterauth.IncrementQuery{
		Model: "counter",
		Where: []betterauth.Where{
			betterauth.Eq("id", "one"),
			{Field: "remaining", Operator: betterauth.WhereGT, Connector: betterauth.WhereAND, Value: float64(0)},
		},
		Increment: map[string]float64{"remaining": -1},
	}
	first, err := adapter.IncrementOne(ctx, query)
	if err != nil {
		t.Fatal(err)
	}
	if first == nil || first["remaining"] != float64(0) {
		t.Fatalf("unexpected first increment: %#v", first)
	}
	second, err := adapter.IncrementOne(ctx, query)
	if err != nil {
		t.Fatal(err)
	}
	if second != nil {
		t.Fatalf("guard should reject second increment: %#v", second)
	}
}
