package betterauth_test

import (
	"context"
	"sync"
	"testing"
	"time"

	betterauth "github.com/eadwinCode/better-auth-go"
	"github.com/eadwinCode/better-auth-go/adapter/memory"
)

type eventCapture struct {
	mu     sync.Mutex
	events []betterauth.DomainEvent
}

func (capture *eventCapture) HandleEvent(_ context.Context, event betterauth.DomainEvent) error {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	capture.events = append(capture.events, event)
	return nil
}

func TestOutboxDispatcher(t *testing.T) {
	t.Parallel()
	database := memory.New()
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	_, err := database.Create(context.Background(), betterauth.CreateQuery{
		Model: betterauth.ModelOutboxEvent, ForceAllowID: true,
		Data: betterauth.Record{
			"id": "event-1", "schemaVersion": 1, "name": betterauth.EventUserCreated,
			"aggregateId": "user-1", "occurredAt": now,
			"payload": map[string]string{"userId": "user-1"}, "publishedAt": nil,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	capture := &eventCapture{}
	dispatcher := betterauth.OutboxDispatcher{
		Database: database, Handler: capture, Clock: fixedClock{now: now.Add(time.Minute)},
	}
	delivered, err := dispatcher.RunOnce(context.Background())
	if err != nil || delivered != 1 {
		t.Fatalf("first dispatch: delivered=%d err=%v", delivered, err)
	}
	delivered, err = dispatcher.RunOnce(context.Background())
	if err != nil || delivered != 0 {
		t.Fatalf("second dispatch: delivered=%d err=%v", delivered, err)
	}
	if len(capture.events) != 1 || capture.events[0].ID != "event-1" {
		t.Fatalf("unexpected events: %#v", capture.events)
	}
}
