package betterauth

import (
	"context"
	"errors"
	"fmt"
)

// EventHandler receives durable, versioned outbox events. Delivery is
// at-least-once; handlers must use DomainEvent.ID as their idempotency key.
type EventHandler interface {
	HandleEvent(context.Context, DomainEvent) error
}

type OutboxDispatcher struct {
	Database  DatabaseAdapter
	Handler   EventHandler
	Clock     Clock
	BatchSize int
}

// RunOnce delivers one ordered batch and marks successful records published.
// A handler error stops the batch and leaves that event unpublished.
func (dispatcher OutboxDispatcher) RunOnce(ctx context.Context) (int, error) {
	if dispatcher.Database == nil || dispatcher.Handler == nil {
		return 0, errors.New("betterauth: outbox database and handler are required")
	}
	if dispatcher.Clock == nil {
		dispatcher.Clock = systemClock{}
	}
	if dispatcher.BatchSize == 0 {
		dispatcher.BatchSize = 100
	}
	if dispatcher.BatchSize < 1 || dispatcher.BatchSize > 1000 {
		return 0, errors.New("betterauth: outbox batch size is out of bounds")
	}
	rows, err := dispatcher.Database.FindMany(ctx, FindManyQuery{
		Model: ModelOutboxEvent, Where: []Where{Eq("publishedAt", nil)},
		Limit: dispatcher.BatchSize, Sort: &Sort{Field: "occurredAt", Direction: "asc"},
	})
	if err != nil {
		return 0, fmt.Errorf("betterauth: read outbox: %w", err)
	}
	delivered := 0
	for _, row := range rows {
		event, err := domainEventFromRecord(row)
		if err != nil {
			return delivered, err
		}
		if err := dispatcher.Handler.HandleEvent(ctx, event); err != nil {
			return delivered, fmt.Errorf("betterauth: deliver outbox event %s: %w", event.ID, err)
		}
		updated, err := dispatcher.Database.Update(ctx, UpdateQuery{
			Model: ModelOutboxEvent, Where: []Where{Eq("id", event.ID), Eq("publishedAt", nil)},
			Update: Record{"publishedAt": dispatcher.Clock.Now().UTC()},
		})
		if err != nil {
			return delivered, fmt.Errorf("betterauth: mark outbox event %s: %w", event.ID, err)
		}
		if updated == nil {
			// Another dispatcher won the publish marker. At-least-once delivery
			// means the handler must tolerate this duplicate.
			continue
		}
		delivered++
	}
	return delivered, nil
}

func domainEventFromRecord(row Record) (DomainEvent, error) {
	id, err := recordString(row, "id")
	if err != nil {
		return DomainEvent{}, err
	}
	name, err := recordString(row, "name")
	if err != nil {
		return DomainEvent{}, err
	}
	aggregateID, err := recordString(row, "aggregateId")
	if err != nil {
		return DomainEvent{}, err
	}
	occurred, err := recordTime(row, "occurredAt")
	if err != nil {
		return DomainEvent{}, err
	}
	version, err := recordInt(row["schemaVersion"])
	if err != nil {
		return DomainEvent{}, err
	}
	return DomainEvent{
		ID: id, SchemaVersion: version, Name: name, AggregateID: aggregateID,
		OccurredAt: occurred, Payload: recordStringMap(row["payload"]),
	}, nil
}

func recordInt(value any) (int, error) {
	switch typed := value.(type) {
	case int:
		return typed, nil
	case int32:
		return int(typed), nil
	case int64:
		return int(typed), nil
	case float64:
		return int(typed), nil
	default:
		return 0, fmt.Errorf("betterauth: adapter returned invalid integer")
	}
}
