package betterauth

import (
	"context"
	"fmt"
	"slices"
)

// DatabaseOperation identifies a logical adapter mutation.
type DatabaseOperation string

// Supported database hook operations.
const (
	DatabaseCreate       DatabaseOperation = "create"
	DatabaseUpdate       DatabaseOperation = "update"
	DatabaseUpdateMany   DatabaseOperation = "updateMany"
	DatabaseDelete       DatabaseOperation = "delete"
	DatabaseDeleteMany   DatabaseOperation = "deleteMany"
	DatabaseConsumeOne   DatabaseOperation = "consumeOne"
	DatabaseIncrementOne DatabaseOperation = "incrementOne"
)

// DatabaseHookContext contains cloned inputs and outputs for one adapter
// mutation. Before hooks may replace Where, Data, and Increment.
type DatabaseHookContext struct {
	Operation DatabaseOperation
	Model     string
	Where     []Where
	Data      Record
	Increment map[string]float64
	Result    Record
	Count     int64
}

// DatabaseHookHandler handles one logical adapter mutation.
type DatabaseHookHandler func(context.Context, *DatabaseHookContext) error

// DatabaseHook registers mutation callbacks for one model or "*" and an
// optional operation allowlist.
type DatabaseHook struct {
	Model      string
	Operations []DatabaseOperation
	Before     DatabaseHookHandler
	After      DatabaseHookHandler
}

type databaseHookRegistration struct {
	pluginID string
	hook     DatabaseHook
}

type hookedDatabaseAdapter struct {
	next     DatabaseAdapter
	hooks    []databaseHookRegistration
	deferred *[]deferredDatabaseHook
}

type deferredDatabaseHook struct {
	ctx          context.Context
	registration databaseHookRegistration
	state        *DatabaseHookContext
}

func wrapDatabaseHooks(adapter DatabaseAdapter, plugins []Plugin) (DatabaseAdapter, error) {
	var registrations []databaseHookRegistration
	for _, plugin := range plugins {
		for _, hook := range plugin.DatabaseHooks {
			if hook.Model == "" || (hook.Before == nil && hook.After == nil) {
				return nil, fmt.Errorf("betterauth: plugin %q has invalid database hook", plugin.ID)
			}
			for _, operation := range hook.Operations {
				if !validDatabaseOperation(operation) {
					return nil, fmt.Errorf("betterauth: plugin %q has invalid database operation %q", plugin.ID, operation)
				}
			}
			hook.Operations = slices.Clone(hook.Operations)
			registrations = append(registrations, databaseHookRegistration{pluginID: plugin.ID, hook: hook})
		}
	}
	if len(registrations) == 0 {
		return adapter, nil
	}
	return &hookedDatabaseAdapter{next: adapter, hooks: registrations}, nil
}

func (adapter *hookedDatabaseAdapter) ID() string { return adapter.next.ID() }

func (adapter *hookedDatabaseAdapter) Capabilities() AdapterCapabilities {
	return adapter.next.Capabilities()
}

func (adapter *hookedDatabaseAdapter) Create(ctx context.Context, query CreateQuery) (Record, error) {
	state := &DatabaseHookContext{
		Operation: DatabaseCreate, Model: query.Model, Data: clonePluginRecord(query.Data),
	}
	if err := adapter.before(ctx, state); err != nil {
		return nil, err
	}
	query.Data = clonePluginRecord(state.Data)
	result, err := adapter.next.Create(ctx, query)
	if err != nil {
		return nil, err
	}
	state.Result = clonePluginRecord(result)
	if err := adapter.after(ctx, state); err != nil {
		return nil, err
	}
	return result, nil
}

func (adapter *hookedDatabaseAdapter) FindOne(ctx context.Context, query FindOneQuery) (Record, error) {
	return adapter.next.FindOne(ctx, query)
}

func (adapter *hookedDatabaseAdapter) FindMany(ctx context.Context, query FindManyQuery) ([]Record, error) {
	return adapter.next.FindMany(ctx, query)
}

func (adapter *hookedDatabaseAdapter) Count(ctx context.Context, query CountQuery) (int64, error) {
	return adapter.next.Count(ctx, query)
}

func (adapter *hookedDatabaseAdapter) Update(ctx context.Context, query UpdateQuery) (Record, error) {
	state := &DatabaseHookContext{
		Operation: DatabaseUpdate, Model: query.Model,
		Where: slices.Clone(query.Where), Data: clonePluginRecord(query.Update),
	}
	if err := adapter.before(ctx, state); err != nil {
		return nil, err
	}
	query.Where, query.Update = slices.Clone(state.Where), clonePluginRecord(state.Data)
	result, err := adapter.next.Update(ctx, query)
	if err != nil {
		return nil, err
	}
	state.Result = clonePluginRecord(result)
	if err := adapter.after(ctx, state); err != nil {
		return nil, err
	}
	return result, nil
}

func (adapter *hookedDatabaseAdapter) UpdateMany(ctx context.Context, query UpdateQuery) (int64, error) {
	state := &DatabaseHookContext{
		Operation: DatabaseUpdateMany, Model: query.Model,
		Where: slices.Clone(query.Where), Data: clonePluginRecord(query.Update),
	}
	if err := adapter.before(ctx, state); err != nil {
		return 0, err
	}
	query.Where, query.Update = slices.Clone(state.Where), clonePluginRecord(state.Data)
	count, err := adapter.next.UpdateMany(ctx, query)
	if err != nil {
		return 0, err
	}
	state.Count = count
	if err := adapter.after(ctx, state); err != nil {
		return 0, err
	}
	return count, nil
}

func (adapter *hookedDatabaseAdapter) Delete(ctx context.Context, query DeleteQuery) error {
	state := &DatabaseHookContext{
		Operation: DatabaseDelete, Model: query.Model, Where: slices.Clone(query.Where),
	}
	if err := adapter.before(ctx, state); err != nil {
		return err
	}
	query.Where = slices.Clone(state.Where)
	if err := adapter.next.Delete(ctx, query); err != nil {
		return err
	}
	state.Count = 1
	return adapter.after(ctx, state)
}

func (adapter *hookedDatabaseAdapter) DeleteMany(ctx context.Context, query DeleteQuery) (int64, error) {
	state := &DatabaseHookContext{
		Operation: DatabaseDeleteMany, Model: query.Model, Where: slices.Clone(query.Where),
	}
	if err := adapter.before(ctx, state); err != nil {
		return 0, err
	}
	query.Where = slices.Clone(state.Where)
	count, err := adapter.next.DeleteMany(ctx, query)
	if err != nil {
		return 0, err
	}
	state.Count = count
	if err := adapter.after(ctx, state); err != nil {
		return 0, err
	}
	return count, nil
}

func (adapter *hookedDatabaseAdapter) ConsumeOne(ctx context.Context, query DeleteQuery) (Record, error) {
	state := &DatabaseHookContext{
		Operation: DatabaseConsumeOne, Model: query.Model, Where: slices.Clone(query.Where),
	}
	if err := adapter.before(ctx, state); err != nil {
		return nil, err
	}
	query.Where = slices.Clone(state.Where)
	result, err := adapter.next.ConsumeOne(ctx, query)
	if err != nil {
		return nil, err
	}
	state.Result = clonePluginRecord(result)
	if err := adapter.after(ctx, state); err != nil {
		return nil, err
	}
	return result, nil
}

func (adapter *hookedDatabaseAdapter) IncrementOne(ctx context.Context, query IncrementQuery) (Record, error) {
	state := &DatabaseHookContext{
		Operation: DatabaseIncrementOne, Model: query.Model,
		Where: slices.Clone(query.Where), Data: clonePluginRecord(query.Set),
		Increment: clonePluginIncrement(query.Increment),
	}
	if err := adapter.before(ctx, state); err != nil {
		return nil, err
	}
	query.Where, query.Set, query.Increment =
		slices.Clone(state.Where), clonePluginRecord(state.Data), clonePluginIncrement(state.Increment)
	result, err := adapter.next.IncrementOne(ctx, query)
	if err != nil {
		return nil, err
	}
	state.Result = clonePluginRecord(result)
	if err := adapter.after(ctx, state); err != nil {
		return nil, err
	}
	return result, nil
}

func (adapter *hookedDatabaseAdapter) Transaction(ctx context.Context, callback func(DatabaseAdapter) error) error {
	if adapter.deferred != nil {
		return adapter.next.Transaction(ctx, func(transaction DatabaseAdapter) error {
			return callback(&hookedDatabaseAdapter{
				next: transaction, hooks: adapter.hooks, deferred: adapter.deferred,
			})
		})
	}
	deferred := make([]deferredDatabaseHook, 0)
	err := adapter.next.Transaction(ctx, func(transaction DatabaseAdapter) error {
		return callback(&hookedDatabaseAdapter{
			next: transaction, hooks: adapter.hooks, deferred: &deferred,
		})
	})
	if err != nil {
		return err
	}
	// The database has committed successfully. From this point an after-hook
	// failure cannot and must not pretend the transaction rolled back.
	for _, effect := range deferred {
		if err := callDatabaseHook(effect.ctx, effect.registration,
			effect.registration.hook.After, effect.state); err != nil {
			return fmt.Errorf("betterauth: database committed but after hook failed: %w", err)
		}
	}
	return nil
}

func (adapter *hookedDatabaseAdapter) before(ctx context.Context, state *DatabaseHookContext) error {
	for _, registration := range adapter.hooks {
		if !registration.matches(state) || registration.hook.Before == nil {
			continue
		}
		if err := callDatabaseHook(ctx, registration, registration.hook.Before, state); err != nil {
			return err
		}
	}
	return nil
}

func (adapter *hookedDatabaseAdapter) after(ctx context.Context, state *DatabaseHookContext) error {
	for _, registration := range adapter.hooks {
		if !registration.matches(state) || registration.hook.After == nil {
			continue
		}
		if adapter.deferred != nil {
			*adapter.deferred = append(*adapter.deferred, deferredDatabaseHook{
				ctx: ctx, registration: registration, state: cloneDatabaseHookContext(state),
			})
			continue
		}
		if err := callDatabaseHook(ctx, registration, registration.hook.After, state); err != nil {
			return err
		}
	}
	return nil
}

func cloneDatabaseHookContext(state *DatabaseHookContext) *DatabaseHookContext {
	return &DatabaseHookContext{
		Operation: state.Operation, Model: state.Model, Count: state.Count,
		Where: slices.Clone(state.Where), Data: clonePluginRecord(state.Data),
		Increment: clonePluginIncrement(state.Increment), Result: clonePluginRecord(state.Result),
	}
}

func (registration databaseHookRegistration) matches(state *DatabaseHookContext) bool {
	if registration.hook.Model != "*" && registration.hook.Model != state.Model {
		return false
	}
	return len(registration.hook.Operations) == 0 || slices.Contains(registration.hook.Operations, state.Operation)
}

func callDatabaseHook(
	ctx context.Context,
	registration databaseHookRegistration,
	handler DatabaseHookHandler,
	state *DatabaseHookContext,
) (err error) {
	defer func() {
		if recover() != nil {
			err = fmt.Errorf("betterauth: plugin %q database hook panicked", registration.pluginID)
		}
	}()
	copyState := cloneDatabaseHookContext(state)
	if err := handler(ctx, copyState); err != nil {
		return fmt.Errorf("betterauth: plugin %q database hook: %w", registration.pluginID, err)
	}
	state.Where, state.Data, state.Increment, state.Result, state.Count =
		slices.Clone(copyState.Where), clonePluginRecord(copyState.Data),
		clonePluginIncrement(copyState.Increment), clonePluginRecord(copyState.Result), copyState.Count
	return nil
}

func clonePluginIncrement(values map[string]float64) map[string]float64 {
	if values == nil {
		return nil
	}
	result := make(map[string]float64, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}

func validDatabaseOperation(operation DatabaseOperation) bool {
	switch operation {
	case DatabaseCreate, DatabaseUpdate, DatabaseUpdateMany, DatabaseDelete,
		DatabaseDeleteMany, DatabaseConsumeOne, DatabaseIncrementOne:
		return true
	default:
		return false
	}
}

func clonePluginRecord(record Record) Record {
	if record == nil {
		return nil
	}
	result := make(Record, len(record))
	for key, value := range record {
		result[key] = clonePluginValue(value)
	}
	return result
}

func clonePluginValue(value any) any {
	switch typed := value.(type) {
	case Record:
		return clonePluginRecord(typed)
	case map[string]any:
		result := make(map[string]any, len(typed))
		for key, child := range typed {
			result[key] = clonePluginValue(child)
		}
		return result
	case []any:
		result := make([]any, len(typed))
		for index, child := range typed {
			result[index] = clonePluginValue(child)
		}
		return result
	case []string:
		return slices.Clone(typed)
	default:
		return value
	}
}
