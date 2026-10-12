package betterauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// SchemaChecker is an optional DatabaseAdapter extension. An adapter that can
// read its live database schema implements it so the Server can find missing
// tables and columns before requests fail in confusing ways.
//
// CheckSchema compares the live database with schema, the merged logical
// schema from Server.Schema. It returns every problem it finds, or an error
// when the database could not be read. DiffSchema does the comparison once an
// adapter has read its tables.
type SchemaChecker interface {
	CheckSchema(ctx context.Context, schema Schema) ([]SchemaFinding, error)
}

// SchemaFindingKind names one kind of schema problem.
type SchemaFindingKind string

const (
	// SchemaFindingMissingTable means a table Better Auth writes does not exist.
	SchemaFindingMissingTable SchemaFindingKind = "missing-table"
	// SchemaFindingMissingColumn means a column Better Auth writes does not exist.
	SchemaFindingMissingColumn SchemaFindingKind = "missing-column"
	// SchemaFindingUnexpectedRequiredColumn means a column Better Auth never
	// writes is NOT NULL and has no default, so every insert into its table fails.
	SchemaFindingUnexpectedRequiredColumn SchemaFindingKind = "unexpected-required-column"
)

// SchemaFinding is one problem in the live database schema. Table and Column
// are the stored (physical) names. Column is empty for a missing table.
type SchemaFinding struct {
	Kind   SchemaFindingKind
	Table  string
	Column string
}

const (
	schemaApplyHint   = "Run the adapter's Migrate with Server.Schema() to add it."
	schemaRelaxHint   = "Drop the column, make it nullable, or give it a database default."
	schemaRepairHint  = "Make the listed columns nullable, give them defaults, or remove them."
	schemaMigrateHint = "Run the adapter's Migrate with Server.Schema() to add the missing " +
		"tables and columns."
	schemaUpgradeGuide = "https://www.better-auth.com/docs/guides/1-7-upgrade-guide"
)

// String describes the finding and the change that fixes it.
func (finding SchemaFinding) String() string {
	switch finding.Kind {
	case SchemaFindingMissingTable:
		return fmt.Sprintf("Table %q is missing. %s", finding.Table, schemaApplyHint)
	case SchemaFindingMissingColumn:
		return fmt.Sprintf(
			"Column %q is missing from table %q. %s", finding.Column, finding.Table, schemaApplyHint,
		)
	case SchemaFindingUnexpectedRequiredColumn:
		issuer := ""
		if finding.Column == "issuer" {
			issuer = " If this column came from Better Auth 1.7.0 through 1.7.2, follow the " +
				"upgrade guide before removing it: " + schemaUpgradeGuide
		}
		return fmt.Sprintf(
			"Column %q on table %q is required but Better Auth never writes it, so every "+
				"insert into %q fails. %s%s",
			finding.Column, finding.Table, finding.Table, schemaRelaxHint, issuer,
		)
	default:
		return fmt.Sprintf("Unknown schema finding %q on table %q.", finding.Kind, finding.Table)
	}
}

// SchemaMismatchError reports that the database cannot hold what Better Auth
// writes. Findings lists every problem; Error lists each one with the change
// that fixes it.
type SchemaMismatchError struct {
	Findings []SchemaFinding
}

// Code matches the Better Auth error code for this failure.
func (err *SchemaMismatchError) Code() string { return "SCHEMA_MISMATCH" }

func (err *SchemaMismatchError) Error() string {
	var tables, columns, required, affected []string
	seen := map[string]bool{}
	hasIssuer := false
	for _, finding := range err.Findings {
		switch finding.Kind {
		case SchemaFindingMissingTable:
			tables = append(tables, finding.Table)
		case SchemaFindingMissingColumn:
			columns = append(columns, finding.Table+"."+finding.Column)
		case SchemaFindingUnexpectedRequiredColumn:
			required = append(required, finding.Table+"."+finding.Column)
			if !seen[finding.Table] {
				seen[finding.Table] = true
				affected = append(affected, finding.Table)
			}
			hasIssuer = hasIssuer || finding.Column == "issuer"
		}
	}
	sections := []string{"Database schema mismatch"}
	if len(tables) > 0 {
		sections = append(sections, "  Missing tables\n    "+strings.Join(tables, ", "))
	}
	if len(columns) > 0 {
		sections = append(sections, "  Missing columns\n    "+strings.Join(columns, "\n    "))
	}
	if len(required) > 0 {
		sections = append(sections,
			"  Required columns Better Auth never writes\n    "+strings.Join(required, "\n    "),
			"  Inserts into "+strings.Join(affected, ", ")+" will fail.",
		)
	}
	var help []string
	if len(required) > 0 {
		help = append(help, schemaRepairHint)
	}
	if len(tables) > 0 || len(columns) > 0 {
		help = append(help, schemaMigrateHint)
	}
	if len(help) > 0 {
		sections = append(sections, "  help: "+strings.Join(help, "\n        "))
	}
	if hasIssuer {
		sections = append(sections,
			"  note: If this column came from Better Auth 1.7.0 through 1.7.2,\n"+
				"        follow the upgrade guide before removing it:\n"+
				"        "+schemaUpgradeGuide,
		)
	}
	return strings.Join(sections, "\n\n")
}

// IntrospectedColumn is a column as the live database reports it.
type IntrospectedColumn struct {
	Name     string
	Nullable bool
	// HasDefault is true when the database fills the column when an insert
	// leaves it out (a default, identity, or auto-increment column).
	HasDefault bool
}

// IntrospectedTable is a table as the live database reports it.
type IntrospectedTable struct {
	Name    string
	Columns []IntrospectedColumn
}

// ExpectedTable is one stored table Better Auth writes, with the stored id
// column first and then every other stored column in sorted order.
type ExpectedTable struct {
	Name    string
	Columns []string
}

// ExpectedTables returns the stored tables and columns that schema writes,
// sorted by table name. Models that share a stored table name are merged.
func ExpectedTables(schema Schema) []ExpectedTable {
	type entry struct {
		id     string
		fields map[string]bool
	}
	byName := map[string]*entry{}
	for logicalName, model := range schema {
		name := model.ModelName
		if name == "" {
			name = logicalName
		}
		current := byName[name]
		if current == nil {
			current = &entry{id: "id", fields: map[string]bool{}}
			byName[name] = current
		}
		for logicalField, field := range model.Fields {
			stored := field.FieldName
			if stored == "" {
				stored = logicalField
			}
			if logicalField == "id" {
				current.id = stored
			}
			current.fields[stored] = true
		}
	}
	result := make([]ExpectedTable, 0, len(byName))
	for name, current := range byName {
		columns := []string{current.id}
		others := make([]string, 0, len(current.fields))
		for field := range current.fields {
			if field != current.id {
				others = append(others, field)
			}
		}
		sort.Strings(others)
		result = append(result, ExpectedTable{Name: name, Columns: append(columns, others...)})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result
}

// DiffSchema compares the tables schema writes with what the database holds.
//
// A table or column Better Auth writes must exist. A column Better Auth does
// not write must accept an insert that leaves it out, so it must be nullable
// or have a default. Otherwise every insert into that table fails with a
// constraint error that does not say why. tables may hold only the tables the
// adapter looked up; a table not in the list counts as missing.
func DiffSchema(schema Schema, tables []IntrospectedTable) []SchemaFinding {
	findings := make([]SchemaFinding, 0)
	for _, expected := range ExpectedTables(schema) {
		index := slices.IndexFunc(tables, func(table IntrospectedTable) bool {
			return table.Name == expected.Name
		})
		if index < 0 {
			findings = append(findings, SchemaFinding{Kind: SchemaFindingMissingTable, Table: expected.Name})
			continue
		}
		actual := tables[index]
		written := make(map[string]bool, len(expected.Columns))
		for _, column := range expected.Columns {
			written[column] = true
		}
		present := make(map[string]bool, len(actual.Columns))
		for _, column := range actual.Columns {
			present[column.Name] = true
		}
		for _, column := range expected.Columns {
			if !present[column] {
				findings = append(findings, SchemaFinding{
					Kind: SchemaFindingMissingColumn, Table: expected.Name, Column: column,
				})
			}
		}
		for _, column := range actual.Columns {
			if written[column.Name] || column.Nullable || column.HasDefault {
				continue
			}
			findings = append(findings, SchemaFinding{
				Kind: SchemaFindingUnexpectedRequiredColumn, Table: expected.Name, Column: column.Name,
			})
		}
	}
	return findings
}

// CheckSchema checks the live database schema against Server.Schema when the
// adapter implements SchemaChecker. It returns a *SchemaMismatchError when
// the schema is wrong, the database error when the check could not run, and
// nil when the schema is fine or the adapter cannot check it (for example the
// memory and MongoDB adapters).
//
// A clean result is kept, so later calls and requests do not ask the
// database again. A failed result is not kept: the next call checks again,
// so running Migrate fixes requests without a restart. CheckSchema runs even
// when Config.DisableSchemaValidation is set.
func (s *Server) CheckSchema(ctx context.Context) error {
	if ctx == nil {
		return errors.New("betterauth: check schema: nil context")
	}
	if s.schemaChecker == nil {
		return nil
	}
	return s.schemaGate.check(ctx, func(ctx context.Context) error {
		findings, err := s.schemaChecker.CheckSchema(ctx, s.Schema())
		if err != nil {
			return err
		}
		if len(findings) > 0 {
			return &SchemaMismatchError{Findings: findings}
		}
		return nil
	})
}

// requireSchema is the request gate. It is a no-op when validation is turned
// off or the adapter cannot check its schema.
func (s *Server) requireSchema(ctx context.Context) error {
	if s.cfg.DisableSchemaValidation {
		return nil
	}
	return s.CheckSchema(ctx)
}

// schemaRequestError turns a failed schema check into the HTTP error. The
// public message carries no table or column names; the full details stay on
// the wrapped *SchemaMismatchError for logs and response hooks.
func schemaRequestError(err error) error {
	var mismatch *SchemaMismatchError
	if errors.As(err, &mismatch) {
		return publicError(
			CodeSchemaMismatch,
			"The database schema does not match what Better Auth needs.",
			http.StatusInternalServerError,
			err,
		)
	}
	return err
}

// schemaGate runs one schema check at a time and keeps only a clean result.
// Callers that arrive while a check runs wait for it and share its result.
type schemaGate struct {
	clean   atomic.Bool
	mu      sync.Mutex
	pending *schemaCall
}

type schemaCall struct {
	done     chan struct{}
	err      error
	canceled bool
}

func (gate *schemaGate) check(ctx context.Context, run func(context.Context) error) error {
	for {
		if gate.clean.Load() {
			return nil
		}
		gate.mu.Lock()
		if gate.clean.Load() {
			gate.mu.Unlock()
			return nil
		}
		call := gate.pending
		leader := call == nil
		if leader {
			call = &schemaCall{done: make(chan struct{})}
			gate.pending = call
		}
		gate.mu.Unlock()

		if leader {
			call.err = run(ctx)
			call.canceled = call.err != nil && ctx.Err() != nil
			gate.mu.Lock()
			if call.err == nil {
				gate.clean.Store(true)
			}
			gate.pending = nil
			gate.mu.Unlock()
			close(call.done)
			return call.err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-call.done:
		}
		// The leader's own request was canceled; that says nothing about
		// the schema, so check again for this caller.
		if call.canceled {
			continue
		}
		return call.err
	}
}
