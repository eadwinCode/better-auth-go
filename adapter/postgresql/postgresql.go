// Package postgresql provides the Better Auth PostgreSQL database adapter.
//
// Applications may open the *sql.DB with pgx/v5/stdlib or another compatible
// PostgreSQL database/sql driver.
package postgresql

import (
	"database/sql"

	"github.com/eadwinCode/better-auth-go/adapter/sqladapter"
)

// Options holds optional PostgreSQL adapter settings.
type Options struct {
	// SchemaName is the schema (namespace) that holds Better Auth's tables,
	// for example "auth". When set, every statement names its table as
	// "auth"."user", so the adapter no longer depends on the connection's
	// search_path, and Migrate runs CREATE SCHEMA IF NOT EXISTS before it
	// creates tables. It matches Better Auth's database.schemaName.
	SchemaName string
}

func New(db *sql.DB) (*sqladapter.Adapter, error) {
	return sqladapter.New(db, sqladapter.PostgreSQL)
}

// NewWithOptions is New with optional settings.
func NewWithOptions(db *sql.DB, options Options) (*sqladapter.Adapter, error) {
	return sqladapter.NewWithOptions(db, sqladapter.PostgreSQL, sqladapter.Options{
		SchemaName: options.SchemaName,
	})
}
