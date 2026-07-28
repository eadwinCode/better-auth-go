// Package sqlite provides the Better Auth SQLite database adapter.
//
// The adapter accepts any database/sql SQLite driver with RETURNING support.
package sqlite

import (
	"database/sql"

	"github.com/eadwinCode/better-auth-go/adapter/sqladapter"
)

func New(db *sql.DB) (*sqladapter.Adapter, error) {
	return sqladapter.New(db, sqladapter.SQLite)
}
