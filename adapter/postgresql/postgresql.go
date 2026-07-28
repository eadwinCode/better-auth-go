// Package postgresql provides the Better Auth PostgreSQL database adapter.
//
// Applications may open the *sql.DB with pgx/v5/stdlib or another compatible
// PostgreSQL database/sql driver.
package postgresql

import (
	"database/sql"

	"github.com/eadwinCode/better-auth-go/adapter/sqladapter"
)

func New(db *sql.DB) (*sqladapter.Adapter, error) {
	return sqladapter.New(db, sqladapter.PostgreSQL)
}
