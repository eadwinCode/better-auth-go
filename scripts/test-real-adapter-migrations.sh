#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${POSTGRES_DSN:-}" ]]; then
  echo "POSTGRES_DSN is required; release migration tests may not skip PostgreSQL" >&2
  exit 1
fi
if [[ -z "${MONGODB_URI:-}" ]]; then
  echo "MONGODB_URI is required; release migration tests may not skip MongoDB" >&2
  exit 1
fi

go test -race -count=1 ./adapter/sqlite
go test -race -count=1 ./adapter/postgresql
go test -race -count=1 ./adapter/mongodb
