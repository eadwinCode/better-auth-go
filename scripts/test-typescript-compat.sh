#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
typescript_root="${BETTER_AUTH_TS_DIR:-${repository_root}/compat/typescript-oracle}"
compatibility_port="${BETTER_AUTH_TS_PORT:-43125}"

if [[ ! -f "${typescript_root}/package.json" ]]; then
  echo "Better Auth TypeScript oracle not found at ${typescript_root}" >&2
  echo "Set BETTER_AUTH_TS_DIR to its directory." >&2
  exit 1
fi

temporary_root="$(mktemp -d)"
oracle_log="${temporary_root}/oracle.log"
oracle_pid=""

cleanup() {
  if [[ -n "${oracle_pid}" ]]; then
    kill "${oracle_pid}" 2>/dev/null || true
    wait "${oracle_pid}" 2>/dev/null || true
  fi
  rm -rf "${temporary_root}"
}
trap cleanup EXIT INT TERM

oracle_url="http://127.0.0.1:${compatibility_port}"
export BETTER_AUTH_SECRET="better-auth-go-v1.6.25-compatibility-only-secret"
export BETTER_AUTH_TEST_CONTROL_SECRET="better-auth-go-test-control-only-secret"
export BETTER_AUTH_URL="${oracle_url}"
export BETTER_AUTH_BASE_PATH="/api/auth"
export BETTER_AUTH_TRUSTED_ORIGINS="${oracle_url}"
export BETTER_AUTH_SECURE_COOKIES="false"
export BETTER_AUTH_DB="${temporary_root}/reference.sqlite"
export HOST="127.0.0.1"
export PORT="${compatibility_port}"

(
  cd "${typescript_root}"
  bun run typecheck
  bun run migrate
  bun run start
) >"${oracle_log}" 2>&1 &
oracle_pid="$!"

ready="false"
for _ in $(seq 1 100); do
  if curl --fail --silent "${oracle_url}/healthz" >/dev/null 2>&1; then
    ready="true"
    break
  fi
  if ! kill -0 "${oracle_pid}" 2>/dev/null; then
    break
  fi
  sleep 0.1
done

if [[ "${ready}" != "true" ]]; then
  echo "TypeScript oracle failed to become ready:" >&2
  sed -n '1,200p' "${oracle_log}" >&2
  exit 1
fi

(
  cd "${repository_root}"
  BETTER_AUTH_TS_URL="${oracle_url}" \
  BETTER_AUTH_TS_CONTROL_SECRET="${BETTER_AUTH_TEST_CONTROL_SECRET}" \
    go test -count=1 -run '^TestBetterAuthV1625' ./compat
)
