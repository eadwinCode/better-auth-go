#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
module_path="github.com/eadwinCode/better-auth-go"
module_ref="${1:-}"

if [[ -z "${module_ref}" ]]; then
  echo "usage: scripts/test-install-module.sh <tag-or-commit>" >&2
  exit 2
fi

temporary_root="$(mktemp -d)"
cleanup() {
  rm -rf "${temporary_root}"
}
trap cleanup EXIT INT TERM

cp "${repository_root}/examples/installcheck/main.go" "${temporary_root}/main.go"

(
  cd "${temporary_root}"
  go mod init example.com/better-auth-go-installcheck
  go get "${module_path}@${module_ref}"
  go mod tidy
  if grep -Eq '^[[:space:]]*replace[[:space:]]' go.mod; then
    echo "install check must not use a local replace directive" >&2
    exit 1
  fi
  resolved_version="$(go list -m -f '{{.Version}}' "${module_path}")"
  if [[ "${module_ref}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?$ ]] &&
    [[ "${resolved_version}" != "${module_ref}" ]]; then
    echo "resolved ${resolved_version}; expected exact tag ${module_ref}" >&2
    exit 1
  fi
  go test -count=1 ./...
  echo "External module resolved ${module_path}@${resolved_version} without replace."
)
