#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
version="${1:-}"
output_root="${2:-${repository_root}/dist}"

if [[ ! "${version}" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-rc\.(0|[1-9][0-9]*))?$ ]]; then
  echo "release version must be vMAJOR.MINOR.PATCH or vMAJOR.MINOR.PATCH-rc.N" >&2
  exit 2
fi

if [[ "${ALLOW_UNTAGGED_RELEASE_ARTIFACTS:-false}" == "true" ]]; then
  release_commit="${RELEASE_COMMIT:-HEAD}"
else
  release_commit="${version}^{commit}"
  tag_commit="$(git -C "${repository_root}" rev-parse "${version}^{commit}")"
  head_commit="$(git -C "${repository_root}" rev-parse HEAD)"
  if [[ "${tag_commit}" != "${head_commit}" ]]; then
    echo "release tag ${version} does not resolve to checked-out commit ${head_commit}" >&2
    exit 1
  fi
fi

git -C "${repository_root}" rev-parse --verify "${release_commit}" >/dev/null

plain_version="${version#v}"
archive_prefix="better-auth-go-${plain_version}/"
archive_base="better-auth-go_${plain_version}_source"

mkdir -p "${output_root}"
git -C "${repository_root}" archive \
  --format=tar \
  --prefix="${archive_prefix}" \
  "${release_commit}" |
  gzip -n >"${output_root}/${archive_base}.tar.gz"
git -C "${repository_root}" archive \
  --format=zip \
  --prefix="${archive_prefix}" \
  --output="${output_root}/${archive_base}.zip" \
  "${release_commit}"

echo "Created versioned source archives for ${version} from $(git -C "${repository_root}" rev-parse "${release_commit}")."
