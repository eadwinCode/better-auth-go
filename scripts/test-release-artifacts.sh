#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
temporary_root="$(mktemp -d)"
cleanup() {
  rm -rf "${temporary_root}"
}
trap cleanup EXIT INT TERM

version="v1.0.0-rc.1"
if ALLOW_UNTAGGED_RELEASE_ARTIFACTS=true \
  RELEASE_COMMIT=HEAD \
  "${repository_root}/scripts/build-release-artifacts.sh" "1.0.0" "${temporary_root}/invalid"; then
  echo "artifact builder accepted an unversioned release" >&2
  exit 1
fi
ALLOW_UNTAGGED_RELEASE_ARTIFACTS=true \
RELEASE_COMMIT=HEAD \
  "${repository_root}/scripts/build-release-artifacts.sh" "${version}" "${temporary_root}"

sbom="${temporary_root}/better-auth-go_1.0.0-rc.1_sbom.spdx.json"
printf '{"spdxVersion":"SPDX-2.3","name":"release-script-fixture"}\n' >"${sbom}"
"${repository_root}/scripts/write-release-checksums.sh" "${version}" "${temporary_root}"

tar_listing="$(tar -tzf "${temporary_root}/better-auth-go_1.0.0-rc.1_source.tar.gz")"
zip_listing="$(unzip -Z1 "${temporary_root}/better-auth-go_1.0.0-rc.1_source.zip")"
grep -qx 'better-auth-go-1.0.0-rc.1/go.mod' <<<"${tar_listing}"
grep -qx 'better-auth-go-1.0.0-rc.1/go.mod' <<<"${zip_listing}"
if grep -Eq '(^|/)\.git(/|$)' <<<"${tar_listing}${zip_listing}"; then
  echo "release archive contains Git metadata" >&2
  exit 1
fi

(
  cd "${temporary_root}"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum --check better-auth-go_1.0.0-rc.1_checksums.txt
  else
    shasum -a 256 -c better-auth-go_1.0.0-rc.1_checksums.txt
  fi
)

if find "${temporary_root}" -type f -name '*v1.0.0-rc.1*' | grep -q .; then
  echo "artifact filenames must use the normalized version without a duplicate v" >&2
  exit 1
fi

echo "Release archive and checksum contract passed."
