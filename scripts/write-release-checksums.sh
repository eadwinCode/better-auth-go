#!/usr/bin/env bash
set -euo pipefail

version="${1:-}"
output_root="${2:-dist}"

if [[ ! "${version}" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-rc\.(0|[1-9][0-9]*))?$ ]]; then
  echo "release version must be vMAJOR.MINOR.PATCH or vMAJOR.MINOR.PATCH-rc.N" >&2
  exit 2
fi
if [[ ! -d "${output_root}" ]]; then
  echo "release output directory does not exist: ${output_root}" >&2
  exit 1
fi

plain_version="${version#v}"
checksum_name="better-auth-go_${plain_version}_checksums.txt"
checksum_path="${output_root}/${checksum_name}"
temporary_path="${checksum_path}.tmp"

(
  cd "${output_root}"
  find . -maxdepth 1 -type f \
    ! -name "${checksum_name}" \
    ! -name "${checksum_name}.tmp" \
    -print |
    sort |
    while IFS= read -r subject; do
      basename_value="$(basename "${subject}")"
      if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "${basename_value}"
      else
        shasum -a 256 "${basename_value}"
      fi
    done
) >"${temporary_path}"
if [[ ! -s "${temporary_path}" ]]; then
  rm -f "${temporary_path}"
  echo "no release artifacts found in ${output_root}" >&2
  exit 1
fi
mv "${temporary_path}" "${checksum_path}"

echo "Wrote ${checksum_path}."
