#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
upstream_root="${BETTER_AUTH_UPSTREAM_DIR:-${repository_root}/../better-auth-repo}"
upstream_tag="v1.6.26"
expected_commit="a16b30e8437927c08350194000178073b06af8cf"

if [[ ! -d "${upstream_root}/.git" ]]; then
  echo "Better Auth upstream checkout not found at ${upstream_root}" >&2
  echo "Set BETTER_AUTH_UPSTREAM_DIR to its directory." >&2
  exit 1
fi

actual_commit="$(git -C "${upstream_root}" rev-parse "${upstream_tag}^{commit}")"
if [[ "${actual_commit}" != "${expected_commit}" ]]; then
  echo "${upstream_tag} resolved to ${actual_commit}; expected ${expected_commit}" >&2
  exit 1
fi

upstream_providers() {
  git -C "${upstream_root}" show \
    "${upstream_tag}:packages/core/src/social-providers/index.ts" |
    awk '
      /export const socialProviders = \{/ { inside = 1; next }
      inside && /^};/ { exit }
      inside {
        gsub(/[[:space:],]/, "")
        if (length($0) > 0) print $0
      }
    ' |
    sort
}

go_providers() {
  awk '
    /var SupportedProviders = \[\]string\{/ { inside = 1; next }
    inside && /^}/ { exit }
    inside { print }
  ' "${repository_root}/social/presets.go" |
    grep -o '"[^"]*"' |
    tr -d '"' |
    sort
}

if ! diff -u <(upstream_providers) <(go_providers); then
  echo "Go social-provider catalog differs from Better Auth ${upstream_tag}" >&2
  exit 1
fi

expected_builtin_plugins() {
  printf '%s\n' \
    access \
    admin \
    anonymous \
    bearer \
    captcha \
    custom-session \
    device-authorization \
    email-otp \
    generic-oauth \
    haveibeenpwned \
    jwt \
    last-login-method \
    magic-link \
    mcp \
    multi-session \
    oauth-popup \
    oauth-proxy \
    oidc-provider \
    one-tap \
    one-time-token \
    open-api \
    organization \
    phone-number \
    siwe \
    test-utils \
    two-factor \
    username |
    sort
}

upstream_builtin_plugins() {
  git -C "${upstream_root}" show \
    "${upstream_tag}:packages/better-auth/src/plugins/index.ts" |
    sed -n 's|^export \* from "\./\([^"]*\)";$|\1|p' |
    sort
}

if ! diff -u <(expected_builtin_plugins) <(upstream_builtin_plugins); then
  echo "Pinned built-in plugin inventory differs from Better Auth ${upstream_tag}" >&2
  exit 1
fi

while IFS='|' read -r package_directory package_name; do
  package_json="$(git -C "${upstream_root}" show \
    "${upstream_tag}:packages/${package_directory}/package.json")"
  actual_name="$(sed -n 's/^[[:space:]]*"name":[[:space:]]*"\([^"]*\)".*/\1/p' <<<"${package_json}" | head -1)"
  actual_version="$(sed -n 's/^[[:space:]]*"version":[[:space:]]*"\([^"]*\)".*/\1/p' <<<"${package_json}" | head -1)"
  if [[ "${actual_name}" != "${package_name}" || "${actual_version}" != "1.6.26" ]]; then
    echo "Unexpected pinned package ${package_directory}: ${actual_name}@${actual_version}" >&2
    exit 1
  fi
done <<'PACKAGES'
api-key|@better-auth/api-key
i18n|@better-auth/i18n
oauth-provider|@better-auth/oauth-provider
passkey|@better-auth/passkey
scim|@better-auth/scim
sso|@better-auth/sso
stripe|@better-auth/stripe
PACKAGES

echo "Better Auth ${upstream_tag} source inventory matches ${expected_commit}."
echo "Verified 35 social providers, 27 built-in plugin exports, and 7 plugin packages."
