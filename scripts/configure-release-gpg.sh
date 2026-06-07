#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: scripts/configure-release-gpg.sh <release-key-fingerprint-or-key-id>

Configures this checkout for GPG-signed release tags and stores the trusted
release public key in the GitHub release-signing environment secret
RELEASE_GPG_PUBLIC_KEY.
EOF
}

if [[ $# -ne 1 ]]; then
  usage
  exit 64
fi

key_ref="$1"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

command -v gpg >/dev/null || {
  echo "gpg is required" >&2
  exit 1
}

command -v gh >/dev/null || {
  echo "gh is required" >&2
  exit 1
}

fingerprint="$(
  gpg --batch --with-colons --fingerprint --list-secret-keys "$key_ref" |
    awk -F: '$1 == "fpr" { print $10; exit }'
)"

if [[ -z "$fingerprint" ]]; then
  echo "No local GPG secret key found for: $key_ref" >&2
  echo "Import or create the real release signing key before running this script." >&2
  exit 1
fi

public_key="$(gpg --batch --armor --export "$fingerprint")"
if [[ -z "$public_key" ]]; then
  echo "Failed to export public key for: $fingerprint" >&2
  exit 1
fi

gh auth status >/dev/null
printf '%s\n' "$public_key" | gh secret set RELEASE_GPG_PUBLIC_KEY \
  --env release-signing

git -C "$repo_root" config gpg.format openpgp
git -C "$repo_root" config user.signingkey "$fingerprint"
git -C "$repo_root" config tag.gpgSign true

echo "Configured release GPG key: $fingerprint"
echo "Updated GitHub environment secret: release-signing/RELEASE_GPG_PUBLIC_KEY"
