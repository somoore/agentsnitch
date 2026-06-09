#!/usr/bin/env bash
set -euo pipefail

ENVIRONMENT_NAME="${1:-release-signing}"
REPO="${GITHUB_REPOSITORY:-${GITHUB_OWNER:-}/${GITHUB_REPO:-}}"
ALT_REPO="${2:-}"

if [ -z "$REPO" ] || [ "$REPO" = "/" ]; then
  echo "GITHUB_REPOSITORY is not set. Set it or pass owner/repo explicitly as 2nd arg?" >&2
  echo "Usage: $0 [environment] [owner/repo]" >&2
  exit 1
fi

if [ -n "$ALT_REPO" ]; then
  REPO="$2"
fi

payload="{\"wait_timer\":0,\"reviewers\":[],\"prevent_self_review\":false}"

gh api -X PUT "repos/$REPO/environments/$ENVIRONMENT_NAME" -H "Accept: application/vnd.github+json" --input - <<<"$payload" >/tmp/release-env.json

echo "release-signing environment guard cleared for '$ENVIRONMENT_NAME' in $REPO"
cat /tmp/release-env.json
rm -f /tmp/release-env.json
