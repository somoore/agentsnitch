#!/usr/bin/env bash
set -euo pipefail

tag="${1:?missing tag name}"
out="${2:?missing output path}"
changelog="${3:-CHANGELOG.md}"

if [[ ! -f "$changelog" ]]; then
  cat > "$out" <<EOF
# Release ${tag}

No CHANGELOG.md found in this repository.

Release artifacts were built without changelog metadata.
EOF
  exit 0
fi

if awk -v tag="$tag" '
  BEGIN {
    in_section = 0
    found = 0
  }
  /^## \[/ {
    if (in_section) {
      exit 0
    }
  }
  $0 ~ "^## \\[" tag "\\]" {
    in_section = 1
    found = 1
  }
  in_section { print }
  END {
    if (!found) {
      exit 1
    }
  }
' "$changelog" > "$out"; then
  exit 0
fi

prev_tag="$(git describe --tags --abbrev=0 "${tag}^" 2>/dev/null || true)"

cat > "$out" <<EOF
# Release ${tag}

No section for ${tag} was found in ${changelog}. Falling back to recent commit history.
EOF

if [[ -n "${prev_tag}" ]]; then
  {
    echo
    echo "## Changes since ${prev_tag}"
    git log --no-color --no-merges --pretty='- %h %s' "${prev_tag}..${tag}" 2>/dev/null || true
  } >> "$out"
else
  {
    echo
    echo "## Recent commits"
    git log --no-color --no-merges --pretty='- %h %s' -n 20
  } >> "$out"
fi
