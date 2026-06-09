#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCHEMA_DIR="${1:-$ROOT_DIR/ui/src-tauri/gen/schemas}"

for schema in "$SCHEMA_DIR"/*.json; do
  [ -f "$schema" ] || continue
  perl -0pi -e 's/[\r\n]*\z/\n/' "$schema"
done
