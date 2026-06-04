#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "AgentSnitch install"
echo "  scope: Claude Code hook registration"
echo "  settings: ${CLAUDE_SETTINGS:-$HOME/.claude/settings.json}"
echo ""

make build-emitter build-hookctl
"$ROOT/bin/hookctl" --emitter "$ROOT/bin/emitter" install

echo ""
echo "Hook install complete. Start or restart Claude Code, then run:"
echo "  make doctor"
echo ""
echo "Network Extension activation/signing is handled separately by:"
echo "  make ne-ready"
