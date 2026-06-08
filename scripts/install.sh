#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "AgentSnitch install"
echo "  scope: Claude Code hook registration"
echo "  settings: ${CLAUDE_SETTINGS:-$HOME/.claude/settings.json}"
echo ""

make build-emitter build-hookctl build-agentsnitch

SUPPORT_DIR="${AGENTSNITCH_SUPPORT_DIR:-$HOME/Library/Application Support/AgentSnitch}"
SUPPORT_BIN="$SUPPORT_DIR/bin"
HOOKCTL="$ROOT/bin/hookctl"
EMITTER="$ROOT/bin/emitter"

if [[ -x "$SUPPORT_BIN/hookctl" && -x "$SUPPORT_BIN/emitter" ]]; then
  HOOKCTL="$SUPPORT_BIN/hookctl"
  EMITTER="$SUPPORT_BIN/emitter"
fi

"$HOOKCTL" --emitter "$EMITTER" install

echo ""
echo "Hook install complete. Start or restart Claude Code, then run:"
echo "  make doctor"
echo ""
echo "Network Extension activation/signing is handled separately by:"
echo "  make ne-ready"
echo ""
echo "Advanced HTTPS Inspect Mode never installs a root CA during hook install."
echo "If enabled later, system trust install/removal is an explicit macOS-admin-approved action."
