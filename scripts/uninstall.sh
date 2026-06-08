#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "AgentSnitch uninstall"
echo "  scope: Claude Code hook registration"
echo "  settings: ${CLAUDE_SETTINGS:-$HOME/.claude/settings.json}"
echo ""

make build-hookctl
"$ROOT/bin/hookctl" --emitter "$ROOT/bin/emitter" uninstall

LAUNCH_AGENT_LABEL="${AGENTSNITCH_LAUNCH_AGENT_LABEL:-com.somoore.agentsnitch.daemon}"
LAUNCH_AGENT_PLIST="$HOME/Library/LaunchAgents/$LAUNCH_AGENT_LABEL.plist"
SYSTEM_LAUNCH_AGENT_PLIST="/Library/LaunchAgents/$LAUNCH_AGENT_LABEL.plist"
SUPPORT_DIR="${AGENTSNITCH_SUPPORT_DIR:-$HOME/Library/Application Support/AgentSnitch}"
SYSTEM_SUPPORT_DIR="/Library/Application Support/AgentSnitch"
INSPECT_CLI="$SUPPORT_DIR/bin/agentsnitchctl"
if [[ ! -x "$INSPECT_CLI" && -x "$ROOT/bin/agentsnitchctl" ]]; then
  INSPECT_CLI="$ROOT/bin/agentsnitchctl"
fi

require_agentsnitch_path_for_delete() {
  path="$1"
  if [ -z "$path" ] || [ "$path" = "/" ]; then
    echo "Refusing unsafe delete path: $path" >&2
    exit 1
  fi
  case "$path" in
    *AgentSnitch*|*agentsnitch*) ;;
    *)
      echo "Refusing delete outside an AgentSnitch-specific path: $path" >&2
      exit 1
      ;;
  esac
}

# --- Network Extension teardown ------------------------------------------------
# The opt-in Network Extension installs a system content filter. Uninstalling
# must not leave that filter behind: a user uninstalling to ESCAPE a network
# problem would otherwise still have the filter active. We set the app-side
# kill switch first, then tear down via the OS CLI (no dependency on the
# possibly-unhealthy app), and always print the manual escape hatch so the user
# is never left guessing.
EXT_BUNDLE_ID="${AGENTSNITCH_EXT_BUNDLE_ID:-com.somoore.agentsnitch.network-extension}"

echo ""
echo "Network Extension teardown:"
launchctl setenv AGENTSNITCH_DISABLE_NETWORK_EXTENSION 1 >/dev/null 2>&1 || true
echo "  Set AGENTSNITCH_DISABLE_NETWORK_EXTENSION=1 for this user session."
if command -v systemextensionsctl >/dev/null 2>&1; then
  # Deactivation may require approval and only affects an activated extension;
  # tolerate "not found" / not-activated without failing the uninstall.
  if systemextensionsctl deactivate "$EXT_BUNDLE_ID" >/dev/null 2>&1; then
    echo "  Requested deactivation of system extension: $EXT_BUNDLE_ID"
  else
    echo "  No active system extension to deactivate (or deactivation needs approval)."
  fi
else
  echo "  systemextensionsctl not available; skipping extension deactivation."
fi

if [[ -f "$LAUNCH_AGENT_PLIST" ]]; then
  launchctl bootout "gui/$UID" "$LAUNCH_AGENT_PLIST" >/dev/null 2>&1 || true
  rm -f "$LAUNCH_AGENT_PLIST"
  echo "Removed daemon LaunchAgent: $LAUNCH_AGENT_PLIST"
fi

if [[ -f "$SYSTEM_LAUNCH_AGENT_PLIST" ]]; then
  launchctl bootout "gui/$UID" "$SYSTEM_LAUNCH_AGENT_PLIST" >/dev/null 2>&1 || true
  if rm -f "$SYSTEM_LAUNCH_AGENT_PLIST" 2>/dev/null; then
    echo "Removed daemon LaunchAgent: $SYSTEM_LAUNCH_AGENT_PLIST"
  else
    echo "System LaunchAgent remains: $SYSTEM_LAUNCH_AGENT_PLIST"
    echo "  Remove with sudo if this was installed from a package."
  fi
fi

echo ""
echo "HTTPS Inspect CA teardown:"
if [[ -x "$INSPECT_CLI" ]]; then
  if "$INSPECT_CLI" inspect status 2>/dev/null | grep -q '"system_trusted": true'; then
    echo "  AgentSnitch CA appears to be installed in macOS System trust."
    echo "  Requesting admin-approved removal now."
    if "$INSPECT_CLI" inspect untrust-system; then
      echo "  Removed AgentSnitch CA from macOS System trust."
    else
      echo "  Could not remove system trust automatically."
      echo "  Open Keychain Access > System and remove the AgentSnitch Local HTTPS Inspection CA."
    fi
  else
    echo "  No AgentSnitch CA detected in macOS System trust."
  fi
  "$INSPECT_CLI" inspect disable --remove-process-trust=true --purge-data=true >/dev/null 2>&1 || true
else
  echo "  agentsnitchctl inspect helper not available; skipping automatic CA trust check."
  echo "  If you enabled system trust, open Keychain Access > System and remove the AgentSnitch Local HTTPS Inspection CA."
fi

if [[ -d "$SUPPORT_DIR" ]]; then
  require_agentsnitch_path_for_delete "$SUPPORT_DIR"
  rm -rf "$SUPPORT_DIR"
  echo "Removed support binaries: $SUPPORT_DIR"
fi

if [[ -d "$SYSTEM_SUPPORT_DIR" ]]; then
  require_agentsnitch_path_for_delete "$SYSTEM_SUPPORT_DIR"
  if rm -rf "$SYSTEM_SUPPORT_DIR" 2>/dev/null; then
    echo "Removed support binaries: $SYSTEM_SUPPORT_DIR"
  else
    echo "System support binaries remain: $SYSTEM_SUPPORT_DIR"
    echo "  Remove with sudo if this was installed from a package."
  fi
fi

cat <<'EOF'

If a network content filter remains (or you ever lose connectivity):
  - Open System Settings > Network > Filters and remove "AgentSnitch".
  - Or run: systemextensionsctl list   (then deactivate the agentsnitch entry).
  - As a last resort, reboot into Safe Mode — third-party content filters do
    not load there — then remove the filter.
The Network Extension is metadata-only and fail-open, but these steps guarantee
you can always restore your network independently of AgentSnitch.
EOF

echo ""
echo "AgentSnitch hooks and daemon support files removed. Other Claude settings were preserved."
