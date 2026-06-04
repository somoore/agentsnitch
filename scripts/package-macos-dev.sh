#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_PATH="${AGENTSNITCH_APP_PATH:-/Applications/AgentSnitch.app}"
EXT_BUNDLE_ID="com.somoore.agentsnitch.network-extension"
EXT_NAME="$EXT_BUNDLE_ID.systemextension"
EXT_BUILD_PATH="${AGENTSNITCH_EXTENSION_BUILD_DIR:-$ROOT_DIR/extension/build}/$EXT_NAME"
HOST_BRIDGE_DYLIB="${AGENTSNITCH_EXTENSION_BUILD_DIR:-$ROOT_DIR/extension/build}/libAgentSnitchHostBridge.dylib"
DEST_DIR="$APP_PATH/Contents/Library/SystemExtensions"
DEST_EXT="$DEST_DIR/$EXT_NAME"
FRAMEWORKS_DIR="$APP_PATH/Contents/Frameworks"
DEST_HOST_BRIDGE="$FRAMEWORKS_DIR/libAgentSnitchHostBridge.dylib"

APP_SIGN_IDENTITY="${AGENTSNITCH_APP_SIGN_IDENTITY:--}"
EXT_SIGN_IDENTITY="${AGENTSNITCH_EXT_SIGN_IDENTITY:-$APP_SIGN_IDENTITY}"
HOST_PROFILE="${AGENTSNITCH_HOST_PROFILE:-${AGENTSNITCH_APP_PROFILE:-}}"
EXT_PROFILE="${AGENTSNITCH_EXTENSION_PROFILE:-${AGENTSNITCH_EXT_PROFILE:-}}"

if [[ "$APP_SIGN_IDENTITY" == "-" ]]; then
  APP_TIMESTAMP_ARGS=(--timestamp=none)
else
  APP_TIMESTAMP_ARGS=(--timestamp)
fi

if [[ "$EXT_SIGN_IDENTITY" == "-" ]]; then
  EXT_TIMESTAMP_ARGS=(--timestamp=none)
else
  EXT_TIMESTAMP_ARGS=(--timestamp)
fi

if [[ -n "${AGENTSNITCH_APP_ENTITLEMENTS:-}" ]]; then
  APP_ENTITLEMENTS="$AGENTSNITCH_APP_ENTITLEMENTS"
elif [[ "$APP_SIGN_IDENTITY" != "-" ]] && [[ -n "$HOST_PROFILE" ]]; then
  APP_ENTITLEMENTS="$ROOT_DIR/ui/src-tauri/entitlements.plist"
else
  APP_ENTITLEMENTS="$ROOT_DIR/ui/src-tauri/dev-entitlements.plist"
fi

if [[ ! -d "$APP_PATH" ]]; then
  echo "AgentSnitch app bundle not found: $APP_PATH" >&2
  echo "Set AGENTSNITCH_APP_PATH or install/build AgentSnitch.app first." >&2
  exit 1
fi

require_agentsnitch_path_for_delete() {
  local path="$1"
  local resolved_parent
  if [[ -z "$path" || "$path" == "/" ]]; then
    echo "Refusing unsafe delete path: $path" >&2
    exit 1
  fi
  resolved_parent="$(cd "$(dirname "$path")" 2>/dev/null && pwd -P || true)"
  case "${resolved_parent}/$(basename "$path")" in
    *AgentSnitch*|*agentsnitch*) ;;
    *)
      echo "Refusing delete outside an AgentSnitch-specific path: $path" >&2
      exit 1
      ;;
  esac
}

if [[ "$APP_SIGN_IDENTITY" == "-" ]] && grep -Eq 'com\.apple\.developer\.(system-extension\.install|networking\.networkextension)' "$APP_ENTITLEMENTS"; then
  cat >&2 <<EOF
Refusing to sign $APP_PATH ad hoc with restricted Network Extension/System Extension entitlements.

macOS will not grant those restricted entitlements without a real Apple Team ID
and provisioning profile, and the resulting app may fail to launch.

Use the default launchable dev entitlements for local UI/fallback testing:
  make package-macos-dev

Use restricted entitlements only with a real signing identity/profile:
  AGENTSNITCH_APP_SIGN_IDENTITY="Developer ID Application: ..." \\
  AGENTSNITCH_APP_ENTITLEMENTS="$ROOT_DIR/ui/src-tauri/entitlements.plist" \\
  make package-macos-dev
EOF
  exit 1
fi

if [[ -n "$HOST_PROFILE" ]] && [[ ! -f "$HOST_PROFILE" ]]; then
  echo "Host provisioning profile not found: $HOST_PROFILE" >&2
  exit 1
fi

if [[ -n "$EXT_PROFILE" ]] && [[ ! -f "$EXT_PROFILE" ]]; then
  echo "Extension provisioning profile not found: $EXT_PROFILE" >&2
  exit 1
fi

if [[ "$APP_SIGN_IDENTITY" != "-" ]] && grep -Eq 'com\.apple\.developer\.(system-extension\.install|networking\.networkextension)' "$APP_ENTITLEMENTS"; then
  if [[ -z "$HOST_PROFILE" || -z "$EXT_PROFILE" ]]; then
    cat >&2 <<EOF
Real Network Extension signing needs both provisioning profiles.

Required:
  AGENTSNITCH_HOST_PROFILE=/path/to/host.provisionprofile
  AGENTSNITCH_EXTENSION_PROFILE=/path/to/extension.provisionprofile

The host app profile must cover com.somoore.agentsnitch.
The extension profile must cover $EXT_BUNDLE_ID.
EOF
    exit 1
  fi
fi

AGENTSNITCH_EXT_SIGN_IDENTITY="$EXT_SIGN_IDENTITY" "$ROOT_DIR/extension/build-extension.sh"

if [[ ! -d "$EXT_BUILD_PATH" ]]; then
  echo "Built extension bundle not found: $EXT_BUILD_PATH" >&2
  exit 1
fi

if [[ ! -f "$HOST_BRIDGE_DYLIB" ]]; then
  echo "Built host bridge dylib not found: $HOST_BRIDGE_DYLIB" >&2
  exit 1
fi

mkdir -p "$DEST_DIR"
require_agentsnitch_path_for_delete "$DEST_EXT"
rm -rf "$DEST_EXT"
ditto "$EXT_BUILD_PATH" "$DEST_EXT"

mkdir -p "$FRAMEWORKS_DIR"
rm -f "$DEST_HOST_BRIDGE"
ditto "$HOST_BRIDGE_DYLIB" "$DEST_HOST_BRIDGE"

if [[ -n "$EXT_PROFILE" ]]; then
  cp "$EXT_PROFILE" "$DEST_EXT/Contents/embedded.provisionprofile"
fi

if [[ -n "$HOST_PROFILE" ]]; then
  cp "$HOST_PROFILE" "$APP_PATH/Contents/embedded.provisionprofile"
fi

codesign --force \
  --sign "$EXT_SIGN_IDENTITY" \
  --entitlements "$ROOT_DIR/extension/entitlements.plist" \
  --options runtime \
  "${EXT_TIMESTAMP_ARGS[@]}" \
  "$DEST_EXT"

codesign --force \
  --sign "$APP_SIGN_IDENTITY" \
  "${APP_TIMESTAMP_ARGS[@]}" \
  "$DEST_HOST_BRIDGE"

codesign --force \
  --deep \
  --sign "$APP_SIGN_IDENTITY" \
  --entitlements "$APP_ENTITLEMENTS" \
  --options runtime \
  "${APP_TIMESTAMP_ARGS[@]}" \
  "$APP_PATH"

echo "Embedded system extension:"
echo "  $DEST_EXT"
echo "Embedded host bridge dylib:"
echo "  $DEST_HOST_BRIDGE"
echo ""
echo "Signed app for local inspection:"
echo "  $APP_PATH"
echo "App entitlements used:"
echo "  $APP_ENTITLEMENTS"
if [[ -n "$HOST_PROFILE" ]]; then
  echo "Host provisioning profile:"
  echo "  $HOST_PROFILE"
fi
if [[ -n "$EXT_PROFILE" ]]; then
  echo "Extension provisioning profile:"
  echo "  $EXT_PROFILE"
fi
echo ""
if [[ "$APP_SIGN_IDENTITY" != "-" && -n "$HOST_PROFILE" && -n "$EXT_PROFILE" && "$APP_ENTITLEMENTS" == "$ROOT_DIR/ui/src-tauri/entitlements.plist" ]]; then
  echo "Developer ID signing prerequisites are present for opt-in Network Extension activation."
else
  echo "This local package is not production-ready unless signed with a real Apple Team ID, provisioning profiles, and the restricted production entitlements."
fi
