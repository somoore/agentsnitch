#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
export COPYFILE_DISABLE=1

APP_PATH="${AGENTSNITCH_APP_PATH:-$ROOT_DIR/ui/src-tauri/target/release/bundle/macos/AgentSnitch.app}"
DIST_DIR="${AGENTSNITCH_DIST_DIR:-$ROOT_DIR/dist}"
WORK_DIR="${AGENTSNITCH_RELEASE_WORK_DIR:-$DIST_DIR/macos-release-work}"
PKGROOT="$WORK_DIR/pkgroot"
SCRIPTS_DIR="$WORK_DIR/scripts"
COMPONENT_PKG="$WORK_DIR/AgentSnitch-component.pkg"
COMPONENT_PLIST="$WORK_DIR/components.plist"
PKG_IDENTIFIER="${AGENTSNITCH_PKG_IDENTIFIER:-com.somoore.agentsnitch.pkg}"
APP_SIGN_IDENTITY="${AGENTSNITCH_APP_SIGN_IDENTITY:-}"
INSTALLER_SIGN_IDENTITY="${AGENTSNITCH_INSTALLER_SIGN_IDENTITY:-}"
REQUIRE_RELEASE_SIGNING="${AGENTSNITCH_REQUIRE_RELEASE_SIGNING:-0}"
NOTARIZE="${AGENTSNITCH_NOTARIZE:-0}"
RELEASE_TAG="${AGENTSNITCH_RELEASE_TAG:-}"

VERSION="$(awk -F\" '/"version"/ {print $4; exit}' ui/src-tauri/tauri.conf.json)"
if [[ -z "$VERSION" ]]; then
  echo "Unable to read app version from ui/src-tauri/tauri.conf.json" >&2
  exit 1
fi

if [[ -z "$RELEASE_TAG" ]]; then
  RELEASE_TAG="v$VERSION"
fi

PKG_BASENAME="AgentSnitch-${RELEASE_TAG}-macos.pkg"
UNSIGNED_PKG="$DIST_DIR/AgentSnitch-${RELEASE_TAG}-macos-unsigned.pkg"
FINAL_PKG="$DIST_DIR/$PKG_BASENAME"

log() {
  printf '==> %s\n' "$*"
}

require_file() {
  local path="$1"
  if [[ ! -f "$path" ]]; then
    echo "Required file missing: $path" >&2
    exit 1
  fi
}

require_dir() {
  local path="$1"
  if [[ ! -d "$path" ]]; then
    echo "Required directory missing: $path" >&2
    exit 1
  fi
}

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

if [[ "$REQUIRE_RELEASE_SIGNING" == "1" ]]; then
  if [[ -z "$APP_SIGN_IDENTITY" || "$APP_SIGN_IDENTITY" == "-" ]]; then
    echo "AGENTSNITCH_APP_SIGN_IDENTITY is required for release signing" >&2
    exit 1
  fi
  if [[ -z "$INSTALLER_SIGN_IDENTITY" || "$INSTALLER_SIGN_IDENTITY" == "-" ]]; then
    echo "AGENTSNITCH_INSTALLER_SIGN_IDENTITY is required for release signing" >&2
    exit 1
  fi
  if [[ "$NOTARIZE" != "1" ]]; then
    echo "AGENTSNITCH_NOTARIZE=1 is required for release signing" >&2
    exit 1
  fi
fi

require_dir "$APP_PATH"
require_file "$ROOT_DIR/bin/emitter"
require_file "$ROOT_DIR/bin/daemon"
require_file "$ROOT_DIR/bin/doctor"
require_file "$ROOT_DIR/bin/hookctl"
require_file "$ROOT_DIR/bin/neready"

mkdir -p "$DIST_DIR"
require_agentsnitch_path_for_delete "$WORK_DIR"
rm -rf "$WORK_DIR"
mkdir -p \
  "$PKGROOT/Applications" \
  "$PKGROOT/Library/Application Support/AgentSnitch/bin" \
  "$PKGROOT/Library/LaunchAgents" \
  "$SCRIPTS_DIR"

log "Staging app bundle"
ditto --norsrc --noextattr --noqtn "$APP_PATH" "$PKGROOT/Applications/AgentSnitch.app"

log "Staging support binaries"
cp -X "$ROOT_DIR/bin/daemon" "$PKGROOT/Library/Application Support/AgentSnitch/bin/AgentSnitch"
cp -X "$ROOT_DIR/bin/emitter" "$PKGROOT/Library/Application Support/AgentSnitch/bin/emitter"
cp -X "$ROOT_DIR/bin/doctor" "$PKGROOT/Library/Application Support/AgentSnitch/bin/doctor"
cp -X "$ROOT_DIR/bin/hookctl" "$PKGROOT/Library/Application Support/AgentSnitch/bin/hookctl"
cp -X "$ROOT_DIR/bin/neready" "$PKGROOT/Library/Application Support/AgentSnitch/bin/neready"
chmod 0755 "$PKGROOT/Library/Application Support/AgentSnitch/bin/"*

if [[ -n "$APP_SIGN_IDENTITY" && "$APP_SIGN_IDENTITY" != "-" ]]; then
  log "Signing support binaries"
  for binary in \
    "$PKGROOT/Library/Application Support/AgentSnitch/bin/AgentSnitch" \
    "$PKGROOT/Library/Application Support/AgentSnitch/bin/emitter" \
    "$PKGROOT/Library/Application Support/AgentSnitch/bin/doctor" \
    "$PKGROOT/Library/Application Support/AgentSnitch/bin/hookctl" \
    "$PKGROOT/Library/Application Support/AgentSnitch/bin/neready"; do
    codesign --force --sign "$APP_SIGN_IDENTITY" --options runtime --timestamp "$binary"
  done
fi

log "Writing LaunchAgent"
cat > "$PKGROOT/Library/LaunchAgents/com.somoore.agentsnitch.daemon.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.somoore.agentsnitch.daemon</string>
  <key>ProgramArguments</key>
  <array>
    <string>/Library/Application Support/AgentSnitch/bin/AgentSnitch</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>AGENTSNITCH_DISABLE_NETWORK_STATISTICS</key>
    <string>0</string>
    <key>AGENTSNITCH_DISABLE_LSOF</key>
    <string>0</string>
  </dict>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>LimitLoadToSessionType</key>
  <string>Aqua</string>
  <key>StandardOutPath</key>
  <string>/dev/null</string>
  <key>StandardErrorPath</key>
  <string>/dev/null</string>
</dict>
</plist>
PLIST
plutil -lint "$PKGROOT/Library/LaunchAgents/com.somoore.agentsnitch.daemon.plist" >/dev/null

log "Writing package scripts"
cat > "$SCRIPTS_DIR/preinstall" <<'SCRIPT'
#!/bin/sh
set -eu

label="com.somoore.agentsnitch.daemon"
console_user="$(/usr/bin/stat -f %Su /dev/console 2>/dev/null || true)"
if [ -n "$console_user" ] && [ "$console_user" != "root" ] && [ "$console_user" != "loginwindow" ]; then
  uid="$(/usr/bin/id -u "$console_user" 2>/dev/null || true)"
  if [ -n "$uid" ]; then
    /bin/launchctl bootout "gui/$uid/$label" >/dev/null 2>&1 || true
  fi
fi

exit 0
SCRIPT

cat > "$SCRIPTS_DIR/postinstall" <<'SCRIPT'
#!/bin/sh
set -eu

app="/Applications/AgentSnitch.app"
support_bin="/Library/Application Support/AgentSnitch/bin"
plist="/Library/LaunchAgents/com.somoore.agentsnitch.daemon.plist"
label="com.somoore.agentsnitch.daemon"

console_user="$(/usr/bin/stat -f %Su /dev/console 2>/dev/null || true)"
if [ -n "$console_user" ] && [ "$console_user" != "root" ] && [ "$console_user" != "loginwindow" ]; then
  uid="$(/usr/bin/id -u "$console_user" 2>/dev/null || true)"
  if [ -n "$uid" ]; then
    if [ -x "$support_bin/hookctl" ] && [ -x "$support_bin/emitter" ]; then
      /usr/bin/sudo -u "$console_user" "$support_bin/hookctl" --emitter "$support_bin/emitter" install >/dev/null 2>&1 || true
    fi
    /bin/launchctl bootstrap "gui/$uid" "$plist" >/dev/null 2>&1 || true
    /bin/launchctl kickstart -k "gui/$uid/$label" >/dev/null 2>&1 || true
    if [ -d "$app" ]; then
      /usr/bin/sudo -u "$console_user" /usr/bin/open "$app" >/dev/null 2>&1 || true
    fi
  fi
fi

exit 0
SCRIPT
chmod 0755 "$SCRIPTS_DIR/preinstall" "$SCRIPTS_DIR/postinstall"

log "Building component package"
find "$PKGROOT" -name '._*' -delete
xattr -cr "$PKGROOT"
pkgbuild --analyze --root "$PKGROOT" "$COMPONENT_PLIST"
/usr/libexec/PlistBuddy -c "Set :0:BundleIsRelocatable false" "$COMPONENT_PLIST"
pkgbuild \
  --root "$PKGROOT" \
  --scripts "$SCRIPTS_DIR" \
  --component-plist "$COMPONENT_PLIST" \
  --filter '\.DS_Store$' \
  --filter '/CVS$' \
  --filter '/\.svn$' \
  --filter '(^|/)\._' \
  --identifier "$PKG_IDENTIFIER" \
  --version "$VERSION" \
  --install-location "/" \
  --ownership recommended \
  "$COMPONENT_PKG"

rm -f "$UNSIGNED_PKG" "$FINAL_PKG"
log "Building product package"
productbuild --package "$COMPONENT_PKG" "$UNSIGNED_PKG"

if [[ -n "$INSTALLER_SIGN_IDENTITY" && "$INSTALLER_SIGN_IDENTITY" != "-" ]]; then
  log "Signing installer package"
  productsign --sign "$INSTALLER_SIGN_IDENTITY" "$UNSIGNED_PKG" "$FINAL_PKG"
  rm -f "$UNSIGNED_PKG"
else
  mv "$UNSIGNED_PKG" "$FINAL_PKG"
fi

notary_args=()
if [[ -n "${AGENTSNITCH_APP_STORE_CONNECT_KEY_PATH:-}" ]]; then
  require_file "$AGENTSNITCH_APP_STORE_CONNECT_KEY_PATH"
  if [[ -z "${AGENTSNITCH_APP_STORE_CONNECT_KEY_ID:-}" || -z "${AGENTSNITCH_APP_STORE_CONNECT_ISSUER_ID:-}" ]]; then
    echo "App Store Connect key notarization requires key id and issuer id" >&2
    exit 1
  fi
  notary_args=(
    --key "$AGENTSNITCH_APP_STORE_CONNECT_KEY_PATH"
    --key-id "$AGENTSNITCH_APP_STORE_CONNECT_KEY_ID"
    --issuer "$AGENTSNITCH_APP_STORE_CONNECT_ISSUER_ID"
  )
elif [[ -n "${AGENTSNITCH_NOTARY_PROFILE:-}" ]]; then
  notary_args=(--keychain-profile "$AGENTSNITCH_NOTARY_PROFILE")
elif [[ -n "${AGENTSNITCH_NOTARY_APPLE_ID:-}" && -n "${AGENTSNITCH_NOTARY_PASSWORD:-}" && -n "${AGENTSNITCH_NOTARY_TEAM_ID:-}" ]]; then
  notary_args=(
    --apple-id "$AGENTSNITCH_NOTARY_APPLE_ID"
    --password "$AGENTSNITCH_NOTARY_PASSWORD"
    --team-id "$AGENTSNITCH_NOTARY_TEAM_ID"
  )
fi

if [[ "$NOTARIZE" == "1" ]]; then
  if [[ "${#notary_args[@]}" -eq 0 ]]; then
    echo "Notarization requested but no notary credentials were provided" >&2
    exit 1
  fi
  log "Submitting package for notarization"
  xcrun notarytool submit "$FINAL_PKG" --wait "${notary_args[@]}"
  log "Stapling notarization ticket"
  xcrun stapler staple "$FINAL_PKG"
  xcrun stapler validate "$FINAL_PKG"
fi

log "Writing checksum"
shasum -a 256 "$FINAL_PKG" > "$FINAL_PKG.sha256"

log "Package ready"
printf '%s\n' "$FINAL_PKG"
