#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

APP_NAME="AgentSnitch"
APP_PATH="${AGENTSNITCH_APP_PATH:-/Applications/AgentSnitch.app}"
BUILT_APP="${AGENTSNITCH_BUILT_APP:-$ROOT/ui/src-tauri/target/release/bundle/macos/AgentSnitch.app}"
SUPPORT_DIR="${AGENTSNITCH_SUPPORT_DIR:-$HOME/Library/Application Support/AgentSnitch}"
SUPPORT_BIN="$SUPPORT_DIR/bin"
DAEMON_EXECUTABLE_NAME="${AGENTSNITCH_DAEMON_EXECUTABLE_NAME:-AgentSnitch}"
DAEMON_PROGRAM="$SUPPORT_BIN/$DAEMON_EXECUTABLE_NAME"
LAUNCH_AGENT_LABEL="${AGENTSNITCH_LAUNCH_AGENT_LABEL:-com.somoore.agentsnitch.daemon}"
LAUNCH_AGENT_PLIST="$HOME/Library/LaunchAgents/$LAUNCH_AGENT_LABEL.plist"
NOTARY_ZIP="${AGENTSNITCH_NOTARY_ZIP:-$ROOT/dist/AgentSnitch-notary.zip}"
DEFAULT_NOTARY_PROFILE="${AGENTSNITCH_DEFAULT_NOTARY_PROFILE:-AgentSnitch}"

log() {
  printf '==> %s\n' "$*"
}

note() {
  printf '    %s\n' "$*"
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

assert_app_exists() {
  local phase="$1"
  if [[ ! -d "$APP_PATH" ]]; then
    echo "AgentSnitch app bundle missing after $phase: $APP_PATH" >&2
    exit 1
  fi
}

detect_signing_identity() {
  if [[ -n "${AGENTSNITCH_APP_SIGN_IDENTITY:-}" ]]; then
    printf '%s\n' "$AGENTSNITCH_APP_SIGN_IDENTITY"
    return
  fi

  local identities
  identities="$(security find-identity -v -p codesigning 2>/dev/null | sed -n 's/.*"\(Developer ID Application: .*\)".*/\1/p' | sort -u || true)"
  local count
  count="$(printf '%s\n' "$identities" | sed '/^$/d' | wc -l | tr -d ' ')"
  if [[ "$count" == "1" ]]; then
    printf '%s\n' "$identities"
  else
    printf '%s\n' "-"
  fi
}

build_everything() {
  log "Building Go tools"
  make build

  log "Building Tauri app"
  if ! command -v cargo >/dev/null 2>&1; then
    echo "cargo is required to build the Tauri app." >&2
    exit 1
  fi
  if ! cargo tauri --version >/dev/null 2>&1; then
    echo "cargo-tauri is required. Install it with: cargo install tauri-cli --locked" >&2
    exit 1
  fi
  (cd ui && cargo tauri build)

  if [[ ! -d "$BUILT_APP" ]]; then
    echo "Built app not found: $BUILT_APP" >&2
    exit 1
  fi
}

install_app_bundle() {
  log "Installing app bundle to $APP_PATH"
  osascript -e 'tell application id "com.somoore.agentsnitch" to quit' >/dev/null 2>&1 || true
  wait_for_app_exit
  local tmp_root
  tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/agentsnitch-app.XXXXXX")"
  ditto "$BUILT_APP" "$tmp_root/AgentSnitch.app"
  require_agentsnitch_path_for_delete "$APP_PATH"
  rm -rf "$APP_PATH"
  ditto "$tmp_root/AgentSnitch.app" "$APP_PATH"
  rm -rf "$tmp_root"
}

wait_for_app_exit() {
  local app_exec="$APP_PATH/Contents/MacOS/agentsnitch-ui"
  for _ in $(seq 1 20); do
    if ! pgrep -f "$app_exec" >/dev/null 2>&1; then
      return
    fi
    sleep 0.25
  done

  note "existing AgentSnitch UI did not quit; terminating stale process"
  pkill -TERM -f "$app_exec" >/dev/null 2>&1 || true
  for _ in $(seq 1 10); do
    if ! pgrep -f "$app_exec" >/dev/null 2>&1; then
      return
    fi
    sleep 0.2
  done
  pkill -KILL -f "$app_exec" >/dev/null 2>&1 || true
}

package_and_sign() {
  local identity
  identity="$(detect_signing_identity)"
  export AGENTSNITCH_APP_PATH="$APP_PATH"
  export AGENTSNITCH_APP_SIGN_IDENTITY="${AGENTSNITCH_APP_SIGN_IDENTITY:-$identity}"
  log "Embedding extension and signing app"
  note "signing identity: $AGENTSNITCH_APP_SIGN_IDENTITY"
  make package-macos-dev
}

notary_args() {
  local profile
  if profile="$(resolved_notary_profile)"; then
    printf '%s\0%s\0' "--keychain-profile" "$profile"
    return
  fi
  if [[ -n "${AGENTSNITCH_NOTARY_APPLE_ID:-}" && -n "${AGENTSNITCH_NOTARY_PASSWORD:-}" && -n "${AGENTSNITCH_NOTARY_TEAM_ID:-}" ]]; then
    printf '%s\0%s\0%s\0%s\0%s\0%s\0' \
      "--apple-id" "$AGENTSNITCH_NOTARY_APPLE_ID" \
      "--password" "$AGENTSNITCH_NOTARY_PASSWORD" \
      "--team-id" "$AGENTSNITCH_NOTARY_TEAM_ID"
  fi
}

resolved_notary_profile() {
  if [[ -n "${AGENTSNITCH_NOTARY_PROFILE:-}" ]]; then
    printf '%s\n' "$AGENTSNITCH_NOTARY_PROFILE"
    return
  fi
  if xcrun notarytool history --keychain-profile "$DEFAULT_NOTARY_PROFILE" >/dev/null 2>&1; then
    printf '%s\n' "$DEFAULT_NOTARY_PROFILE"
    return
  fi
  return 1
}

notary_configured() {
  resolved_notary_profile >/dev/null || {
    [[ -n "${AGENTSNITCH_NOTARY_APPLE_ID:-}" && -n "${AGENTSNITCH_NOTARY_PASSWORD:-}" && -n "${AGENTSNITCH_NOTARY_TEAM_ID:-}" ]]
  }
}

notarize_if_configured() {
  if [[ "${AGENTSNITCH_SKIP_NOTARIZE:-0}" == "1" ]]; then
    log "Skipping notarization because AGENTSNITCH_SKIP_NOTARIZE=1"
    return
  fi
  if [[ "${AGENTSNITCH_APP_SIGN_IDENTITY:-}" == "-" ]]; then
    log "Skipping notarization for ad hoc signed app"
    note "set AGENTSNITCH_APP_SIGN_IDENTITY and notary credentials for notarized distribution"
    return
  fi

  if ! notary_configured; then
    log "Skipping notarization because no notary credentials are configured"
    note "set AGENTSNITCH_NOTARY_PROFILE, or set AGENTSNITCH_NOTARY_APPLE_ID/PASSWORD/TEAM_ID"
    return
  fi

  log "Notarizing $APP_PATH"
  mkdir -p "$(dirname "$NOTARY_ZIP")"
  rm -f "$NOTARY_ZIP"
  ditto -c -k --keepParent "$APP_PATH" "$NOTARY_ZIP"

  local args=()
  while IFS= read -r -d '' arg; do
    args+=("$arg")
  done < <(notary_args)

  xcrun notarytool submit "$NOTARY_ZIP" --wait "${args[@]}"
  xcrun stapler staple "$APP_PATH"
  xcrun stapler validate "$APP_PATH"
}

install_support_binaries() {
  log "Installing support binaries to $SUPPORT_BIN"
  mkdir -p "$SUPPORT_BIN"
  install -m 0755 "$ROOT/bin/emitter" "$SUPPORT_BIN/emitter"
  rm -f "$SUPPORT_BIN/daemon"
  install -m 0755 "$ROOT/bin/daemon" "$DAEMON_PROGRAM"
  install -m 0755 "$ROOT/bin/doctor" "$SUPPORT_BIN/doctor"
  install -m 0755 "$ROOT/bin/hookctl" "$SUPPORT_BIN/hookctl"
  install -m 0755 "$ROOT/bin/neready" "$SUPPORT_BIN/neready"
}

sign_support_binaries() {
  local identity="${AGENTSNITCH_APP_SIGN_IDENTITY:-}"
  if [[ -z "$identity" ]]; then
    identity="$(detect_signing_identity)"
  fi
  local timestamp_args=(--timestamp)
  if [[ "$identity" == "-" ]]; then
    timestamp_args=(--timestamp=none)
  fi

  log "Signing support binaries"
  note "signing identity: $identity"
  codesign --force --sign "$identity" --identifier com.somoore.agentsnitch.daemon --options runtime "${timestamp_args[@]}" "$DAEMON_PROGRAM"
  codesign --force --sign "$identity" --identifier com.somoore.agentsnitch.emitter --options runtime "${timestamp_args[@]}" "$SUPPORT_BIN/emitter"
  codesign --force --sign "$identity" --identifier com.somoore.agentsnitch.doctor --options runtime "${timestamp_args[@]}" "$SUPPORT_BIN/doctor"
  codesign --force --sign "$identity" --identifier com.somoore.agentsnitch.hookctl --options runtime "${timestamp_args[@]}" "$SUPPORT_BIN/hookctl"
  codesign --force --sign "$identity" --identifier com.somoore.agentsnitch.neready --options runtime "${timestamp_args[@]}" "$SUPPORT_BIN/neready"
}

install_hooks() {
  log "Installing Claude Code hooks"
  "$SUPPORT_BIN/hookctl" --emitter "$SUPPORT_BIN/emitter" install
}

write_launch_agent() {
  log "Installing daemon LaunchAgent"
  mkdir -p "$HOME/Library/LaunchAgents" "$HOME/.agentsnitch"
  local disable_network_statistics="${AGENTSNITCH_DISABLE_NETWORK_STATISTICS:-0}"
  local disable_lsof="${AGENTSNITCH_DISABLE_LSOF:-0}"
  local disable_lsof_block="
  <key>EnvironmentVariables</key>
  <dict>
    <key>AGENTSNITCH_DISABLE_NETWORK_STATISTICS</key>
    <string>$disable_network_statistics</string>
    <key>AGENTSNITCH_DISABLE_LSOF</key>
    <string>$disable_lsof</string>
  </dict>"
  cat > "$LAUNCH_AGENT_PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>$LAUNCH_AGENT_LABEL</string>
  <key>ProgramArguments</key>
  <array>
    <string>$DAEMON_PROGRAM</string>
  </array>$disable_lsof_block
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>$HOME/.agentsnitch/daemon.log</string>
  <key>StandardErrorPath</key>
  <string>$HOME/.agentsnitch/daemon.log</string>
</dict>
</plist>
EOF
  chmod 0644 "$LAUNCH_AGENT_PLIST"
  plutil -lint "$LAUNCH_AGENT_PLIST" >/dev/null
}

restart_launch_agent() {
  log "Starting daemon LaunchAgent"
  launchctl bootout "gui/$UID/$LAUNCH_AGENT_LABEL" >/dev/null 2>&1 || true
  launchctl bootout "gui/$UID" "$LAUNCH_AGENT_PLIST" >/dev/null 2>&1 || true
  launchctl bootstrap "gui/$UID" "$LAUNCH_AGENT_PLIST"
  launchctl kickstart -k "gui/$UID/$LAUNCH_AGENT_LABEL"
}

wait_for_daemon_socket() {
  log "Waiting for daemon socket"
  local socket_path="${AGENTSNITCH_SOCK:-${AGENTSNITCH_SOCKET:-$HOME/.agentsnitch/events.sock}}"
  for _ in $(seq 1 20); do
    if [[ -S "$socket_path" ]]; then
      note "$socket_path"
      return
    fi
    sleep 0.25
  done
  echo "Daemon socket did not appear at $socket_path" >&2
  echo "Check $HOME/.agentsnitch/daemon.log" >&2
  exit 1
}

launch_app() {
  log "Launching $APP_NAME"
  open "$APP_PATH"
}

verify_install() {
  log "Running doctor"
  "$SUPPORT_BIN/doctor" || true
}

build_everything
install_app_bundle
assert_app_exists "installing app bundle"
package_and_sign
assert_app_exists "signing app bundle"
notarize_if_configured
assert_app_exists "notarizing app bundle"
install_support_binaries
assert_app_exists "installing support binaries"
sign_support_binaries
assert_app_exists "signing support binaries"
install_hooks
assert_app_exists "installing hooks"
write_launch_agent
assert_app_exists "writing LaunchAgent"
restart_launch_agent
assert_app_exists "starting LaunchAgent"
wait_for_daemon_socket
assert_app_exists "waiting for daemon socket"
launch_app
verify_install

log "create complete"
note "app: $APP_PATH"
note "daemon: $LAUNCH_AGENT_PLIST"
note "logs: $HOME/.agentsnitch/daemon.log"
