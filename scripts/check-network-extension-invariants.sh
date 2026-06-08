#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

extension_source="${AGENTSNITCH_EXTENSION_SOURCE:-extension/AgentSnitchNetworkExtension.swift}"
extension_info="${AGENTSNITCH_EXTENSION_INFO:-extension/Info.plist}"
extension_entitlements="${AGENTSNITCH_EXTENSION_ENTITLEMENTS:-extension/entitlements.plist}"
host_bridge="${AGENTSNITCH_HOST_BRIDGE:-extension/AgentSnitchHostBridge.swift}"

failures=0

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  failures=$((failures + 1))
}

require_file() {
  local path="$1"
  if [[ ! -f "$path" ]]; then
    fail "missing required file: $path"
  fi
}

require_contains() {
  local path="$1"
  local needle="$2"
  local why="$3"
  if ! grep -Fq "$needle" "$path"; then
    fail "$path must contain '$needle' ($why)"
  fi
}

forbid_contains() {
  local path="$1"
  local needle="$2"
  local why="$3"
  local hit_file
  hit_file="$(mktemp "${TMPDIR:-/tmp}/agentsnitch-invariant-hit.XXXXXX")"
  if grep -Fn "$needle" "$path" >"$hit_file"; then
    printf 'Forbidden pattern in %s (%s): %s\n' "$path" "$why" "$needle" >&2
    sed 's/^/  /' "$hit_file" >&2
    failures=$((failures + 1))
  fi
  rm -f "$hit_file"
}

forbid_regex() {
  local path="$1"
  local pattern="$2"
  local why="$3"
  local hit_file
  hit_file="$(mktemp "${TMPDIR:-/tmp}/agentsnitch-invariant-hit.XXXXXX")"
  if grep -En "$pattern" "$path" >"$hit_file"; then
    printf 'Forbidden pattern in %s (%s): %s\n' "$path" "$why" "$pattern" >&2
    sed 's/^/  /' "$hit_file" >&2
    failures=$((failures + 1))
  fi
  rm -f "$hit_file"
}

require_file "$extension_source"
require_file "$extension_info"
require_file "$extension_entitlements"
require_file "$host_bridge"

require_contains "$extension_info" "com.apple.networkextension.filter-data" "Network Extension must be a metadata content filter"
require_contains "$extension_entitlements" "content-filter-provider-systemextension" "only the content-filter provider entitlement is expected"
require_contains "$extension_source" "NEFilterDataProvider" "provider must remain a data-filter sensor"
require_contains "$extension_source" "return .allow()" "new-flow decisions must fail open"
require_contains "$extension_source" "sourceProcessAuditToken" "attribution should use OS audit-token metadata"
require_contains "$extension_source" "remoteFlowEndpoint" "flow destination metadata should come from Network Extension endpoints"
require_contains "$extension_source" "hostnameHint(socketFlow.remoteHostname)" "remoteHostname is preserved only as a display hint"
require_contains "$host_bridge" "\"capture_bytes\": false" "byte lifecycle callbacks must remain disabled by default"
require_contains "$host_bridge" "\"observe_local\": false" "local/private traffic observation must remain disabled by default"

for needle in \
  "transparent-proxy-provider-systemextension" \
  "app-proxy-provider-systemextension" \
  "packet-tunnel-provider-systemextension" \
  "dns-proxy-systemextension"; do
  forbid_contains "$extension_entitlements" "$needle" "proxy/tunnel/DNS providers are out of scope"
done

for needle in \
  "com.apple.networkextension.transparent-proxy" \
  "com.apple.networkextension.app-proxy" \
  "com.apple.networkextension.packet-tunnel" \
  "com.apple.networkextension.dns-proxy"; do
  forbid_contains "$extension_info" "$needle" "Info.plist must not declare proxy, tunnel, or DNS provider types"
done

for needle in \
  "NETransparentProxyProvider" \
  "NEAppProxyProvider" \
  "NEPacketTunnelProvider" \
  "NEDNSProxyProvider" \
  "URLSession" \
  "URLRequest" \
  "NWConnection" \
  "socket(AF_INET" \
  "socket(AF_INET6" \
  "NSXPCListener" \
  "listen(" \
  "accept(" \
  "NEFilterNewFlowVerdict.drop" \
  "NEFilterDataVerdict.drop" \
  "NEFilterNewFlowVerdict.remediate" \
  "NEFilterDataVerdict.remediate"; do
  forbid_contains "$extension_source" "$needle" "extension must not proxy, open external sockets, listen inbound, block, or remediate traffic"
done

forbid_regex "$extension_source" '(^|[^[:alnum:]_])\.(drop|remediate)[[:space:]]*\(' "extension must not use inferred Swift drop/remediate verdicts"

if [[ "$failures" -gt 0 ]]; then
  exit 1
fi

echo "Network Extension static invariants: OK"
