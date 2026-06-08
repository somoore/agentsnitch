#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

tmp="$(mktemp -d "${TMPDIR:-/tmp}/agentsnitch-ne-invariants.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

copy_fixture() {
  cp extension/AgentSnitchNetworkExtension.swift "$tmp/AgentSnitchNetworkExtension.swift"
  cp extension/Info.plist "$tmp/Info.plist"
  cp extension/entitlements.plist "$tmp/entitlements.plist"
  cp extension/AgentSnitchHostBridge.swift "$tmp/AgentSnitchHostBridge.swift"
}

run_check() {
  AGENTSNITCH_EXTENSION_SOURCE="$tmp/AgentSnitchNetworkExtension.swift" \
    AGENTSNITCH_EXTENSION_INFO="$tmp/Info.plist" \
    AGENTSNITCH_EXTENSION_ENTITLEMENTS="$tmp/entitlements.plist" \
    AGENTSNITCH_HOST_BRIDGE="$tmp/AgentSnitchHostBridge.swift" \
    ./scripts/check-network-extension-invariants.sh >/dev/null
}

expect_fail() {
  local name="$1"
  if run_check; then
    echo "FAIL: invariant fixture unexpectedly passed: $name" >&2
    exit 1
  fi
}

copy_fixture
run_check

copy_fixture
cat >>"$tmp/AgentSnitchNetworkExtension.swift" <<'SWIFT'
func forbiddenDropFixture() -> NEFilterNewFlowVerdict {
    return .drop()
}
SWIFT
expect_fail "inferred Swift drop verdict"

copy_fixture
cat >>"$tmp/AgentSnitchNetworkExtension.swift" <<'SWIFT'
func forbiddenRemediateFixture() -> NEFilterDataVerdict {
    return .remediate("blocked")
}
SWIFT
expect_fail "inferred Swift remediate verdict"

copy_fixture
cat >>"$tmp/Info.plist" <<'PLIST'
<string>com.apple.networkextension.app-proxy</string>
PLIST
expect_fail "forbidden Info.plist provider"

copy_fixture
cat >>"$tmp/entitlements.plist" <<'PLIST'
<string>transparent-proxy-provider-systemextension</string>
PLIST
expect_fail "forbidden transparent proxy entitlement"

echo "Network Extension invariant regression tests: OK"
