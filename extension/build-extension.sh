#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXT_DIR="$ROOT_DIR/extension"
BUILD_DIR="${AGENTSNITCH_EXTENSION_BUILD_DIR:-$EXT_DIR/build}"

BUNDLE_ID="com.somoore.agentsnitch.network-extension"
MODULE_NAME="AgentSnitchNetworkExtension"
EXECUTABLE_NAME="AgentSnitchNetworkExtension"
BUNDLE_DIR="$BUILD_DIR/$BUNDLE_ID.systemextension"
CONTENTS_DIR="$BUNDLE_DIR/Contents"
MACOS_DIR="$CONTENTS_DIR/MacOS"
HOST_BRIDGE_DYLIB_NAME="libAgentSnitchHostBridge.dylib"
HOST_BRIDGE_DYLIB="$BUILD_DIR/$HOST_BRIDGE_DYLIB_NAME"

SIGN_IDENTITY="${AGENTSNITCH_EXT_SIGN_IDENTITY:--}"
SKIP_CODESIGN="${AGENTSNITCH_SKIP_CODESIGN:-0}"

mkdir -p "$MACOS_DIR"

rm -rf "$BUNDLE_DIR"
mkdir -p "$MACOS_DIR"

INFO_PLIST="$CONTENTS_DIR/Info.plist"
sed "s/\$(PRODUCT_MODULE_NAME)/$MODULE_NAME/g" "$EXT_DIR/Info.plist" > "$INFO_PLIST"

xcrun swiftc \
  -emit-executable \
  -module-name "$MODULE_NAME" \
  -o "$MACOS_DIR/$EXECUTABLE_NAME" \
  "$EXT_DIR/main.swift" \
  "$EXT_DIR/AgentSnitchXPCProtocol.swift" \
  "$EXT_DIR/AgentSnitchNetworkExtension.swift" \
  -framework NetworkExtension \
  -framework Security \
  -lbsm

chmod 755 "$MACOS_DIR/$EXECUTABLE_NAME"

xcrun swiftc \
  -emit-library \
  -module-name AgentSnitchHostBridge \
  -o "$HOST_BRIDGE_DYLIB" \
  "$EXT_DIR/AgentSnitchXPCProtocol.swift" \
  "$EXT_DIR/AgentSnitchHostBridge.swift" \
  -framework Foundation \
  -framework NetworkExtension \
  -framework SystemExtensions \
  -Xlinker -install_name \
  -Xlinker "@rpath/$HOST_BRIDGE_DYLIB_NAME"

chmod 755 "$HOST_BRIDGE_DYLIB"

if [[ "$SKIP_CODESIGN" != "1" ]]; then
  codesign --force \
    --sign "$SIGN_IDENTITY" \
    --entitlements "$EXT_DIR/entitlements.plist" \
    --timestamp=none \
    "$BUNDLE_DIR"

  codesign --force \
    --sign "$SIGN_IDENTITY" \
    --timestamp=none \
    "$HOST_BRIDGE_DYLIB"
fi

echo "Built system extension bundle:"
echo "  $BUNDLE_DIR"
echo "Built host bridge dylib:"
echo "  $HOST_BRIDGE_DYLIB"
echo ""
echo "Next production packaging step:"
echo "  copy the .systemextension into AgentSnitch.app/Contents/Library/SystemExtensions/"
echo "  copy the host bridge dylib into AgentSnitch.app/Contents/Frameworks/"
echo "  then sign the inner extension, host bridge dylib, and outer app with a real Apple Team ID profile."
