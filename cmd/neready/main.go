package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	hostEntitlementsPath = "ui/src-tauri/entitlements.plist"
	extensionInfoPath    = "extension/Info.plist"
	extensionEntPath     = "extension/entitlements.plist"
	xpcProtocolPath      = "extension/AgentSnitchXPCProtocol.swift"
	hostBridgePath       = "extension/AgentSnitchHostBridge.swift"
	extensionSourcePath  = "extension/AgentSnitchNetworkExtension.swift"
	tauriBackendPath     = "ui/src-tauri/src/lib.rs"
	uiDistPath           = "ui/dist/index.html"

	defaultAppBundlePath = "/Applications/AgentSnitch.app"
	extensionBundleID    = "com.somoore.agentsnitch.network-extension"
	extensionBundleName  = extensionBundleID + ".systemextension"
	hostBridgeDylibName  = "libAgentSnitchHostBridge.dylib"
	builtExtensionPath   = "extension/build/" + extensionBundleName
	builtHostBridgePath  = "extension/build/" + hostBridgeDylibName
)

type check struct {
	name   string
	status string
	detail string
	fail   bool
}

func appBundlePath() string {
	if path := strings.TrimSpace(os.Getenv("AGENTSNITCH_APP_PATH")); path != "" {
		return path
	}
	return defaultAppBundlePath
}

func main() {
	var checks []check
	checks = append(checks, checkPlistSyntax("Host entitlements", hostEntitlementsPath))
	checks = append(checks, checkPlistSyntax("Extension Info.plist", extensionInfoPath))
	checks = append(checks, checkPlistSyntax("Extension entitlements", extensionEntPath))
	checks = append(checks, checkSourceFile("XPC protocol source", xpcProtocolPath))
	checks = append(checks, checkSourceFile("Host bridge source", hostBridgePath))
	checks = append(checks, checkSourceFile("Network Extension source", extensionSourcePath))
	checks = append(checks, checkSourceFile("Tauri backend source", tauriBackendPath))
	checks = append(checks, checkSourceFile("Tauri static UI", uiDistPath))
	checks = append(checks, checkSourceContracts()...)
	checks = append(checks, checkBuiltExtension()...)
	checks = append(checks, checkBuiltHostBridge()...)
	checks = append(checks, checkInstalledApp()...)
	checks = append(checks, checkSystemExtensionState())

	failed := false
	for _, c := range checks {
		if c.fail {
			failed = true
		}
		fmt.Printf("%-30s %-5s %s\n", c.name+":", c.status, c.detail)
	}
	if failed {
		os.Exit(1)
	}
}

func checkPlistSyntax(name, path string) check {
	if _, err := os.Stat(path); err != nil {
		return check{name: name, status: "FAIL", detail: path + " missing", fail: true}
	}
	out, err := exec.Command("plutil", "-lint", path).CombinedOutput()
	if err != nil {
		return check{name: name, status: "FAIL", detail: strings.TrimSpace(string(out)), fail: true}
	}
	return check{name: name, status: "OK", detail: path}
}

func checkSourceFile(name, path string) check {
	if _, err := os.Stat(path); err != nil {
		return check{name: name, status: "FAIL", detail: path + " missing", fail: true}
	}
	return check{name: name, status: "OK", detail: path}
}

func checkSourceContracts() []check {
	var checks []check
	host, _ := os.ReadFile(hostEntitlementsPath)
	extInfo, _ := os.ReadFile(extensionInfoPath)
	extEnt, _ := os.ReadFile(extensionEntPath)
	xpcProtocol, _ := os.ReadFile(xpcProtocolPath)
	hostBridge, _ := os.ReadFile(hostBridgePath)
	extensionSource, _ := os.ReadFile(extensionSourcePath)
	tauriBackend, _ := os.ReadFile(tauriBackendPath)
	uiDist, _ := os.ReadFile(uiDistPath)

	checks = append(checks, containsCheck(
		"Host sysext install entitlement",
		host,
		"com.apple.developer.system-extension.install",
		"host can request OSSystemExtension activation",
	))
	checks = append(checks, containsCheck(
		"Host NE entitlement",
		host,
		"content-filter-provider-systemextension",
		"host declares content-filter system extension capability",
	))
	checks = append(checks, containsCheck(
		"Extension NE entitlement",
		extEnt,
		"content-filter-provider-systemextension",
		"extension declares matching content-filter capability",
	))
	checks = append(checks, forbiddenNeedlesCheck(
		"Extension entitlement minimum",
		extEnt,
		[]string{
			"app-proxy-provider-systemextension",
			"packet-tunnel-provider-systemextension",
			"dns-proxy-systemextension",
		},
		"content-filter entitlement only",
	))
	checks = append(checks, containsCheck(
		"Extension bundle id",
		extInfo,
		extensionBundleID,
		extensionBundleID,
	))
	checks = append(checks, containsCheck(
		"Extension provider type",
		extInfo,
		"com.apple.networkextension.filter-data",
		"NEFilterDataProvider / content filter",
	))
	checks = append(checks, containsCheck(
		"XPC service name",
		xpcProtocol,
		"com.somoore.agentsnitch.xpc",
		"shared extension->host XPC service name",
	))
	checks = append(checks, containsCheck(
		"Host XPC receiver",
		hostBridge,
		"handleFlowEvent",
		"host bridge receives FlowEvent Data over XPC",
	))
	checks = append(checks, containsCheck(
		"Host daemon forwarder",
		hostBridge,
		"forwardToDaemon",
		"host bridge forwards FlowEvent JSON to daemon socket",
	))
	checks = append(checks, containsCheck(
		"Host filter manager",
		hostBridge,
		"NEFilterManager.shared",
		"host bridge configures NEFilterManager preferences",
	))
	checks = append(checks, containsCheck(
		"Host filter bundle binding",
		hostBridge,
		"filterDataProviderBundleIdentifier",
		"content filter binds to AgentSnitch data provider bundle id",
	))
	checks = append(checks, containsCheck(
		"NE byte capture default",
		hostBridge,
		"\"capture_bytes\": false",
		"host config leaves byte callbacks disabled by default",
	))
	checks = append(checks, containsCheck(
		"NE local traffic default",
		hostBridge,
		"\"observe_local\": false",
		"host config excludes local/private routine traffic by default",
	))
	checks = append(checks, containsCheck(
		"High Assurance off by default",
		tauriBackend,
		"network_sensor_disabled: true",
		"fresh settings start in User Visibility until the user enables High Assurance",
	))
	checks = append(checks, containsCheck(
		"Static UI High Assurance default",
		uiDist,
		"high_assurance_default_enabled: false",
		"static UI initializes High Assurance startup default as off before settings load",
	))
	checks = append(checks, containsCheck(
		"Static UI High Assurance warning",
		uiDist,
		"High Assurance mode",
		"settings expose High Assurance as the user-facing mode instead of raw Network Extension wording",
	))
	checks = append(checks, containsCheck(
		"Tauri NE env kill switch",
		tauriBackend,
		"AGENTSNITCH_DISABLE_NETWORK_EXTENSION",
		"app-side kill switch skips activation and requests filter disable",
	))
	checks = append(checks, containsCheck(
		"Host bridge disable waits",
		hostBridge,
		"DispatchSemaphore",
		"disable/enable bridge waits for NEFilterManager save result instead of fire-and-forget",
	))
	checks = append(checks, containsCheck(
		"NE byte lifecycle gate",
		extensionSource,
		"guard captureByteLifecycle else",
		"provider allows flows without byte callbacks by default",
	))
	checks = append(checks, containsCheck(
		"NE fail-open new flow",
		extensionSource,
		"return .allow()",
		"provider returns allow verdicts on unavailable delivery, local/private skip, and default observe path",
	))
	checks = append(checks, containsCheck(
		"NE process audit token source",
		extensionSource,
		"sourceProcessAuditToken",
		"provider prefers process audit token for PID attribution",
	))
	checks = append(checks, containsCheck(
		"NE modern endpoint source",
		extensionSource,
		"remoteFlowEndpoint",
		"provider uses macOS 15+ Network endpoint metadata",
	))
	checks = append(checks, containsCheck(
		"NE hostname hint source",
		extensionSource,
		"hostnameHint(socketFlow.remoteHostname)",
		"provider preserves remoteHostname as a destination display hint",
	))
	checks = append(checks, forbiddenNeedlesCheck(
		"NE no remote egress APIs",
		extensionSource,
		[]string{
			"URLSession",
			"URLRequest",
			"NWConnection",
			"NETransparentProxyProvider",
			"NEAppProxyProvider",
			"NEPacketTunnelProvider",
			"NEDNSProxyProvider",
			"socket(AF_INET",
			"socket(AF_INET6",
			"NSXPCListener",
			"listen(",
			"accept(",
		},
		"extension source contains no proxy, tunnel, remote socket, HTTP, or inbound-listener APIs",
	))
	checks = append(checks, containsCheck(
		"NE event payload cap",
		extensionSource,
		"maxEncodedEventBytes",
		"extension rejects oversized encoded events before local IPC",
	))
	checks = append(checks, containsCheck(
		"NE config payload cap",
		extensionSource,
		"maxDaemonSocketPathBytes",
		"extension rejects oversized daemon socket configuration",
	))
	checks = append(checks, containsCheck(
		"Host XPC payload cap",
		hostBridge,
		"maxForwardedEventBytes",
		"host XPC fallback rejects oversized FlowEvent payloads before daemon forwarding",
	))
	checks = append(checks, checkTauriHostBridgeLinked(tauriBackend))
	if bytes.Contains(extInfo, []byte("$(PRODUCT_MODULE_NAME)")) {
		checks = append(checks, check{
			name:   "Principal class concrete",
			status: "WARN",
			detail: "NSExtensionPrincipalClass still uses $(PRODUCT_MODULE_NAME); Xcode must substitute it or Info.plist must be concrete",
		})
	} else {
		checks = append(checks, check{name: "Principal class concrete", status: "OK", detail: "principal class is concrete"})
	}
	return checks
}

func checkTauriHostBridgeLinked(tauriBackend []byte) check {
	if len(tauriBackend) == 0 {
		return check{name: "Tauri host bridge linked", status: "FAIL", detail: tauriBackendPath + " missing or empty", fail: true}
	}
	if bytes.Contains(tauriBackend, []byte("NE activation stub complete")) ||
		bytes.Contains(tauriBackend, []byte("(stub)")) {
		return check{
			name:   "Tauri host bridge linked",
			status: "FAIL",
			detail: "Tauri backend still uses activation stub; Swift host bridge is not linked/called at runtime",
			fail:   true,
		}
	}
	if bytes.Contains(tauriBackend, []byte("AgentSnitchHostBridgeStart")) &&
		bytes.Contains(tauriBackend, []byte("AgentSnitchHostBridgeActivateSystemExtension")) &&
		bytes.Contains(tauriBackend, []byte("AgentSnitchHostBridgeSetNetworkSensorDisabled")) &&
		bytes.Contains(tauriBackend, []byte(hostBridgeDylibName)) {
		return check{name: "Tauri host bridge linked", status: "OK", detail: "Tauri dynamically loads host bridge dylib and calls start/activate/disable exports"}
	}
	return check{name: "Tauri host bridge linked", status: "WARN", detail: "no activation stub found, but host bridge dynamic linkage could not be proven"}
}

func containsCheck(name string, blob []byte, needle, detail string) check {
	if bytes.Contains(blob, []byte(needle)) {
		return check{name: name, status: "OK", detail: detail}
	}
	return check{name: name, status: "FAIL", detail: "missing " + needle, fail: true}
}

func forbiddenNeedlesCheck(name string, blob []byte, forbidden []string, detail string) check {
	for _, needle := range forbidden {
		if bytes.Contains(blob, []byte(needle)) {
			return check{name: name, status: "FAIL", detail: "forbidden " + needle, fail: true}
		}
	}
	return check{name: name, status: "OK", detail: detail}
}

func checkBuiltExtension() []check {
	var checks []check
	if _, err := os.Stat(builtExtensionPath); err != nil {
		return []check{{name: "Built system extension", status: "FAIL", detail: builtExtensionPath + " missing; run make build-extension", fail: true}}
	}
	checks = append(checks, check{name: "Built system extension", status: "OK", detail: builtExtensionPath})

	infoPath := filepath.Join(builtExtensionPath, "Contents", "Info.plist")
	info, err := os.ReadFile(infoPath)
	if err != nil {
		checks = append(checks, check{name: "Built extension Info.plist", status: "FAIL", detail: infoPath + " missing", fail: true})
	} else if bytes.Contains(info, []byte("$(PRODUCT_MODULE_NAME)")) {
		checks = append(checks, check{name: "Built principal class", status: "FAIL", detail: "principal class still contains $(PRODUCT_MODULE_NAME)", fail: true})
	} else {
		checks = append(checks, check{name: "Built principal class", status: "OK", detail: "principal class is concrete"})
	}

	execPath := filepath.Join(builtExtensionPath, "Contents", "MacOS", "AgentSnitchNetworkExtension")
	if st, err := os.Stat(execPath); err != nil || st.IsDir() {
		checks = append(checks, check{name: "Built extension executable", status: "FAIL", detail: execPath + " missing", fail: true})
	} else {
		checks = append(checks, check{name: "Built extension executable", status: "OK", detail: execPath})
		checks = append(checks, checkBinaryContains("Built NE process audit token", execPath, "sourceProcessAuditToken", "prefers process audit token attribution"))
	}

	codesignOut, _ := exec.Command("codesign", "-dvvv", "--entitlements", ":-", builtExtensionPath).CombinedOutput()
	codesignText := string(codesignOut)
	if strings.Contains(codesignText, "Signature=adhoc") {
		checks = append(checks, check{name: "Built extension signature", status: "WARN", detail: "ad hoc signed; use AGENTSNITCH_EXT_SIGN_IDENTITY for production signing"})
	} else if strings.TrimSpace(codesignText) == "" {
		checks = append(checks, check{name: "Built extension signature", status: "FAIL", detail: "codesign did not report signature", fail: true})
	} else {
		checks = append(checks, check{name: "Built extension signature", status: "OK", detail: "not ad hoc"})
	}
	return checks
}

func checkBuiltHostBridge() []check {
	var checks []check
	if st, err := os.Stat(builtHostBridgePath); err != nil || st.IsDir() {
		return []check{{name: "Built host bridge dylib", status: "FAIL", detail: builtHostBridgePath + " missing; run make build-extension", fail: true}}
	}
	checks = append(checks, check{name: "Built host bridge dylib", status: "OK", detail: builtHostBridgePath})

	checks = append(checks, checkDylibSymbol("Built host bridge start symbol", builtHostBridgePath, "AgentSnitchHostBridgeStart"))
	checks = append(checks, checkDylibSymbol("Built host bridge activate symbol", builtHostBridgePath, "AgentSnitchHostBridgeActivateSystemExtension"))
	checks = append(checks, checkDylibSymbol("Built host bridge disable symbol", builtHostBridgePath, "AgentSnitchHostBridgeSetNetworkSensorDisabled"))
	checks = append(checks, checkDylibContains("Built host bridge filter manager", builtHostBridgePath, "NEFilterManager", "contains NEFilterManager configuration code"))

	codesignOut, _ := exec.Command("codesign", "-dvvv", builtHostBridgePath).CombinedOutput()
	codesignText := string(codesignOut)
	if strings.Contains(codesignText, "Signature=adhoc") {
		checks = append(checks, check{name: "Built host bridge signature", status: "WARN", detail: "ad hoc signed; use a real signing identity for production"})
	} else if strings.TrimSpace(codesignText) == "" {
		checks = append(checks, check{name: "Built host bridge signature", status: "FAIL", detail: "codesign did not report signature", fail: true})
	} else {
		checks = append(checks, check{name: "Built host bridge signature", status: "OK", detail: "not ad hoc"})
	}
	return checks
}

func checkDylibSymbol(name, path, symbol string) check {
	out, err := exec.Command("nm", "-gU", path).CombinedOutput()
	if err != nil {
		return check{name: name, status: "FAIL", detail: strings.TrimSpace(string(out)), fail: true}
	}
	if strings.Contains(string(out), symbol) {
		return check{name: name, status: "OK", detail: symbol}
	}
	return check{name: name, status: "FAIL", detail: "missing " + symbol, fail: true}
}

func checkDylibContains(name, path, needle, detail string) check {
	out, err := exec.Command("strings", path).CombinedOutput()
	if err != nil {
		return check{name: name, status: "FAIL", detail: strings.TrimSpace(string(out)), fail: true}
	}
	if strings.Contains(string(out), needle) {
		return check{name: name, status: "OK", detail: detail}
	}
	return check{name: name, status: "FAIL", detail: "missing " + needle, fail: true}
}

func checkBinaryContains(name, path, needle, detail string) check {
	out, err := exec.Command("strings", path).CombinedOutput()
	if err != nil {
		return check{name: name, status: "FAIL", detail: strings.TrimSpace(string(out)), fail: true}
	}
	if strings.Contains(string(out), needle) {
		return check{name: name, status: "OK", detail: detail}
	}
	return check{name: name, status: "FAIL", detail: "missing " + needle, fail: true}
}

func checkInstalledApp() []check {
	var checks []check
	appPath := appBundlePath()
	if _, err := os.Stat(appPath); err != nil {
		return []check{{name: "Installed app", status: "FAIL", detail: appPath + " missing", fail: true}}
	}
	checks = append(checks, check{name: "Installed app", status: "OK", detail: appPath})
	checks = append(checks, checkInstalledTauriBinary()...)

	codesignOut, _ := exec.Command("codesign", "-dvvv", "--entitlements", ":-", appPath).CombinedOutput()
	codesignText := string(codesignOut)
	if strings.Contains(codesignText, "Signature=adhoc") {
		checks = append(checks, check{name: "App signature", status: "FAIL", detail: "ad hoc signed; NE activation requires a real Apple signing identity/profile", fail: true})
	} else {
		checks = append(checks, check{name: "App signature", status: "OK", detail: "not ad hoc"})
	}
	if strings.Contains(codesignText, "TeamIdentifier=not set") {
		checks = append(checks, check{name: "App team id", status: "FAIL", detail: "TeamIdentifier not set", fail: true})
	} else {
		checks = append(checks, check{name: "App team id", status: "OK", detail: teamLine(codesignText)})
	}
	if strings.Contains(codesignText, "com.apple.developer.system-extension.install") &&
		strings.Contains(codesignText, "content-filter-provider-systemextension") {
		checks = append(checks, check{name: "Signed app entitlements", status: "OK", detail: "system-extension + networkextension present"})
	} else {
		checks = append(checks, check{name: "Signed app entitlements", status: "FAIL", detail: "signed app does not show required system-extension/networkextension entitlements", fail: true})
	}
	checks = append(checks, checkProvisioningProfile(
		"Embedded host profile",
		filepath.Join(appPath, "Contents", "embedded.provisionprofile"),
		[]string{
			"com.apple.application-identifier",
			"com.somoore.agentsnitch",
			"com.apple.developer.system-extension.install",
			"content-filter-provider-systemextension",
		},
		"host profile covers app id, System Extension install, and content-filter entitlement",
	))

	embedded := filepath.Join(appPath, "Contents", "Library", "SystemExtensions", extensionBundleName)
	if _, err := os.Stat(embedded); err != nil {
		checks = append(checks, check{name: "Embedded system extension", status: "FAIL", detail: embedded + " missing", fail: true})
	} else {
		checks = append(checks, check{name: "Embedded system extension", status: "OK", detail: embedded})
		checks = append(checks, checkProvisioningProfile(
			"Embedded extension profile",
			filepath.Join(embedded, "Contents", "embedded.provisionprofile"),
			[]string{
				"com.apple.application-identifier",
				extensionBundleID,
				"content-filter-provider-systemextension",
			},
			"extension profile covers extension id and content-filter entitlement",
		))
		embeddedCodesignOut, _ := exec.Command("codesign", "-dvvv", "--entitlements", ":-", embedded).CombinedOutput()
		embeddedCodesignText := string(embeddedCodesignOut)
		checks = append(checks, checkSignedSystemExtension(embeddedCodesignText)...)
		embeddedExec := filepath.Join(embedded, "Contents", "MacOS", "AgentSnitchNetworkExtension")
		if st, err := os.Stat(embeddedExec); err != nil || st.IsDir() {
			checks = append(checks, check{name: "Embedded extension executable", status: "FAIL", detail: embeddedExec + " missing", fail: true})
		} else {
			checks = append(checks, check{name: "Embedded extension executable", status: "OK", detail: embeddedExec})
			checks = append(checks, checkBinaryContains("Embedded NE process audit token", embeddedExec, "sourceProcessAuditToken", "prefers process audit token attribution"))
		}
	}

	embeddedBridge := filepath.Join(appPath, "Contents", "Frameworks", hostBridgeDylibName)
	if _, err := os.Stat(embeddedBridge); err != nil {
		checks = append(checks, check{name: "Embedded host bridge dylib", status: "FAIL", detail: embeddedBridge + " missing", fail: true})
	} else {
		checks = append(checks, check{name: "Embedded host bridge dylib", status: "OK", detail: embeddedBridge})
		checks = append(checks, checkDylibSymbol("Embedded host bridge start symbol", embeddedBridge, "AgentSnitchHostBridgeStart"))
		checks = append(checks, checkDylibSymbol("Embedded host bridge activate symbol", embeddedBridge, "AgentSnitchHostBridgeActivateSystemExtension"))
		checks = append(checks, checkDylibSymbol("Embedded host bridge disable symbol", embeddedBridge, "AgentSnitchHostBridgeSetNetworkSensorDisabled"))
		checks = append(checks, checkDylibContains("Embedded host bridge filter manager", embeddedBridge, "NEFilterManager", "installed dylib contains NEFilterManager configuration code"))
	}
	checks = append(checks, checkInstalledTeamAlignment(appPath, embedded, embeddedBridge))
	return checks
}

func checkProvisioningProfile(name, path string, required []string, detail string) check {
	if _, err := os.Stat(path); err != nil {
		return check{name: name, status: "FAIL", detail: path + " missing", fail: true}
	}
	out, err := exec.Command("security", "cms", "-D", "-i", path).CombinedOutput()
	if err != nil {
		return check{name: name, status: "FAIL", detail: strings.TrimSpace(string(out)), fail: true}
	}
	text := string(out)
	for _, needle := range required {
		if !strings.Contains(text, needle) {
			return check{name: name, status: "FAIL", detail: "missing " + needle, fail: true}
		}
	}
	return check{name: name, status: "OK", detail: detail}
}

func checkSignedSystemExtension(codesignText string) []check {
	var checks []check
	if strings.TrimSpace(codesignText) == "" {
		return []check{{name: "Embedded extension signature", status: "FAIL", detail: "codesign did not report signature", fail: true}}
	}
	if strings.Contains(codesignText, "Signature=adhoc") {
		checks = append(checks, check{name: "Embedded extension signature", status: "FAIL", detail: "ad hoc signed; System Extension activation requires real Apple signing/provisioning", fail: true})
	} else {
		checks = append(checks, check{name: "Embedded extension signature", status: "OK", detail: "not ad hoc"})
	}
	if strings.Contains(codesignText, "content-filter-provider-systemextension") {
		checks = append(checks, check{name: "Embedded extension entitlements", status: "OK", detail: "signed extension includes content-filter-provider-systemextension"})
	} else {
		checks = append(checks, check{name: "Embedded extension entitlements", status: "FAIL", detail: "signed extension does not show content-filter-provider-systemextension entitlement", fail: true})
	}
	return checks
}

func checkInstalledTeamAlignment(appPath, extensionPath, bridgePath string) check {
	appTeam := teamIdentifierForPath(appPath)
	extensionTeam := teamIdentifierForPath(extensionPath)
	bridgeTeam := teamIdentifierForPath(bridgePath)
	if appTeam == "" || extensionTeam == "" || bridgeTeam == "" {
		return check{
			name:   "Installed signing team alignment",
			status: "FAIL",
			detail: fmt.Sprintf("TeamIdentifier missing (app=%q extension=%q bridge=%q); NE activation requires one real Team ID across installed artifacts", appTeam, extensionTeam, bridgeTeam),
			fail:   true,
		}
	}
	if appTeam != extensionTeam || appTeam != bridgeTeam {
		return check{
			name:   "Installed signing team alignment",
			status: "FAIL",
			detail: fmt.Sprintf("TeamIdentifier mismatch (app=%q extension=%q bridge=%q)", appTeam, extensionTeam, bridgeTeam),
			fail:   true,
		}
	}
	return check{name: "Installed signing team alignment", status: "OK", detail: "all installed artifacts signed by TeamIdentifier=" + appTeam}
}

func teamIdentifierForPath(path string) string {
	if path == "" {
		return ""
	}
	out, err := exec.Command("codesign", "-dvvv", path).CombinedOutput()
	if err != nil && len(out) == 0 {
		return ""
	}
	return parseTeamIdentifier(string(out))
}

func parseTeamIdentifier(codesignText string) string {
	for _, line := range strings.Split(codesignText, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "TeamIdentifier=") {
			value := strings.TrimSpace(strings.TrimPrefix(line, "TeamIdentifier="))
			if value == "not set" {
				return ""
			}
			return value
		}
	}
	return ""
}

func checkInstalledTauriBinary() []check {
	var checks []check
	execPath, err := installedAppExecutablePath()
	if err != nil {
		return []check{{name: "Installed app executable", status: "FAIL", detail: err.Error(), fail: true}}
	}
	if st, err := os.Stat(execPath); err != nil || st.IsDir() {
		return []check{{name: "Installed app executable", status: "FAIL", detail: execPath + " missing", fail: true}}
	}
	checks = append(checks, check{name: "Installed app executable", status: "OK", detail: execPath})

	out, err := exec.Command("strings", execPath).CombinedOutput()
	if err != nil {
		checks = append(checks, check{name: "Installed app bridge loader", status: "FAIL", detail: strings.TrimSpace(string(out)), fail: true})
		return checks
	}
	binaryText := string(out)
	if strings.Contains(binaryText, "AgentSnitchHostBridgeStart") &&
		strings.Contains(binaryText, "AgentSnitchHostBridgeActivateSystemExtension") &&
		strings.Contains(binaryText, "AgentSnitchHostBridgeSetNetworkSensorDisabled") &&
		strings.Contains(binaryText, hostBridgeDylibName) {
		checks = append(checks, check{name: "Installed app bridge loader", status: "OK", detail: "binary contains host bridge dylib loader and start/activate/disable symbols"})
	} else {
		checks = append(checks, check{name: "Installed app bridge loader", status: "FAIL", detail: "installed Tauri binary does not contain host bridge loader symbols; rebuild and reinstall app", fail: true})
	}
	return checks
}

func installedAppExecutablePath() (string, error) {
	appPath := appBundlePath()
	infoPath := filepath.Join(appPath, "Contents", "Info.plist")
	out, err := exec.Command("plutil", "-extract", "CFBundleExecutable", "raw", infoPath).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("could not read CFBundleExecutable: %s", strings.TrimSpace(string(out)))
	}
	name := strings.TrimSpace(string(out))
	if name == "" {
		return "", fmt.Errorf("CFBundleExecutable is empty")
	}
	return filepath.Join(appPath, "Contents", "MacOS", name), nil
}

func teamLine(codesignText string) string {
	for _, line := range strings.Split(codesignText, "\n") {
		if strings.HasPrefix(line, "TeamIdentifier=") {
			return line
		}
	}
	return "TeamIdentifier not reported"
}

func checkSystemExtensionState() check {
	out, err := exec.Command("systemextensionsctl", "list").CombinedOutput()
	if err != nil {
		return check{name: "System extension state", status: "WARN", detail: strings.TrimSpace(string(out))}
	}
	if strings.Contains(string(out), extensionBundleID) {
		return check{name: "System extension state", status: "OK", detail: "listed by systemextensionsctl"}
	}
	return check{name: "System extension state", status: "FAIL", detail: extensionBundleID + " is not activated/listed", fail: true}
}
