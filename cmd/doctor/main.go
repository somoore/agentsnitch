package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/somoore/agentsnitch/internal/event"
	"github.com/somoore/agentsnitch/internal/hookmatch"
	"github.com/somoore/agentsnitch/internal/inspect"
	asruntime "github.com/somoore/agentsnitch/internal/runtime"
)

const networkExtensionBundleID = "com.somoore.agentsnitch.network-extension"

type check struct {
	name   string
	status string
	detail string
	ok     bool
	fail   bool
}

type appSettings struct {
	NetworkSensorDisabled       bool `json:"network_sensor_disabled"`
	HighAssuranceDefaultEnabled bool `json:"high_assurance_default_enabled"`
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "inspect" {
		printInspectDoctor()
		return
	}
	var checks []check

	emitter := preferredEmitterPath()
	checks = append(checks, checkEmitter(emitter))
	checks = append(checks, checkClaudeHooks(emitter))
	checks = append(checks, checkDaemonSocket())
	checks = append(checks, checkUIListener())
	checks = append(checks, checkLastHookEvent())
	checks = append(checks, checkLastNetworkEvent())
	checks = append(checks, checkNetworkExtension())
	checks = append(checks, checkInspectMode())
	checks = append(checks, checkLastCorrelatedEvent())
	checks = append(checks, checkLastTranscript())

	failed := false
	for _, c := range checks {
		icon := c.status
		if icon == "" {
			icon = "OK"
			if !c.ok {
				icon = "--"
			}
		}
		if c.fail || (!c.ok && c.status == "") {
			failed = true
		}
		if c.detail != "" {
			fmt.Printf("%-22s %s  %s\n", c.name+":", icon, c.detail)
		} else {
			fmt.Printf("%-22s %s\n", c.name+":", icon)
		}
	}

	if failed {
		os.Exit(1)
	}
}

func printInspectDoctor() {
	status := currentInspectStatus()
	fmt.Printf("HTTPS Inspect Mode: %s\n", onOff(status.Enabled))
	fmt.Printf("Managed proxy: %s\n", onOff(status.Proxy.Listening))
	if status.Proxy.Address != "" {
		fmt.Printf("Proxy listener: %s\n", status.Proxy.Address)
	}
	fmt.Printf("CA present: %s\n", yesNo(status.CA.Present))
	if status.CA.Fingerprint != "" {
		fmt.Printf("CA fingerprint: %s\n", status.CA.Fingerprint)
	}
	fmt.Printf("Trust mode: %s\n", status.TrustMode)
	fmt.Printf("System trust: %s\n", yesNo(status.Trust.SystemTrusted))
	fmt.Printf("Payload retention: %s, %s\n", status.PayloadMode, status.Retention)
	if len(status.Warnings) > 0 {
		for _, warning := range status.Warnings {
			fmt.Printf("WARN: %s\n", warning)
		}
	}
}

func checkInspectMode() check {
	status := currentInspectStatus()
	if !status.Enabled && !status.CA.Present && !status.Trust.SystemTrusted {
		return check{name: "HTTPS Inspect", ok: true, status: "OFF", detail: "off by default; no local CA trusted"}
	}
	detail := []string{}
	if status.CA.Fingerprint != "" {
		detail = append(detail, status.CA.Fingerprint)
	}
	detail = append(detail, "trust="+status.TrustMode)
	detail = append(detail, "payload="+status.PayloadMode)
	if status.Proxy.Listening {
		detail = append(detail, "proxy="+status.Proxy.Address)
	}
	if len(status.Warnings) > 0 {
		return check{name: "HTTPS Inspect", ok: true, status: "WARN", detail: strings.Join(append(detail, status.Warnings...), "; ")}
	}
	return check{name: "HTTPS Inspect", ok: true, status: onOff(status.Enabled), detail: strings.Join(detail, "; ")}
}

func currentInspectStatus() inspect.Status {
	if runtimeStatus, err := asruntime.ReadStatus(); err == nil {
		status := inspect.CurrentStatus(runtimeStatus.Inspect.Proxy)
		status.ProcessEnv = runtimeStatus.Inspect.ProcessEnv
		if runtimeStatus.LastInspectedHTTP != nil {
			host := runtimeStatus.LastInspectedHTTP.Request.Host
			if host == "" {
				host = runtimeStatus.LastInspectedHTTP.Network.Remote
			}
			status.LastInspection = strings.TrimSpace(host)
		}
		return status
	}
	return inspect.CurrentStatus(inspect.ProxyStatus{})
}

func onOff(value bool) string {
	if value {
		return "ON"
	}
	return "OFF"
}

func yesNo(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}

func preferredEmitterPath() string {
	if p := os.Getenv("AGENTSNITCH_EMITTER"); p != "" {
		return p
	}
	if installed := installedEmitterPath(); installed != "" {
		return installed
	}
	return asruntime.DefaultEmitterPath()
}

func installedEmitterPath() string {
	if supportDir := os.Getenv("AGENTSNITCH_SUPPORT_DIR"); supportDir != "" {
		return executableCandidate(filepath.Join(supportDir, "bin", "emitter"))
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return executableCandidate(filepath.Join(home, "Library", "Application Support", "AgentSnitch", "bin", "emitter"))
}

func executableCandidate(path string) string {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() || info.Mode()&0o111 == 0 {
		return ""
	}
	return path
}

func checkEmitter(path string) check {
	info, err := os.Stat(path)
	if err != nil {
		return check{name: "Emitter binary", ok: false, fail: true, detail: fmt.Sprintf("missing at %s", path)}
	}
	if info.IsDir() || info.Mode()&0o111 == 0 {
		return check{name: "Emitter binary", ok: false, fail: true, detail: fmt.Sprintf("not executable at %s", path)}
	}
	return check{name: "Emitter binary", ok: true, detail: path}
}

func checkClaudeHooks(emitter string) check {
	settings, err := claudeSettingsPath()
	if err != nil {
		return check{name: "Claude hooks", ok: false, fail: true, detail: err.Error()}
	}
	raw, err := os.ReadFile(settings)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return check{name: "Claude hooks", status: "SETUP", detail: "not installed; open AgentSnitch Settings > Hooks"}
		}
		return check{name: "Claude hooks", ok: false, fail: true, detail: fmt.Sprintf("settings not readable: %s", settings)}
	}

	var doc map[string]interface{}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return check{name: "Claude hooks", ok: false, fail: true, detail: "settings JSON is invalid"}
	}

	hooks, _ := doc["hooks"].(map[string]interface{})
	pre := hookHasEmitter(hooks, "PreToolUse", emitter, "pretooluse")
	post := hookHasEmitter(hooks, "PostToolUse", emitter, "posttooluse")
	if pre && post {
		return check{name: "Claude hooks", ok: true, detail: "PreToolUse and PostToolUse installed"}
	}

	missing := []string{}
	if !pre {
		missing = append(missing, "PreToolUse")
	}
	if !post {
		missing = append(missing, "PostToolUse")
	}
	return check{name: "Claude hooks", status: "SETUP", detail: "missing or wrong: " + strings.Join(missing, ", ") + "; open AgentSnitch Settings > Hooks"}
}

func claudeSettingsPath() (string, error) {
	if p := os.Getenv("CLAUDE_SETTINGS"); p != "" {
		return p, nil
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "", fmt.Errorf("HOME unavailable")
	}
	return filepath.Join(home, ".claude", "settings.json"), nil
}

func hookHasEmitter(hooks map[string]interface{}, eventName, emitter, arg string) bool {
	items, _ := hooks[eventName].([]interface{})
	for _, item := range items {
		group, _ := item.(map[string]interface{})
		commands, _ := group["hooks"].([]interface{})
		for _, command := range commands {
			hook, _ := command.(map[string]interface{})
			cmd, _ := hook["command"].(string)
			if cmd == "" {
				continue
			}
			if hookmatch.Installed(cmd, emitter, arg) {
				return true
			}
		}
	}
	return false
}

func checkDaemonSocket() check {
	conn, err := asruntime.DialDaemon(150 * time.Millisecond)
	if err != nil {
		return check{name: "Daemon socket", ok: false, fail: true, detail: fmt.Sprintf("unreachable at %s", asruntime.SocketPath())}
	}
	_ = conn.Close()
	return check{name: "Daemon socket", ok: true, detail: asruntime.SocketPath()}
}

func checkUIListener() check {
	conn, err := asruntime.DialUI(150 * time.Millisecond)
	if err != nil {
		return check{name: "UI listener", ok: false, fail: true, detail: "unreachable at " + asruntime.UISocketPath()}
	}
	_ = conn.Close()
	return check{name: "UI listener", ok: true, detail: asruntime.UISocketPath()}
}

func checkLastHookEvent() check {
	if status, err := asruntime.ReadStatus(); err == nil {
		if status.LastSemantic == nil {
			return check{name: "Last hook event", ok: false, status: "--", fail: true, detail: missingHookDetail("none yet in " + asruntime.StatusPath())}
		}
		ev := *status.LastSemantic
		event.NormalizeSemanticEvent(&ev)
		if err := event.ValidateSemanticEvent(ev); err != nil {
			return check{name: "Last hook event", ok: false, status: "--", fail: true, detail: "last semantic event incomplete: " + err.Error()}
		}
		return check{name: "Last hook event", ok: true, detail: formatAge(time.Since(ev.TS)) + " ago; real hook contract OK"}
	}

	logPath := daemonLogPath()
	line, age, err := findLastLogJSON(logPath, "SEMANTIC_JSON:")
	if err != nil {
		return check{name: "Last hook event", ok: false, status: "--", fail: true, detail: missingHookDetail(err.Error())}
	}
	var ev event.SemanticEvent
	if err := json.Unmarshal([]byte(line), &ev); err != nil {
		return check{name: "Last hook event", ok: false, status: "--", fail: true, detail: "last semantic JSON is invalid"}
	}
	event.NormalizeSemanticEvent(&ev)
	if err := event.ValidateSemanticEvent(ev); err != nil {
		return check{name: "Last hook event", ok: false, status: "--", fail: true, detail: "last semantic event incomplete: " + err.Error()}
	}
	return check{name: "Last hook event", ok: true, detail: formatAge(age) + " ago; real hook contract OK"}
}

type claudeProcess struct {
	PID     int
	Started time.Time
	Command string
}

func missingHookDetail(base string) string {
	settings, err := claudeSettingsPath()
	if err != nil {
		return base
	}
	info, err := os.Stat(settings)
	if err != nil {
		return base
	}
	processes, err := currentClaudeProcesses()
	if err != nil || len(processes) == 0 {
		return base + "; start Claude Code and run a real tool action"
	}

	var older []claudeProcess
	for _, proc := range processes {
		if !proc.Started.IsZero() && proc.Started.Before(info.ModTime()) {
			older = append(older, proc)
		}
	}
	if len(older) == len(processes) {
		return fmt.Sprintf("%s; %d running Claude process(es) predate hook settings, restart Claude Code and run a real tool action", base, len(processes))
	}
	if len(older) > 0 {
		return fmt.Sprintf("%s; %d of %d running Claude process(es) predate hook settings, restart stale sessions or run a tool in a fresh session", base, len(older), len(processes))
	}
	return base + "; run a real Claude Code tool action to trigger hooks"
}

func currentClaudeProcesses() ([]claudeProcess, error) {
	out, err := exec.Command("ps", "-axo", "pid=,lstart=,command=").Output()
	if err != nil {
		return nil, err
	}
	return parseClaudeProcesses(string(out), time.Local), nil
}

func parseClaudeProcesses(raw string, loc *time.Location) []claudeProcess {
	var processes []claudeProcess
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 7 {
			continue
		}
		pid, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}
		command := strings.Join(fields[6:], " ")
		if !isClaudeCommand(command) {
			continue
		}
		started, err := time.ParseInLocation("Mon Jan 2 15:04:05 2006", strings.Join(fields[1:6], " "), loc)
		if err != nil {
			started = time.Time{}
		}
		processes = append(processes, claudeProcess{PID: pid, Started: started, Command: command})
	}
	return processes
}

func isClaudeCommand(command string) bool {
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return false
	}
	name := filepath.Base(fields[0])
	return name == "claude"
}

func checkLastNetworkEvent() check {
	if status, err := asruntime.ReadStatus(); err == nil {
		if status.LastNetwork == nil {
			return check{name: "Last network event", ok: true, status: "WAIT", detail: "none yet in " + asruntime.StatusPath()}
		}
		ev := *status.LastNetwork
		event.NormalizeNetworkFlow(&ev)
		if err := event.ValidateNetworkFlow(ev); err != nil {
			return check{name: "Last network event", ok: true, status: "WAIT", detail: "last network event incomplete: " + err.Error()}
		}
		return check{name: "Last network event", ok: true, detail: formatAge(time.Since(ev.TS)) + " ago; real network contract OK" + observerDetail(ev)}
	}

	logPath := daemonLogPath()
	line, age, err := findLastLogJSON(logPath, "NETFLOW_JSON:")
	if err != nil {
		return check{name: "Last network event", ok: true, status: "WAIT", detail: err.Error()}
	}
	var ev event.NetworkFlowEvent
	if err := json.Unmarshal([]byte(line), &ev); err != nil {
		return check{name: "Last network event", ok: true, status: "WAIT", detail: "last network JSON is invalid"}
	}
	event.NormalizeNetworkFlow(&ev)
	if err := event.ValidateNetworkFlow(ev); err != nil {
		return check{name: "Last network event", ok: true, status: "WAIT", detail: "last network event incomplete: " + err.Error()}
	}
	return check{name: "Last network event", ok: true, detail: formatAge(age) + " ago; real network contract OK" + observerDetail(ev)}
}

func observerDetail(ev event.NetworkFlowEvent) string {
	switch ev.Observer {
	case "network_extension":
		return " via Network Extension"
	case "network_statistics":
		return " via NetworkStatistics"
	case "lsof":
		return " via lsof fallback"
	case "":
		return ""
	default:
		return " via " + ev.Observer
	}
}

func checkNetworkExtension() check {
	if networkSensorDisabledInSettings() {
		return check{name: "OS Sensor", ok: true, status: "OFF", detail: "User Visibility mode; semantic hooks + userland process/network correlation are primary"}
	}
	status, err := asruntime.ReadStatus()
	if err != nil {
		return check{name: "OS Sensor", ok: true, status: "WAIT", detail: "requested in app settings, but no daemon status at " + asruntime.StatusPath()}
	}
	listed, listErr := systemExtensionListed()
	return networkExtensionCheckForStatus(status, listed, listErr)
}

func networkSensorDisabledInSettings() bool {
	raw, err := os.ReadFile(appSettingsPath())
	if err != nil {
		return true
	}
	var settings appSettings
	if err := json.Unmarshal(raw, &settings); err != nil {
		return true
	}
	return settings.NetworkSensorDisabled && !settings.HighAssuranceDefaultEnabled
}

func appSettingsPath() string {
	if path := strings.TrimSpace(os.Getenv("AGENTSNITCH_UI_SETTINGS")); path != "" {
		return path
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, ".agentsnitch", "ui-settings.json")
	}
	return filepath.Join(os.TempDir(), "agentsnitch-ui-settings.json")
}

func networkExtensionCheckForStatus(status asruntime.Status, listed bool, listErr error) check {
	if status.ObserverMode == "high_assurance_active" {
		detail := "OS-backed flow telemetry has been observed"
		if len(status.ObserverSources) > 0 {
			detail += "; active observers: " + strings.Join(status.ObserverSources, ", ")
		}
		return check{name: "OS Sensor", ok: true, detail: detail}
	}
	if status.ObserverMode == "high_assurance_requested" {
		if listErr != nil {
			return check{name: "OS Sensor", ok: true, status: "WARN", detail: "requested, but could not inspect system extension state: " + listErr.Error()}
		}
		if listed {
			return check{name: "OS Sensor", ok: true, status: "WAIT", detail: "system extension is listed; waiting for first OS-backed flow"}
		}
		return check{name: "OS Sensor", ok: true, status: "WARN", detail: networkExtensionBundleID + " is not activated/listed; run ./bin/neready for signing details"}
	}
	if status.LastNetwork != nil {
		ev := *status.LastNetwork
		event.NormalizeNetworkFlow(&ev)
		if ev.Observer == "network_extension" {
			return check{name: "OS Sensor", ok: true, detail: formatAge(time.Since(ev.TS)) + " ago; real NE flow observed"}
		}
		if ev.Observer == "lsof" {
			if listErr != nil {
				return check{name: "OS Sensor", ok: true, status: "WARN", detail: "latest network event is lsof fallback; could not inspect system extension state: " + listErr.Error()}
			}
			if listed {
				return check{name: "OS Sensor", ok: true, status: "WAIT", detail: "system extension is listed, but latest network event is still lsof fallback"}
			}
			return check{name: "OS Sensor", ok: true, status: "WARN", detail: "lsof fallback only; " + networkExtensionBundleID + " is not activated/listed"}
		}
		if ev.Observer != "" {
			return check{name: "OS Sensor", ok: true, status: "WARN", detail: "latest network event came from observer " + ev.Observer}
		}
	}
	if listErr != nil {
		return check{name: "OS Sensor", ok: true, status: "WARN", detail: "could not inspect system extension state: " + listErr.Error()}
	}
	if listed {
		return check{name: "OS Sensor", ok: true, status: "WAIT", detail: "system extension is listed; waiting for first NE flow"}
	}
	return check{name: "OS Sensor", ok: true, status: "WARN", detail: networkExtensionBundleID + " is not activated/listed; run ./bin/neready for signing details"}
}

func systemExtensionListed() (bool, error) {
	out, err := exec.Command("systemextensionsctl", "list").CombinedOutput()
	if err != nil {
		detail := strings.TrimSpace(string(out))
		if detail == "" {
			detail = err.Error()
		}
		return false, errors.New(detail)
	}
	return strings.Contains(string(out), networkExtensionBundleID), nil
}

func checkLastCorrelatedEvent() check {
	if status, err := asruntime.ReadStatus(); err == nil {
		if status.LastCorrelated == nil {
			return check{name: "Last linked event", ok: true, status: "WAIT", detail: missingLinkedDetail(status)}
		}
		ev := *status.LastCorrelated
		if err := event.ValidateCorrelatedEvent(ev); err != nil {
			return check{name: "Last linked event", ok: true, status: "WAIT", detail: "last linked event incomplete: " + err.Error()}
		}
		return check{name: "Last linked event", ok: true, detail: formatAge(time.Since(ev.TS)) + " ago; real linked evidence OK"}
	}

	return checkLastLogEvent("Last linked event", "CORRELATED:", false)
}

func missingLinkedDetail(status asruntime.Status) string {
	base := "none yet in " + asruntime.StatusPath()
	if status.LastSemantic == nil && status.LastNetwork == nil {
		return base + "; waiting for real hook and network events"
	}
	if status.LastSemantic == nil {
		return base + "; waiting for a real hook event"
	}
	if status.LastNetwork == nil {
		return base + "; waiting for a real network event"
	}

	sem := *status.LastSemantic
	event.NormalizeSemanticEvent(&sem)
	flow := *status.LastNetwork
	event.NormalizeNetworkFlow(&flow)

	if !isLinkedSignal(sem) {
		return fmt.Sprintf("%s; last hook was %s without sensitive/egress tags, waiting for sensitive read, explicit egress, or MCP tool", base, hookLabel(sem))
	}
	if !flow.IsExternal() {
		return base + "; latest network event is not outbound external activity"
	}
	if reason := linkedTimeMissReason(sem, flow); reason != "" {
		return base + "; " + reason
	}
	if reasons := linkedProcessReasons(sem, flow); len(reasons) == 0 {
		return fmt.Sprintf("%s; latest network sample does not prove same process tree (hook pid=%d ppid=%d, flow pid=%d ppid=%d)", base, sem.PID, sem.PPID, flow.PID, flow.PPID)
	}
	return base + "; latest hook and network sample look linkable, check daemon correlation logs"
}

func isLinkedSignal(sem event.SemanticEvent) bool {
	if sem.IsEgressLike() {
		return true
	}
	for _, tag := range sem.Tags {
		switch tag {
		case "sensitive_read", "credential_output", "structured_secret":
			return true
		}
	}
	return false
}

func hookLabel(sem event.SemanticEvent) string {
	label := strings.TrimSpace(sem.Tool)
	if label == "" {
		label = strings.TrimSpace(sem.Event)
	}
	if label == "" {
		label = "hook"
	}
	return label
}

func linkedTimeMissReason(sem event.SemanticEvent, flow event.NetworkFlowEvent) string {
	if sem.TS.IsZero() || flow.TS.IsZero() {
		return ""
	}
	delta := flow.TS.Sub(sem.TS)
	if delta >= 0 && delta <= 10*time.Second {
		return ""
	}
	if delta < 0 && -delta <= 30*time.Second && isSensitiveSignal(sem) && isActiveNetworkFlow(flow) {
		return ""
	}
	return fmt.Sprintf("last high-signal hook and latest network sample are outside the correlation window (delta %s)", delta.Round(time.Second))
}

func isSensitiveSignal(sem event.SemanticEvent) bool {
	for _, tag := range sem.Tags {
		switch tag {
		case "sensitive_read", "credential_output", "structured_secret":
			return true
		}
	}
	return false
}

func isActiveNetworkFlow(flow event.NetworkFlowEvent) bool {
	switch strings.ToLower(strings.TrimSpace(flow.State)) {
	case "established", "data":
		return true
	default:
		return false
	}
}

func linkedProcessReasons(sem event.SemanticEvent, flow event.NetworkFlowEvent) []string {
	var reasons []string
	if sem.PID > 0 && sem.PID == flow.PID {
		reasons = append(reasons, "pid_match")
	}
	if sem.PPID > 0 && sem.PPID == flow.PID {
		reasons = append(reasons, "parent_match")
	}
	if flow.PPID > 0 && sem.PID == flow.PPID {
		reasons = append(reasons, "parent_match")
	}
	if sem.PPID > 0 && flow.PPID > 0 && sem.PPID == flow.PPID {
		reasons = append(reasons, "same_agent_session")
	}
	return uniqueStrings(reasons)
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func checkLastTranscript() check {
	status, err := asruntime.ReadStatus()
	if err != nil {
		return check{name: "Last transcript", ok: true, status: "WAIT", detail: "no status at " + asruntime.StatusPath()}
	}
	if status.LastTranscriptPath == "" {
		return check{name: "Last transcript", ok: true, status: "WAIT", detail: "none yet in " + asruntime.StatusPath()}
	}
	info, err := os.Stat(status.LastTranscriptPath)
	if err != nil {
		return check{name: "Last transcript", ok: true, status: "WAIT", detail: "missing " + status.LastTranscriptPath}
	}
	if info.IsDir() {
		return check{name: "Last transcript", ok: true, status: "WAIT", detail: "path is a directory: " + status.LastTranscriptPath}
	}
	if info.Mode().Perm() != 0o600 {
		return check{name: "Last transcript", ok: true, status: "WAIT", detail: fmt.Sprintf("permissions %o, want 0600 at %s", info.Mode().Perm(), status.LastTranscriptPath)}
	}
	detail := status.LastTranscriptPath
	if status.LastTranscriptKind != "" {
		detail = status.LastTranscriptKind + " -> " + detail
	}
	if !status.LastTranscriptAt.IsZero() {
		detail = formatAge(time.Since(status.LastTranscriptAt)) + " ago; " + detail
	}
	return check{name: "Last transcript", ok: true, detail: detail}
}

func checkLastLogEvent(name, needle string, required bool) check {
	logPath := daemonLogPath()
	raw, err := os.ReadFile(logPath)
	if err != nil {
		return check{name: name, ok: !required, status: waitStatus(required), fail: required, detail: "no daemon log at " + logPath}
	}

	lines := strings.Split(string(raw), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := lines[i]
		if !strings.Contains(line, needle) {
			continue
		}
		if len(line) >= len("2006/01/02 15:04:05") {
			ts, err := time.ParseInLocation("2006/01/02 15:04:05", line[:19], time.Local)
			if err == nil {
				return check{name: name, ok: true, detail: time.Since(ts).Round(time.Second).String() + " ago"}
			}
		}
		return check{name: name, ok: true, detail: "seen in " + logPath}
	}
	return check{name: name, ok: !required, status: waitStatus(required), fail: required, detail: "none yet in " + logPath}
}

func daemonLogPath() string {
	logPath := os.Getenv("AGENTSNITCH_DAEMON_LOG")
	if logPath == "" {
		logPath = "/tmp/agentsnitch-daemon.log"
	}
	return logPath
}

func findLastLogJSON(logPath, marker string) (payload string, age time.Duration, err error) {
	raw, err := os.ReadFile(logPath)
	if err != nil {
		return "", 0, fmt.Errorf("no daemon log at %s", logPath)
	}
	lines := strings.Split(string(raw), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := lines[i]
		idx := strings.Index(line, marker)
		if idx < 0 {
			continue
		}
		payload := strings.TrimSpace(line[idx+len(marker):])
		if payload == "" {
			return "", 0, fmt.Errorf("empty %s payload in %s", marker, logPath)
		}
		age := time.Duration(0)
		if len(line) >= len("2006/01/02 15:04:05") {
			ts, parseErr := time.ParseInLocation("2006/01/02 15:04:05", line[:19], time.Local)
			if parseErr == nil {
				age = time.Since(ts)
			}
		}
		return payload, age, nil
	}
	return "", 0, fmt.Errorf("none yet in %s", logPath)
}

func formatAge(age time.Duration) string {
	if age <= 0 {
		return "seen"
	}
	return age.Round(time.Second).String()
}

func waitStatus(required bool) string {
	if required {
		return "--"
	}
	return "WAIT"
}
