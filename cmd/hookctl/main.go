package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/somoore/agentsnitch/internal/hookmatch"
	asruntime "github.com/somoore/agentsnitch/internal/runtime"
)

const (
	preEvent  = "PreToolUse"
	postEvent = "PostToolUse"
)

type options struct {
	settings string
	emitter  string
	events   []hookSpec
}

type hookSpec struct {
	Event       string `json:"event"`
	Arg         string `json:"arg"`
	Label       string `json:"label"`
	Description string `json:"description"`
}

type hookStatus struct {
	Event          string `json:"event"`
	Arg            string `json:"arg"`
	Label          string `json:"label"`
	Description    string `json:"description"`
	DesiredCommand string `json:"desired_command"`
	Installed      bool   `json:"installed"`
	UpToDate       bool   `json:"up_to_date"`
	Stale          bool   `json:"stale"`
	CurrentCommand string `json:"current_command,omitempty"`
	Status         string `json:"status"`
}

type statusReport struct {
	Schema            string       `json:"schema"`
	ClaudeInstalled   bool         `json:"claude_installed"`
	ClaudePath        string       `json:"claude_path,omitempty"`
	SettingsPath      string       `json:"settings_path"`
	SettingsExists    bool         `json:"settings_exists"`
	EmitterPath       string       `json:"emitter_path"`
	EmitterExecutable bool         `json:"emitter_executable"`
	AllInstalled      bool         `json:"all_installed"`
	AllUpToDate       bool         `json:"all_up_to_date"`
	NeedsUpdate       bool         `json:"needs_update"`
	Hooks             []hookStatus `json:"hooks"`
}

var allHookSpecs = []hookSpec{
	{
		Event:       preEvent,
		Arg:         "pretooluse",
		Label:       "PreToolUse",
		Description: "Records Claude Code tool intent before a tool runs.",
	},
	{
		Event:       postEvent,
		Arg:         "posttooluse",
		Label:       "PostToolUse",
		Description: "Records Claude Code tool result metadata after a tool runs.",
	},
}

func main() {
	opts := options{}
	var eventsCSV string
	flag.StringVar(&opts.settings, "settings", "", "Claude settings.json path")
	flag.StringVar(&opts.emitter, "emitter", "", "AgentSnitch emitter path")
	flag.StringVar(&eventsCSV, "events", "", "Comma-separated Claude hook events to manage")
	flag.Parse()

	args := flag.Args()
	if len(args) != 1 {
		usage()
		os.Exit(2)
	}

	if opts.emitter == "" {
		opts.emitter = asruntime.DefaultEmitterPath()
	}
	if opts.settings == "" {
		path, err := claudeSettingsPath()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		opts.settings = path
	}
	events, err := parseHookEvents(eventsCSV)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	opts.events = events

	switch args[0] {
	case "install":
		err = installClaudeHooks(opts)
	case "uninstall":
		err = uninstallClaudeHooks(opts)
	case "verify":
		err = verifyClaudeHooks(opts)
	case "status-json":
		err = writeStatusJSON(opts)
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: hookctl [--settings path] [--emitter path] [--events PreToolUse,PostToolUse] install|uninstall|verify|status-json")
}

func claudeSettingsPath() (string, error) {
	if p := os.Getenv("CLAUDE_SETTINGS"); p != "" {
		return p, nil
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "", errors.New("HOME unavailable")
	}
	return filepath.Join(home, ".claude", "settings.json"), nil
}

func claudeCommandPath() string {
	for _, env := range []string{"CLAUDE_BIN", "CLAUDE_PATH"} {
		if p := os.Getenv(env); executable(p) {
			return p
		}
	}
	if p, err := exec.LookPath("claude"); err == nil && p != "" {
		return p
	}
	home, _ := os.UserHomeDir()
	candidates := []string{}
	if home != "" {
		candidates = append(candidates,
			filepath.Join(home, ".local", "bin", "claude"),
			filepath.Join(home, ".claude", "local", "claude"),
			filepath.Join(home, ".npm-global", "bin", "claude"),
			filepath.Join(home, ".npm-packages", "bin", "claude"),
			filepath.Join(home, "Library", "pnpm", "claude"),
			filepath.Join(home, ".volta", "bin", "claude"),
			filepath.Join(home, ".asdf", "shims", "claude"),
		)
	}
	candidates = append(candidates,
		"/opt/homebrew/bin/claude",
		"/usr/local/bin/claude",
		"/opt/local/bin/claude",
	)
	for _, p := range candidates {
		if executable(p) {
			return p
		}
	}
	if p := loginShellClaudePath(); p != "" {
		return p
	}
	return ""
}

func loginShellClaudePath() string {
	shells := []string{}
	if shell := os.Getenv("SHELL"); shell != "" {
		shells = append(shells, shell)
	}
	shells = append(shells, "/bin/zsh", "/bin/bash")
	seen := map[string]bool{}
	for _, shell := range shells {
		if seen[shell] || !executable(shell) {
			continue
		}
		seen[shell] = true
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		out, err := exec.CommandContext(ctx, shell, "-lc", "command -v claude").Output()
		cancel()
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(out), "\n") {
			p := strings.TrimSpace(line)
			if filepath.IsAbs(p) && executable(p) {
				return p
			}
		}
	}
	return ""
}

func installClaudeHooks(opts options) error {
	opts.events = selectedHooks(opts.events)
	if err := requireExecutable(opts.emitter); err != nil {
		return err
	}
	doc, err := readSettings(opts.settings)
	if err != nil {
		return err
	}

	hooks := hooksMap(doc)
	removeAgentSnitchHooks(hooks, opts.emitter, opts.events)
	for _, spec := range opts.events {
		addAgentSnitchHook(hooks, spec, opts.emitter)
	}
	doc["hooks"] = hooks

	if err := writeSettings(opts.settings, doc); err != nil {
		return err
	}
	fmt.Printf("Claude hooks installed: %s\n", opts.settings)
	fmt.Printf("Emitter: %s\n", opts.emitter)
	return verifyClaudeHooks(opts)
}

func uninstallClaudeHooks(opts options) error {
	opts.events = selectedHooks(opts.events)
	doc, err := readSettings(opts.settings)
	if err != nil {
		return err
	}
	hooks := hooksMap(doc)
	removed := removeAgentSnitchHooks(hooks, opts.emitter, opts.events)
	doc["hooks"] = hooks
	if err := writeSettings(opts.settings, doc); err != nil {
		return err
	}
	fmt.Printf("Claude hooks removed: %d AgentSnitch command(s)\n", removed)
	return nil
}

func verifyClaudeHooks(opts options) error {
	opts.events = selectedHooks(opts.events)
	doc, err := readSettings(opts.settings)
	if err != nil {
		return err
	}
	hooks := hooksMap(doc)
	missing := []string{}
	for _, spec := range opts.events {
		if !hookInstalled(hooks, spec, opts.emitter) {
			missing = append(missing, spec.Event)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("Claude hooks missing or wrong for: %s", strings.Join(missing, ", "))
	}
	fmt.Printf("Claude hooks verified: %s point at %s\n", eventNames(opts.events), opts.emitter)
	return nil
}

func writeStatusJSON(opts options) error {
	report, err := statusClaudeHooks(opts)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

func statusClaudeHooks(opts options) (statusReport, error) {
	opts.events = selectedHooks(opts.events)
	doc, err := readSettings(opts.settings)
	if err != nil {
		return statusReport{}, err
	}
	hooks := hooksMap(doc)
	_, settingsErr := os.Stat(opts.settings)
	claudePath := claudeCommandPath()
	emitterExecutable := requireExecutable(opts.emitter) == nil
	report := statusReport{
		Schema:            "agentsnitch.hooks_status.v0",
		ClaudeInstalled:   claudePath != "",
		ClaudePath:        claudePath,
		SettingsPath:      opts.settings,
		SettingsExists:    settingsErr == nil,
		EmitterPath:       opts.emitter,
		EmitterExecutable: emitterExecutable,
		AllInstalled:      true,
		AllUpToDate:       true,
	}
	for _, spec := range opts.events {
		status := statusForHook(hooks, spec, opts.emitter)
		report.Hooks = append(report.Hooks, status)
		if !status.Installed {
			report.AllInstalled = false
		}
		if !status.UpToDate {
			report.AllUpToDate = false
		}
	}
	report.NeedsUpdate = !report.AllUpToDate
	return report, nil
}

func executable(path string) bool {
	if path == "" {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && !info.IsDir() && info.Mode()&0o111 != 0
}

func requireExecutable(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("emitter missing: %s", path)
	}
	if info.IsDir() || info.Mode()&0o111 == 0 {
		return fmt.Errorf("emitter is not executable: %s", path)
	}
	return nil
}

func readSettings(path string) (map[string]interface{}, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]interface{}{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read Claude settings: %w", err)
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return map[string]interface{}{}, nil
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("Claude settings JSON is invalid: %w", err)
	}
	if doc == nil {
		doc = map[string]interface{}{}
	}
	return doc, nil
}

func writeSettings(path string, doc map[string]interface{}) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if _, err := os.Stat(path); err == nil {
		backup := fmt.Sprintf("%s.agentsnitch-backup-%s", path, time.Now().Format("20060102-150405"))
		if err := copyFile(path, backup); err != nil {
			return fmt.Errorf("write backup: %w", err)
		}
	}
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	tmp := path + ".agentsnitch-tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func copyFile(src, dst string) error {
	raw, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, raw, 0o600)
}

func hooksMap(doc map[string]interface{}) map[string]interface{} {
	if hooks, ok := doc["hooks"].(map[string]interface{}); ok {
		return hooks
	}
	hooks := map[string]interface{}{}
	doc["hooks"] = hooks
	return hooks
}

func addAgentSnitchHook(hooks map[string]interface{}, spec hookSpec, emitter string) {
	hooks[spec.Event] = append(asSlice(hooks[spec.Event]), map[string]interface{}{
		"matcher": "",
		"hooks": []interface{}{
			map[string]interface{}{
				"type":    "command",
				"command": shellCommand(emitter, spec.Arg),
				"timeout": float64(5),
			},
		},
	})
}

func removeAgentSnitchHooks(hooks map[string]interface{}, emitter string, specs []hookSpec) int {
	removed := 0
	for _, spec := range specs {
		eventName := spec.Event
		var keptGroups []interface{}
		for _, groupValue := range asSlice(hooks[eventName]) {
			group, ok := groupValue.(map[string]interface{})
			if !ok {
				keptGroups = append(keptGroups, groupValue)
				continue
			}
			var keptCommands []interface{}
			for _, hookValue := range asSlice(group["hooks"]) {
				hook, ok := hookValue.(map[string]interface{})
				if !ok {
					keptCommands = append(keptCommands, hookValue)
					continue
				}
				cmd, _ := hook["command"].(string)
				if isAgentSnitchCommand(cmd, emitter) {
					removed++
					continue
				}
				keptCommands = append(keptCommands, hookValue)
			}
			if len(keptCommands) == 0 {
				continue
			}
			group["hooks"] = keptCommands
			keptGroups = append(keptGroups, group)
		}
		if len(keptGroups) == 0 {
			delete(hooks, eventName)
		} else {
			hooks[eventName] = keptGroups
		}
	}
	return removed
}

func hookInstalled(hooks map[string]interface{}, spec hookSpec, emitter string) bool {
	status := statusForHook(hooks, spec, emitter)
	return status.UpToDate
}

func statusForHook(hooks map[string]interface{}, spec hookSpec, emitter string) hookStatus {
	status := hookStatus{
		Event:          spec.Event,
		Arg:            spec.Arg,
		Label:          spec.Label,
		Description:    spec.Description,
		DesiredCommand: shellCommand(emitter, spec.Arg),
		Status:         "missing",
	}
	for _, groupValue := range asSlice(hooks[spec.Event]) {
		group, ok := groupValue.(map[string]interface{})
		if !ok {
			continue
		}
		for _, hookValue := range asSlice(group["hooks"]) {
			hook, ok := hookValue.(map[string]interface{})
			if !ok {
				continue
			}
			cmd, _ := hook["command"].(string)
			if hookmatch.Installed(cmd, emitter, spec.Arg) {
				status.Installed = true
				status.UpToDate = true
				status.CurrentCommand = cmd
				status.Status = "up_to_date"
				return status
			}
			if isAgentSnitchCommand(cmd, emitter) {
				status.Installed = true
				status.Stale = true
				status.CurrentCommand = cmd
				status.Status = "stale"
			}
		}
	}
	return status
}

func asSlice(value interface{}) []interface{} {
	items, _ := value.([]interface{})
	return items
}

func isAgentSnitchCommand(cmd, emitter string) bool {
	return hookmatch.AgentSnitchCommand(cmd, emitter)
}

func commandReferencesEmitter(cmd, emitter string) bool {
	argv, ok := hookmatch.ShellFields(cmd)
	return ok && len(argv) > 0 && (argv[0] == emitter || argv[0] == filepath.Base(emitter))
}

func shellCommand(emitter, arg string) string {
	return shellQuote(emitter) + " " + arg
}

func parseHookEvents(csv string) ([]hookSpec, error) {
	if strings.TrimSpace(csv) == "" {
		return append([]hookSpec(nil), allHookSpecs...), nil
	}
	byName := map[string]hookSpec{}
	for _, spec := range allHookSpecs {
		byName[strings.ToLower(spec.Event)] = spec
		byName[strings.ToLower(spec.Arg)] = spec
	}
	var specs []hookSpec
	seen := map[string]bool{}
	for _, raw := range strings.Split(csv, ",") {
		key := strings.ToLower(strings.TrimSpace(raw))
		spec, ok := byName[key]
		if !ok {
			return nil, fmt.Errorf("unsupported hook event: %s", raw)
		}
		if !seen[spec.Event] {
			specs = append(specs, spec)
			seen[spec.Event] = true
		}
	}
	if len(specs) == 0 {
		return nil, errors.New("no hook events selected")
	}
	return specs, nil
}

func eventNames(specs []hookSpec) string {
	names := make([]string, 0, len(specs))
	for _, spec := range specs {
		names = append(names, spec.Event)
	}
	return strings.Join(names, ", ")
}

func selectedHooks(specs []hookSpec) []hookSpec {
	if len(specs) == 0 {
		return append([]hookSpec(nil), allHookSpecs...)
	}
	return specs
}

func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	if strings.IndexFunc(s, func(r rune) bool {
		return !(r == '/' || r == '_' || r == '-' || r == '.' || r == ':' ||
			r >= '0' && r <= '9' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z')
	}) < 0 {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}
