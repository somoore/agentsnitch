package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
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
}

func main() {
	opts := options{}
	flag.StringVar(&opts.settings, "settings", "", "Claude settings.json path")
	flag.StringVar(&opts.emitter, "emitter", "", "AgentSnitch emitter path")
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

	var err error
	switch args[0] {
	case "install":
		err = installClaudeHooks(opts)
	case "uninstall":
		err = uninstallClaudeHooks(opts)
	case "verify":
		err = verifyClaudeHooks(opts)
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
	fmt.Fprintln(os.Stderr, "usage: hookctl [--settings path] [--emitter path] install|uninstall|verify")
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

func installClaudeHooks(opts options) error {
	if err := requireExecutable(opts.emitter); err != nil {
		return err
	}
	doc, err := readSettings(opts.settings)
	if err != nil {
		return err
	}

	hooks := hooksMap(doc)
	removeAgentSnitchHooks(hooks, opts.emitter)
	addAgentSnitchHook(hooks, preEvent, opts.emitter, "pretooluse")
	addAgentSnitchHook(hooks, postEvent, opts.emitter, "posttooluse")
	doc["hooks"] = hooks

	if err := writeSettings(opts.settings, doc); err != nil {
		return err
	}
	fmt.Printf("Claude hooks installed: %s\n", opts.settings)
	fmt.Printf("Emitter: %s\n", opts.emitter)
	return verifyClaudeHooks(opts)
}

func uninstallClaudeHooks(opts options) error {
	doc, err := readSettings(opts.settings)
	if err != nil {
		return err
	}
	hooks := hooksMap(doc)
	removed := removeAgentSnitchHooks(hooks, opts.emitter)
	doc["hooks"] = hooks
	if err := writeSettings(opts.settings, doc); err != nil {
		return err
	}
	fmt.Printf("Claude hooks removed: %d AgentSnitch command(s)\n", removed)
	return nil
}

func verifyClaudeHooks(opts options) error {
	doc, err := readSettings(opts.settings)
	if err != nil {
		return err
	}
	hooks := hooksMap(doc)
	missing := []string{}
	if !hookInstalled(hooks, preEvent, opts.emitter, "pretooluse") {
		missing = append(missing, preEvent)
	}
	if !hookInstalled(hooks, postEvent, opts.emitter, "posttooluse") {
		missing = append(missing, postEvent)
	}
	if len(missing) > 0 {
		return fmt.Errorf("Claude hooks missing or wrong for: %s", strings.Join(missing, ", "))
	}
	fmt.Printf("Claude hooks verified: PreToolUse and PostToolUse point at %s\n", opts.emitter)
	return nil
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

func addAgentSnitchHook(hooks map[string]interface{}, eventName, emitter, arg string) {
	hooks[eventName] = append(asSlice(hooks[eventName]), map[string]interface{}{
		"matcher": "",
		"hooks": []interface{}{
			map[string]interface{}{
				"type":    "command",
				"command": shellCommand(emitter, arg),
				"timeout": float64(5),
			},
		},
	})
}

func removeAgentSnitchHooks(hooks map[string]interface{}, emitter string) int {
	removed := 0
	for _, eventName := range []string{preEvent, postEvent} {
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

func hookInstalled(hooks map[string]interface{}, eventName, emitter, arg string) bool {
	for _, groupValue := range asSlice(hooks[eventName]) {
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
			if hookmatch.Installed(cmd, emitter, arg) {
				return true
			}
		}
	}
	return false
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
