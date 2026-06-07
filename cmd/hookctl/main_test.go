package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestInstallClaudeHooksIsIdempotentAndPreservesOtherHooks(t *testing.T) {
	dir := t.TempDir()
	settings := filepath.Join(dir, "settings.json")
	emitter := filepath.Join(dir, "emitter")
	if err := os.WriteFile(emitter, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	initial := []byte(`{
  "theme": "dark",
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {"type": "command", "command": "/usr/bin/true", "timeout": 3}
        ]
      }
    ]
  }
}`)
	if err := os.WriteFile(settings, initial, 0o600); err != nil {
		t.Fatal(err)
	}

	opts := options{settings: settings, emitter: emitter, events: allHookSpecs}
	if err := installClaudeHooks(opts); err != nil {
		t.Fatal(err)
	}
	if err := installClaudeHooks(opts); err != nil {
		t.Fatal(err)
	}

	doc := readSettingsForTest(t, settings)
	hooks := hooksMap(doc)
	if countAgentSnitchHooks(hooks, emitter) != 2 {
		t.Fatalf("expected exactly two AgentSnitch hooks, got %#v", hooks)
	}
	if !hookInstalled(hooks, allHookSpecs[0], emitter) {
		t.Fatal("missing PreToolUse AgentSnitch hook")
	}
	if !hookInstalled(hooks, allHookSpecs[1], emitter) {
		t.Fatal("missing PostToolUse AgentSnitch hook")
	}
	if !commandPresent(hooks, preEvent, "/usr/bin/true") {
		t.Fatalf("unrelated hook was not preserved: %#v", hooks[preEvent])
	}
}

func TestUninstallClaudeHooksRemovesOnlyAgentSnitchHooks(t *testing.T) {
	dir := t.TempDir()
	settings := filepath.Join(dir, "settings.json")
	emitter := filepath.Join(dir, "emitter")
	if err := os.WriteFile(emitter, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	opts := options{settings: settings, emitter: emitter, events: allHookSpecs}
	if err := installClaudeHooks(opts); err != nil {
		t.Fatal(err)
	}

	doc := readSettingsForTest(t, settings)
	hooks := hooksMap(doc)
	addAgentSnitchHook(hooks, hookSpec{Event: preEvent, Arg: "true"}, "/usr/bin/true")
	if err := writeSettings(settings, doc); err != nil {
		t.Fatal(err)
	}

	if err := uninstallClaudeHooks(opts); err != nil {
		t.Fatal(err)
	}

	doc = readSettingsForTest(t, settings)
	hooks = hooksMap(doc)
	if countAgentSnitchHooks(hooks, emitter) != 0 {
		t.Fatalf("AgentSnitch hooks remain: %#v", hooks)
	}
	if !commandPresent(hooks, preEvent, "/usr/bin/true true") {
		t.Fatalf("unrelated hook was removed: %#v", hooks[preEvent])
	}
}

func TestVerifyRejectsCommandsThatOnlyMentionEmitter(t *testing.T) {
	dir := t.TempDir()
	settings := filepath.Join(dir, "settings.json")
	emitter := filepath.Join(dir, "emitter")
	if err := os.WriteFile(emitter, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	doc := map[string]interface{}{
		"hooks": map[string]interface{}{
			preEvent: []interface{}{
				map[string]interface{}{"hooks": []interface{}{
					map[string]interface{}{"type": "command", "command": "echo " + emitter + " pretooluse"},
				}},
			},
			postEvent: []interface{}{
				map[string]interface{}{"hooks": []interface{}{
					map[string]interface{}{"type": "command", "command": "echo " + emitter + " posttooluse"},
				}},
			},
		},
	}
	if err := writeSettings(settings, doc); err != nil {
		t.Fatal(err)
	}
	if err := verifyClaudeHooks(options{settings: settings, emitter: emitter, events: allHookSpecs}); err == nil {
		t.Fatal("spoofed echo commands should not verify")
	}
}

func TestSelectedHookInstallAndUninstall(t *testing.T) {
	dir := t.TempDir()
	settings := filepath.Join(dir, "settings.json")
	emitter := filepath.Join(dir, "emitter")
	if err := os.WriteFile(emitter, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	preOnly := []hookSpec{allHookSpecs[0]}
	opts := options{settings: settings, emitter: emitter, events: preOnly}
	if err := installClaudeHooks(opts); err != nil {
		t.Fatal(err)
	}
	doc := readSettingsForTest(t, settings)
	hooks := hooksMap(doc)
	if !hookInstalled(hooks, allHookSpecs[0], emitter) {
		t.Fatal("expected PreToolUse installed")
	}
	if hookInstalled(hooks, allHookSpecs[1], emitter) {
		t.Fatal("PostToolUse should not be installed")
	}
	if err := uninstallClaudeHooks(opts); err != nil {
		t.Fatal(err)
	}
	doc = readSettingsForTest(t, settings)
	hooks = hooksMap(doc)
	if countAgentSnitchHooks(hooks, emitter) != 0 {
		t.Fatalf("selected uninstall left hooks: %#v", hooks)
	}
}

func TestStatusReportsStaleHooks(t *testing.T) {
	dir := t.TempDir()
	settings := filepath.Join(dir, "settings.json")
	emitter := filepath.Join(dir, "emitter")
	if err := os.WriteFile(emitter, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	doc := map[string]interface{}{}
	hooks := hooksMap(doc)
	addAgentSnitchHook(hooks, hookSpec{Event: preEvent, Arg: "old"}, emitter)
	if err := writeSettings(settings, doc); err != nil {
		t.Fatal(err)
	}
	report, err := statusClaudeHooks(options{settings: settings, emitter: emitter, events: allHookSpecs})
	if err != nil {
		t.Fatal(err)
	}
	if report.AllUpToDate {
		t.Fatal("stale hook should not report all up to date")
	}
	if !report.Hooks[0].Installed || !report.Hooks[0].Stale || report.Hooks[0].UpToDate {
		t.Fatalf("unexpected pre hook status: %+v", report.Hooks[0])
	}
	if report.Hooks[1].Installed {
		t.Fatalf("post hook should be missing: %+v", report.Hooks[1])
	}
}

func TestClaudeCommandPathUsesExplicitEnv(t *testing.T) {
	dir := t.TempDir()
	claude := filepath.Join(dir, "claude")
	if err := os.WriteFile(claude, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CLAUDE_BIN", claude)
	t.Setenv("CLAUDE_PATH", "")
	t.Setenv("PATH", "")

	if got := claudeCommandPath(); got != claude {
		t.Fatalf("expected %s, got %s", claude, got)
	}
}

func readSettingsForTest(t *testing.T, path string) map[string]interface{} {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func countAgentSnitchHooks(hooks map[string]interface{}, emitter string) int {
	count := 0
	for _, eventName := range []string{preEvent, postEvent} {
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
				if isAgentSnitchCommand(cmd, emitter) {
					count++
				}
			}
		}
	}
	return count
}

func commandPresent(hooks map[string]interface{}, eventName, want string) bool {
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
			if cmd == want {
				return true
			}
		}
	}
	return false
}
