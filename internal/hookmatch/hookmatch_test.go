package hookmatch

import "testing"

func TestInstalledRequiresEmitterAsExecutable(t *testing.T) {
	emitter := "/Applications/AgentSnitch.app/Contents/Resources/bin/emitter"
	if !Installed("'"+emitter+"' pretooluse", emitter, "pretooluse") {
		t.Fatal("expected quoted emitter command to match")
	}
	if Installed("echo "+emitter+" pretooluse", emitter, "pretooluse") {
		t.Fatal("echo command should not verify as installed")
	}
	if Installed("'"+emitter+"' posttooluse", emitter, "pretooluse") {
		t.Fatal("wrong hook arg should not verify")
	}
}

func TestAgentSnitchCommandRequiresEmitterExecutable(t *testing.T) {
	emitter := "/tmp/current/emitter"
	if !AgentSnitchCommand("/Library/Application\\ Support/AgentSnitch/bin/emitter pretooluse", emitter) {
		t.Fatal("expected packaged AgentSnitch emitter to be removable")
	}
	if AgentSnitchCommand("logger mentions agentsnitch emitter", emitter) {
		t.Fatal("non-emitter executable should not be removed")
	}
}

func TestShellFieldsParsesHookctlQuoteStyle(t *testing.T) {
	got, ok := ShellFields("'/tmp/Agent Snitch/bin/emitter' pretooluse")
	if !ok || len(got) != 2 || got[0] != "/tmp/Agent Snitch/bin/emitter" || got[1] != "pretooluse" {
		t.Fatalf("unexpected fields: %#v ok=%v", got, ok)
	}
}
