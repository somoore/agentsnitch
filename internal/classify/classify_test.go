package classify

import (
	"testing"

	"github.com/somoore/agentsnitch/internal/agent"
)

func TestClassify_SensitiveRead(t *testing.T) {
	p := &agent.HookPayload{
		HookEventName: "PreToolUse",
		ToolName:      "Read",
		ToolInput:     map[string]interface{}{"file_path": "/Users/x/.env"},
	}
	tags := Classify(p, "/tmp")
	if !contains(tags, "sensitive_read") {
		t.Errorf("expected sensitive_read tag, got %v", tags)
	}
}

func TestClassify_BashEgress(t *testing.T) {
	p := &agent.HookPayload{
		HookEventName: "PreToolUse",
		ToolName:      "Bash",
		ToolInput:     map[string]interface{}{"command": "curl https://example.com/data"},
	}
	tags := Classify(p, "/tmp")
	if !contains(tags, "external_egress_attempt") {
		t.Errorf("expected external_egress_attempt, got %v", tags)
	}
}

func TestClassify_ExplicitEgressTools(t *testing.T) {
	for _, tool := range []string{"WebFetch", "WebSearch"} {
		p := &agent.HookPayload{
			HookEventName: "PreToolUse",
			ToolName:      tool,
			ToolInput:     map[string]interface{}{"query": "search github"},
		}
		tags := Classify(p, "/tmp")
		if !contains(tags, "external_egress_attempt") {
			t.Fatalf("expected external_egress_attempt for %s, got %v", tool, tags)
		}
	}
}

func TestClassify_BashEgressCommandForms(t *testing.T) {
	cases := []string{
		"curl -fsS https://example.com/data",
		"/usr/bin/curl https://example.com/data",
		"wget -qO- https://example.com",
		"env TOKEN=redacted socat - TCP:example.com:443",
		"printf hi | nc example.com 443",
		"echo https://example.com",
	}
	for _, command := range cases {
		p := &agent.HookPayload{
			HookEventName: "PreToolUse",
			ToolName:      "Bash",
			ToolInput:     map[string]interface{}{"command": command},
		}
		tags := Classify(p, "/tmp")
		if !contains(tags, "external_egress_attempt") {
			t.Fatalf("expected external_egress_attempt for %q, got %v", command, tags)
		}
	}
}

func TestClassify_BashLocalNetworkCommandsAreNotExternalEgress(t *testing.T) {
	cases := []string{
		"curl http://localhost:8080",
		"/usr/bin/curl http://127.0.0.1:8080",
		"wget http://[::1]:8080",
		"nc 0.0.0.0 8080",
	}
	for _, command := range cases {
		p := &agent.HookPayload{
			HookEventName: "PreToolUse",
			ToolName:      "Bash",
			ToolInput:     map[string]interface{}{"command": command},
		}
		tags := Classify(p, "/tmp")
		if contains(tags, "external_egress_attempt") {
			t.Fatalf("did not expect external_egress_attempt for %q, got %v", command, tags)
		}
	}
}

func TestClassify_MCP(t *testing.T) {
	p := &agent.HookPayload{
		HookEventName: "PreToolUse",
		ToolName:      "mcp__filesystem__read_file",
		ToolInput:     map[string]interface{}{"path": ".env"},
	}
	tags := Classify(p, "/tmp")
	if !contains(tags, "mcp_tool_use") {
		t.Errorf("expected mcp_tool_use, got %v", tags)
	}
	if !contains(tags, "sensitive_read") {
		t.Errorf("expected sensitive_read for MCP read of sensitive path, got %v", tags)
	}
}

func TestClassify_MapPayloadPath(t *testing.T) {
	payload := map[string]interface{}{
		"tool_name": "mcp__filesystem__read_file",
		"tool_input": map[string]interface{}{
			"path": "/tmp/project/.env.local",
		},
	}
	tags := Classify(payload, "/tmp")
	if !contains(tags, "mcp_tool_use") || !contains(tags, "sensitive_read") {
		t.Fatalf("expected MCP + sensitive tags, got %v", tags)
	}
}

func TestClassify_CommonCredentialFilesAreSensitive(t *testing.T) {
	cases := []string{
		"/Users/x/.npmrc",
		"/Users/x/.pypirc",
		"/Users/x/.docker/config.json",
		"/Users/x/.kube/config",
		"/Users/x/.config/gcloud/application_default_credentials.json",
		"/tmp/project/terraform.tfvars",
		"/tmp/project/prod.auto.tfvars",
		"/tmp/project/client_secret.json",
		"/tmp/project/service-account.json",
	}
	for _, path := range cases {
		p := &agent.HookPayload{
			HookEventName: "PreToolUse",
			ToolName:      "Read",
			ToolInput:     map[string]interface{}{"file_path": path},
		}
		tags := Classify(p, "/tmp")
		if !contains(tags, "sensitive_read") {
			t.Fatalf("expected sensitive_read for %q, got %v", path, tags)
		}
	}
}

func TestClassify_BashCredentialFileCommandsAreSensitive(t *testing.T) {
	cases := []string{
		"cat ~/.npmrc",
		"python - <<'PY'\nopen('/tmp/project/client_secret.json').read()\nPY",
		"grep token ~/.git-credentials",
	}
	for _, command := range cases {
		p := &agent.HookPayload{
			HookEventName: "PreToolUse",
			ToolName:      "Bash",
			ToolInput:     map[string]interface{}{"command": command},
		}
		tags := Classify(p, "/tmp")
		if !contains(tags, "sensitive_read") {
			t.Fatalf("expected sensitive_read for %q, got %v", command, tags)
		}
	}
}

func TestClassify_BashSourceSearchForSecretWordsIsNotSensitiveRead(t *testing.T) {
	command := "echo \"=== where are secret/restricted Sensitivity labels attached ===\" && grep -rn '\"secret\"\\|\"restricted\"\\|Sensitivity:' pkg/hooks pkg/detect pkg/kernel pkg/mcp 2>/dev/null | grep -iv \"_test\\|secretsession\\|secret_session\\|wassecret\""
	p := &agent.HookPayload{
		HookEventName: "PreToolUse",
		ToolName:      "Bash",
		ToolInput:     map[string]interface{}{"command": command},
	}
	tags := Classify(p, "/tmp")
	if contains(tags, "sensitive_read") {
		t.Fatalf("did not expect sensitive_read for source search command, got %v", tags)
	}
}

func TestNormalizeAndIsSensitive(t *testing.T) {
	if !IsSensitivePath(".env", "/p") {
		t.Error(".env should be sensitive")
	}
	if NormalizeCommand("/usr/bin/env FOO=1 cat .env") == "" {
		t.Error("normalize should strip env")
	}
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
