package main

import "testing"

func TestParseTeamIdentifier(t *testing.T) {
	text := `
Executable=/Applications/AgentSnitch.app/Contents/MacOS/agentsnitch-ui
Identifier=com.somoore.agentsnitch
TeamIdentifier=ABCDE12345
Signature=Developer ID Application
`
	if got := parseTeamIdentifier(text); got != "ABCDE12345" {
		t.Fatalf("parseTeamIdentifier = %q, want ABCDE12345", got)
	}
}

func TestParseTeamIdentifierTreatsNotSetAsMissing(t *testing.T) {
	if got := parseTeamIdentifier("TeamIdentifier=not set\nSignature=adhoc"); got != "" {
		t.Fatalf("parseTeamIdentifier = %q, want empty", got)
	}
}

func TestCheckSignedSystemExtensionRequiresSignedEntitlement(t *testing.T) {
	checks := checkSignedSystemExtension("Signature=Developer ID Application\nTeamIdentifier=ABCDE12345\n")
	if len(checks) != 2 {
		t.Fatalf("got %d checks, want 2", len(checks))
	}
	if !checks[1].fail || checks[1].name != "Embedded extension entitlements" {
		t.Fatalf("expected missing entitlement failure, got %#v", checks[1])
	}
}

func TestCheckSignedSystemExtensionAcceptsContentFilterEntitlement(t *testing.T) {
	checks := checkSignedSystemExtension("Signature=Developer ID Application\nTeamIdentifier=ABCDE12345\ncontent-filter-provider-systemextension\n")
	if len(checks) != 2 {
		t.Fatalf("got %d checks, want 2", len(checks))
	}
	for _, check := range checks {
		if check.fail {
			t.Fatalf("expected successful check, got %#v", check)
		}
	}
}

func TestForbiddenNeedlesCheckFailsOnRemoteEgressAPI(t *testing.T) {
	got := forbiddenNeedlesCheck(
		"NE no remote egress APIs",
		[]byte("let conn = NWConnection(host: \"example.com\", port: 443, using: .tcp)"),
		[]string{"NWConnection"},
		"safe",
	)
	if !got.fail || got.status != "FAIL" {
		t.Fatalf("expected forbidden API failure, got %#v", got)
	}
}

func TestForbiddenNeedlesCheckPassesWithoutForbiddenAPIs(t *testing.T) {
	got := forbiddenNeedlesCheck(
		"NE no remote egress APIs",
		[]byte("let fd = socket(AF_UNIX, SOCK_STREAM, 0)"),
		[]string{"NWConnection", "socket(AF_INET"},
		"safe",
	)
	if got.fail || got.status != "OK" {
		t.Fatalf("expected safe source check, got %#v", got)
	}
}
