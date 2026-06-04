package destinationintent

import "testing"

func TestExtractFindsURLsAndGitStyleHosts(t *testing.T) {
	got := Extract("Bash", "", `curl -fsS https://example.com/data && git clone git@github.com:org/repo.git`, nil)
	for _, want := range []string{"example.com", "github.com"} {
		if !contains(got, want) {
			t.Fatalf("Extract() = %v, missing %q", got, want)
		}
	}
}

func TestExtractUsesNestedToolInput(t *testing.T) {
	got := Extract("mcp__browser__navigate", "", "", map[string]interface{}{
		"params": map[string]interface{}{"url": "https://docs.example.org/path?token=secret"},
	})
	if len(got) != 1 || got[0] != "docs.example.org" {
		t.Fatalf("Extract() = %v, want docs.example.org", got)
	}
}

func TestExtractInfersWebSearchProviderIntent(t *testing.T) {
	got := Extract("WebSearch", "", "", map[string]interface{}{
		"query": "Buildkite Cleanroom agent sandbox on GitHub",
	})
	if len(got) != 1 || got[0] != "github.com" {
		t.Fatalf("Extract() = %v, want github.com", got)
	}
}

func TestExtractRejectsLocalFilePathsAndPlainBranches(t *testing.T) {
	got := Extract("Bash", "/Users/me/project/README.md", "git checkout main", nil)
	if len(got) != 0 {
		t.Fatalf("Extract() = %v, want no destination intent", got)
	}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
