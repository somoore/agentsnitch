package config

import "testing"

func TestDefaultHeuristicsLoads(t *testing.T) {
	cfg := DefaultHeuristics()
	if cfg.Schema != HeuristicsSchema {
		t.Fatalf("schema = %q", cfg.Schema)
	}
	if got := cfg.DestinationCategoryForHost("api.anthropic.com"); got != "known Claude service" {
		t.Fatalf("anthropic category = %q", got)
	}
	if got := cfg.DestinationCategoryForHost("160.79.104.10"); got != "known Claude service" {
		t.Fatalf("anthropic cidr category = %q", got)
	}
	if got := cfg.DestinationCategoryForHost("registry.npmjs.com"); got != "package registry" {
		t.Fatalf("npm category = %q", got)
	}
	if got := cfg.DestinationCategoryForHost("bridge.claudeusercontent.com"); got != "Playwright bridge traffic" {
		t.Fatalf("bridge category = %q", got)
	}
	if got := cfg.DestinationCategoryForHost("17.46.190.35.bc.googleusercontent.com"); got != "cloud provider" {
		t.Fatalf("cloud provider category = %q", got)
	}
}
