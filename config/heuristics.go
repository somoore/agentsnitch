package config

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
)

//go:embed heuristics.json
var defaultHeuristicsJSON []byte

const HeuristicsSchema = "agentsnitch.heuristics.v0"

type Heuristics struct {
	Schema                string                `json:"schema"`
	Correlation           CorrelationHeuristics `json:"correlation"`
	Classify              ClassifyHeuristics    `json:"classify"`
	DestinationCategories []DestinationCategory `json:"destination_categories"`
	QuietCategories       []string              `json:"quiet_categories"`
	NoisyAutomation       []NoisyAutomationRule `json:"noisy_automation"`
}

type CorrelationHeuristics struct {
	CorrelationWindowSeconds        int   `json:"correlation_window_seconds"`
	ExistingConnectionWindowSeconds int   `json:"existing_connection_window_seconds"`
	ProcessTTLMinutes               int   `json:"process_ttl_minutes"`
	MaxAncestorDepth                int   `json:"max_ancestor_depth"`
	HighByteThreshold               int64 `json:"high_byte_threshold"`
}

type ClassifyHeuristics struct {
	SensitivePaths       []string `json:"sensitive_paths"`
	LocalOnlyHosts       []string `json:"local_only_hosts"`
	NetworkCommandTokens []string `json:"network_command_tokens"`
}

type DestinationCategory struct {
	Name           string   `json:"name"`
	Domains        []string `json:"domains"`
	CIDRs          []string `json:"cidrs,omitempty"`
	QuietByDefault bool     `json:"quiet_by_default"`
}

type NoisyAutomationRule struct {
	Family            string   `json:"family"`
	Contains          []string `json:"contains"`
	RequiresLocalhost bool     `json:"requires_localhost,omitempty"`
}

func DefaultHeuristics() Heuristics {
	cfg, err := ParseHeuristics(defaultHeuristicsJSON)
	if err != nil {
		panic(err)
	}
	return cfg
}

func DefaultHeuristicsJSON() []byte {
	out := make([]byte, len(defaultHeuristicsJSON))
	copy(out, defaultHeuristicsJSON)
	return out
}

func ParseHeuristics(data []byte) (Heuristics, error) {
	var cfg Heuristics
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, err
	}
	if cfg.Schema != HeuristicsSchema {
		return cfg, fmt.Errorf("unsupported heuristics schema %q", cfg.Schema)
	}
	if cfg.Correlation.CorrelationWindowSeconds <= 0 {
		return cfg, fmt.Errorf("correlation_window_seconds must be positive")
	}
	if cfg.Correlation.ExistingConnectionWindowSeconds <= 0 {
		return cfg, fmt.Errorf("existing_connection_window_seconds must be positive")
	}
	if cfg.Correlation.ProcessTTLMinutes <= 0 {
		return cfg, fmt.Errorf("process_ttl_minutes must be positive")
	}
	if cfg.Correlation.MaxAncestorDepth <= 0 {
		return cfg, fmt.Errorf("max_ancestor_depth must be positive")
	}
	if cfg.Correlation.HighByteThreshold <= 0 {
		return cfg, fmt.Errorf("high_byte_threshold must be positive")
	}
	if len(cfg.Classify.SensitivePaths) == 0 {
		return cfg, fmt.Errorf("sensitive_paths must not be empty")
	}
	if len(cfg.Classify.LocalOnlyHosts) == 0 {
		return cfg, fmt.Errorf("local_only_hosts must not be empty")
	}
	if len(cfg.Classify.NetworkCommandTokens) == 0 {
		return cfg, fmt.Errorf("network_command_tokens must not be empty")
	}
	seenCategories := map[string]struct{}{}
	for _, category := range cfg.DestinationCategories {
		name := strings.TrimSpace(category.Name)
		if name == "" {
			return cfg, fmt.Errorf("destination category missing name")
		}
		if len(category.Domains) == 0 && len(category.CIDRs) == 0 {
			return cfg, fmt.Errorf("destination category %q missing domains or cidrs", name)
		}
		for _, cidr := range category.CIDRs {
			if _, err := netip.ParsePrefix(strings.TrimSpace(cidr)); err != nil {
				return cfg, fmt.Errorf("destination category %q has invalid cidr %q: %w", name, cidr, err)
			}
		}
		if _, ok := seenCategories[name]; ok {
			return cfg, fmt.Errorf("duplicate destination category %q", name)
		}
		seenCategories[name] = struct{}{}
	}
	return cfg, nil
}

func (h Heuristics) DestinationCategoryForHost(host string) string {
	host = strings.Trim(strings.ToLower(strings.TrimSpace(host)), "[]")
	if host == "" {
		return ""
	}
	for _, category := range h.DestinationCategories {
		if h.HostMatchesAnyDomain(host, category.Domains) || h.HostMatchesAnyCIDR(host, category.CIDRs) {
			return category.Name
		}
	}
	return ""
}

func (h Heuristics) HostMatchesAnyCIDR(host string, cidrs []string) bool {
	host = strings.Trim(strings.ToLower(strings.TrimSpace(host)), "[]")
	if before, _, ok := strings.Cut(host, ":"); ok {
		host = strings.Trim(before, "[]")
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	for _, cidr := range cidrs {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(cidr))
		if err == nil && prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func (h Heuristics) HostMatchesAnyDomain(host string, domains []string) bool {
	for _, domain := range domains {
		if HostMatchesDomain(host, domain) {
			return true
		}
	}
	return false
}

func (h Heuristics) DestinationCategoryDomains(name string) []string {
	for _, category := range h.DestinationCategories {
		if category.Name == name {
			out := make([]string, len(category.Domains))
			copy(out, category.Domains)
			return out
		}
	}
	return nil
}

func HostMatchesDomain(host, domain string) bool {
	host = strings.Trim(strings.ToLower(strings.TrimSpace(host)), "[]")
	domain = strings.Trim(strings.ToLower(strings.TrimSpace(domain)), "[]")
	if host == "" || domain == "" {
		return false
	}
	if before, _, ok := strings.Cut(host, ":"); ok {
		host = strings.Trim(before, "[]")
	}
	return host == domain || strings.HasSuffix(host, "."+domain)
}
