package inspect

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	SettingsSchema = "agentsnitch.ui_settings.v0"

	TrustModeProcessScoped = "process_scoped"
	TrustModeSystem        = "system"
	TrustModeBoth          = "both"
	TrustModeNone          = "none"

	PayloadMetadataOnly    = "metadata_only"
	PayloadRedactedPreview = "redacted_preview"
	PayloadFull            = "full"

	FullPayloadUntilSession = "until_session_ends"
	FullPayloadOneHour      = "1h"
	FullPayloadTwentyFour   = "24h"
	FullPayloadManual       = "manual"
)

type Settings struct {
	Schema                       string    `json:"schema"`
	AdvancedControlsEnabled      bool      `json:"advanced_controls_enabled"`
	KeepHooksUpToDate            bool      `json:"keep_hooks_up_to_date"`
	NetworkSensorDisabled        bool      `json:"network_sensor_disabled"`
	HighAssuranceDefaultEnabled  bool      `json:"high_assurance_default_enabled"`
	ReverseDNSEnabled            bool      `json:"reverse_dns_enabled"`
	ReverseDNSAlwaysOn           bool      `json:"reverse_dns_always_on"`
	DebugModeEnabled             bool      `json:"debug_mode_enabled"`
	DebugModeAlwaysOn            bool      `json:"debug_mode_always_on"`
	HTTPSInspectEnabled          bool      `json:"https_inspect_enabled"`
	HTTPSInspectProcessScoped    bool      `json:"https_inspect_process_scoped"`
	HTTPSInspectAllowSystemTrust bool      `json:"https_inspect_allow_system_trust"`
	HTTPSInspectCapturePreviews  bool      `json:"https_inspect_capture_previews"`
	HTTPSInspectCaptureFull      bool      `json:"https_inspect_capture_full_payloads"`
	HTTPSInspectPreviewBytes     int       `json:"https_inspect_preview_bytes"`
	HTTPSInspectFullRetention    string    `json:"https_inspect_full_retention"`
	HTTPSInspectDomainsMode      string    `json:"https_inspect_domains_mode"`
	HTTPSInspectDomains          []string  `json:"https_inspect_domains"`
	HTTPSInspectNeverDomains     []string  `json:"https_inspect_never_domains"`
	HTTPSInspectUpdatedAt        time.Time `json:"https_inspect_updated_at,omitempty"`
}

func DefaultSettings() Settings {
	return Settings{
		Schema:                      SettingsSchema,
		NetworkSensorDisabled:       true,
		HTTPSInspectProcessScoped:   true,
		HTTPSInspectCapturePreviews: true,
		HTTPSInspectPreviewBytes:    2048,
		HTTPSInspectFullRetention:   FullPayloadUntilSession,
		HTTPSInspectDomainsMode:     "all_managed",
	}
}

func SettingsPath() string {
	if path := strings.TrimSpace(os.Getenv("AGENTSNITCH_UI_SETTINGS")); path != "" {
		return path
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, ".agentsnitch", "ui-settings.json")
	}
	return filepath.Join(os.TempDir(), "agentsnitch-ui-settings.json")
}

func LoadSettings() (Settings, error) {
	path := SettingsPath()
	settings := DefaultSettings()
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return settings, nil
		}
		return settings, err
	}
	if err := json.Unmarshal(raw, &settings); err != nil {
		return DefaultSettings(), err
	}
	normalizeSettings(&settings)
	return settings, nil
}

func SaveSettings(settings Settings) error {
	normalizeSettings(&settings)
	settings.HTTPSInspectUpdatedAt = time.Now().UTC()
	path := SettingsPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".ui-settings-*.json")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return os.Chmod(path, 0o600)
}

func normalizeSettings(settings *Settings) {
	if settings.Schema == "" {
		settings.Schema = SettingsSchema
	}
	if settings.HTTPSInspectPreviewBytes <= 0 {
		settings.HTTPSInspectPreviewBytes = 2048
	}
	if settings.HTTPSInspectFullRetention == "" {
		settings.HTTPSInspectFullRetention = FullPayloadUntilSession
	}
	if settings.HTTPSInspectDomainsMode == "" {
		settings.HTTPSInspectDomainsMode = "all_managed"
	}
	settings.HTTPSInspectDomains = normalizeDomains(settings.HTTPSInspectDomains)
	settings.HTTPSInspectNeverDomains = normalizeDomains(settings.HTTPSInspectNeverDomains)
}

func (s Settings) TrustMode(systemTrusted bool) string {
	if s.HTTPSInspectProcessScoped && systemTrusted {
		return TrustModeBoth
	}
	if systemTrusted {
		return TrustModeSystem
	}
	if s.HTTPSInspectProcessScoped {
		return TrustModeProcessScoped
	}
	return TrustModeNone
}

func (s Settings) PayloadMode() string {
	if s.HTTPSInspectCaptureFull {
		return PayloadFull
	}
	if s.HTTPSInspectCapturePreviews {
		return PayloadRedactedPreview
	}
	return PayloadMetadataOnly
}

func normalizeDomains(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		value = strings.TrimPrefix(value, "https://")
		value = strings.TrimPrefix(value, "http://")
		value = strings.Trim(value, "/")
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
