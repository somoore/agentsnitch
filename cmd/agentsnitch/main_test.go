package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/somoore/agentsnitch/internal/event"
	"github.com/somoore/agentsnitch/internal/inspect"
	asruntime "github.com/somoore/agentsnitch/internal/runtime"
)

func TestShellExportValueQuotesSingleQuotes(t *testing.T) {
	got := shellExportValue("alpha'beta")
	want := "'alpha'\\''beta'"
	if got != want {
		t.Fatalf("shellExportValue = %q, want %q", got, want)
	}
}

func TestInspectCertificateForCLIParsesGeneratedCA(t *testing.T) {
	base := t.TempDir()
	paths := inspect.Paths{
		BaseDir:    base,
		CAPath:     filepath.Join(base, "ca.pem"),
		KeyPath:    filepath.Join(base, "ca-key.pem"),
		BundlePath: filepath.Join(base, "bundle.pem"),
		LeafDir:    filepath.Join(base, "leaf-cache"),
		DataDir:    filepath.Join(base, "payloads"),
	}

	info, err := inspect.NewCertManager(paths).EnsureCA()
	if err != nil {
		t.Fatalf("EnsureCA: %v", err)
	}
	cert, err := inspectCertificateForCLI(paths.CAPath)
	if err != nil {
		t.Fatalf("inspectCertificateForCLI: %v", err)
	}
	if !strings.Contains(cert.Subject.String(), "AgentSnitch Local HTTPS Inspection CA") {
		t.Fatalf("unexpected cert subject: %s", cert.Subject.String())
	}
	if info.Fingerprint != inspect.Fingerprint(cert) {
		t.Fatalf("fingerprint mismatch")
	}
}

func TestInspectCertificateForCLIRejectsInvalidPEM(t *testing.T) {
	path := filepath.Join(t.TempDir(), "invalid.pem")
	if err := os.WriteFile(path, []byte("not pem"), 0o600); err != nil {
		t.Fatalf("write invalid pem: %v", err)
	}
	if _, err := inspectCertificateForCLI(path); err == nil {
		t.Fatal("expected invalid PEM to fail")
	}
}

func TestDisableInspectCleansProcessTrustAndPayloadData(t *testing.T) {
	base := t.TempDir()
	settingsPath := filepath.Join(base, "settings.json")
	inspectDir := filepath.Join(base, "inspect")
	t.Setenv("AGENTSNITCH_UI_SETTINGS", settingsPath)
	t.Setenv("AGENTSNITCH_INSPECT_DIR", inspectDir)

	settings := inspect.DefaultSettings()
	settings.HTTPSInspectEnabled = true
	settings.HTTPSInspectProcessScoped = true
	settings.HTTPSInspectCapturePreviews = true
	settings.HTTPSInspectCaptureFull = true
	if err := inspect.SaveSettings(settings); err != nil {
		t.Fatalf("SaveSettings: %v", err)
	}
	paths := inspect.DefaultPaths()
	if err := inspect.EnsureDirs(paths); err != nil {
		t.Fatalf("EnsureDirs: %v", err)
	}
	if err := os.WriteFile(paths.BundlePath, []byte("bundle"), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	payloadPath := filepath.Join(paths.DataDir, "payload.json")
	if err := os.WriteFile(payloadPath, []byte("{}"), 0o600); err != nil {
		t.Fatalf("write payload: %v", err)
	}

	disableInspect([]string{"--remove-process-trust=true", "--purge-data=true"})

	got, err := inspect.LoadSettings()
	if err != nil {
		t.Fatalf("LoadSettings: %v", err)
	}
	if got.HTTPSInspectEnabled || got.HTTPSInspectCaptureFull {
		t.Fatalf("settings not disabled: %+v", got)
	}
	if _, err := os.Stat(paths.BundlePath); !os.IsNotExist(err) {
		t.Fatalf("bundle still exists or unexpected stat error: %v", err)
	}
	entries, err := os.ReadDir(paths.DataDir)
	if err != nil {
		t.Fatalf("read payload dir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("payload dir entries = %d, want 0", len(entries))
	}
}

func TestPurgeInspectDataExpiredOnlyPreservesActivePayloads(t *testing.T) {
	base := t.TempDir()
	t.Setenv("AGENTSNITCH_INSPECT_DIR", filepath.Join(base, "inspect"))
	paths := inspect.DefaultPaths()
	if err := os.MkdirAll(paths.DataDir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	expiredAt := time.Now().UTC().Add(-time.Minute)
	futureAt := time.Now().UTC().Add(time.Hour)
	expiredPath := writePayloadRecordForCLITest(t, paths, "expired.json", &expiredAt)
	futurePath := writePayloadRecordForCLITest(t, paths, "future.json", &futureAt)
	manualPath := writePayloadRecordForCLITest(t, paths, "manual.json", nil)

	purgeInspectData([]string{"--expired"})

	if _, err := os.Stat(expiredPath); !os.IsNotExist(err) {
		t.Fatalf("expired payload still exists or unexpected stat error: %v", err)
	}
	for _, path := range []string{futurePath, manualPath} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("active payload should remain at %s: %v", path, err)
		}
	}
}

func writePayloadRecordForCLITest(t *testing.T, paths inspect.Paths, name string, expiresAt *time.Time) string {
	t.Helper()
	raw, err := json.Marshal(inspect.PayloadRecord{
		Schema:    "agentsnitch.inspect_payload.v0",
		Captured:  time.Now().UTC(),
		ExpiresAt: expiresAt,
		Request:   "request",
		Response:  "response",
	})
	if err != nil {
		t.Fatalf("Marshal payload record: %v", err)
	}
	path := filepath.Join(paths.DataDir, name)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("WriteFile payload record: %v", err)
	}
	return path
}

func TestCurrentInspectStatusUsesLiveDaemonProxy(t *testing.T) {
	base := t.TempDir()
	t.Setenv("AGENTSNITCH_UI_SETTINGS", filepath.Join(base, "settings.json"))
	t.Setenv("AGENTSNITCH_INSPECT_DIR", filepath.Join(base, "inspect"))
	t.Setenv("AGENTSNITCH_STATUS", filepath.Join(base, "status.json"))

	settings := inspect.DefaultSettings()
	settings.HTTPSInspectEnabled = true
	if err := inspect.SaveSettings(settings); err != nil {
		t.Fatalf("SaveSettings: %v", err)
	}
	if _, err := inspect.NewCertManager(inspect.DefaultPaths()).EnsureCA(); err != nil {
		t.Fatalf("EnsureCA: %v", err)
	}
	if err := asruntime.WriteStatus(asruntime.Status{
		UpdatedAt: time.Now().UTC(),
		Inspect: inspect.Status{
			Proxy: inspect.ProxyStatus{
				Enabled:   true,
				Listening: true,
				Address:   "127.0.0.1:49152",
			},
			ProcessEnv: map[string]string{"HTTPS_PROXY": "http://agentsnitch:token@127.0.0.1:49152"},
		},
		LastInspectedHTTP: &event.InspectedHTTPExchange{
			Request: event.InspectedHTTPRequest{Host: "api.example.com"},
		},
	}); err != nil {
		t.Fatalf("WriteStatus: %v", err)
	}

	got := currentInspectStatus()
	if !got.Proxy.Listening || got.Proxy.Address != "127.0.0.1:49152" {
		t.Fatalf("live proxy status not used: %+v", got.Proxy)
	}
	if got.ProcessEnv["HTTPS_PROXY"] == "" {
		t.Fatalf("process env not preserved: %+v", got.ProcessEnv)
	}
	if got.LastInspection != "api.example.com" {
		t.Fatalf("last inspection = %q", got.LastInspection)
	}
	if len(got.Warnings) != 0 {
		t.Fatalf("unexpected warnings from live proxy status: %+v", got.Warnings)
	}
}
